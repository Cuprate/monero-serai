use core::{marker::PhantomData, future::Future};

use blake2::{digest::typenum::U32, Digest, Blake2b};

use scale::Encode;
use serai_db::{DbTxn, Db};

use serai_validator_sets_primitives::Session;
use serai_in_instructions_primitives::{MAX_BATCH_SIZE, Batch};

use primitives::{EncodableG, task::ContinuallyRan};
use crate::{
  db::{Returnable, ScannerGlobalDb, InInstructionData, ScanToReportDb, Batches, BatchesToSign},
  scan::next_to_scan_for_outputs_block,
  substrate, ScannerFeed, KeyFor,
};

mod db;
pub(crate) use db::{BatchInfo, ReturnInformation, InternalBatches};
use db::ReportDb;

pub(crate) fn take_info_for_batch<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  id: u32,
) -> Option<BatchInfo<EncodableG<KeyFor<S>>>> {
  ReportDb::<S>::take_info_for_batch(txn, id)
}

pub(crate) fn take_return_information<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  id: u32,
) -> Option<Vec<Option<ReturnInformation<S>>>> {
  ReportDb::<S>::take_return_information(txn, id)
}

/*
  This task produces Batches for notable blocks, with all InInstructions, in an ordered fashion.

  We only report blocks once both tasks, scanning for received outputs and checking for resolved
  Eventualities, have processed the block. This ensures we know if this block is notable, and have
  the InInstructions for it.
*/
#[allow(non_snake_case)]
pub(crate) struct ReportTask<D: Db, S: ScannerFeed> {
  db: D,
  _S: PhantomData<S>,
}

impl<D: Db, S: ScannerFeed> ReportTask<D, S> {
  pub(crate) fn new(mut db: D, start_block: u64) -> Self {
    if ReportDb::<S>::next_to_potentially_report_block(&db).is_none() {
      // Initialize the DB
      let mut txn = db.txn();
      ReportDb::<S>::set_next_to_potentially_report_block(&mut txn, start_block);
      txn.commit();
    }

    Self { db, _S: PhantomData }
  }
}

impl<D: Db, S: ScannerFeed> ContinuallyRan for ReportTask<D, S> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let highest_reportable = {
        // Fetch the next to scan block
        let next_to_scan = next_to_scan_for_outputs_block::<S>(&self.db)
          .expect("ReportTask run before writing the start block");
        // If we haven't done any work, return
        if next_to_scan == 0 {
          return Ok(false);
        }
        // The last scanned block is the block prior to this
        #[allow(clippy::let_and_return)]
        let last_scanned = next_to_scan - 1;
        // The last scanned block is the highest reportable block as we only scan blocks within a
        // window where it's safe to immediately report the block
        // See `eventuality.rs` for more info
        last_scanned
      };

      let next_to_potentially_report = ReportDb::<S>::next_to_potentially_report_block(&self.db)
        .expect("ReportTask run before writing the start block");

      for block_number in next_to_potentially_report ..= highest_reportable {
        let mut txn = self.db.txn();

        // Receive the InInstructions for this block
        // We always do this as we can't trivially tell if we should recv InInstructions before we
        // do
        let InInstructionData {
          session_to_sign_batch,
          external_key_for_session_to_sign_batch,
          returnable_in_instructions: in_instructions,
        } = ScanToReportDb::<S>::recv_in_instructions(&mut txn, block_number);

        let notable = ScannerGlobalDb::<S>::is_block_notable(&txn, block_number);
        if !notable {
          assert!(in_instructions.is_empty(), "block wasn't notable yet had InInstructions");
        }
        // If this block is notable, create the Batch(s) for it
        if notable {
          let network = S::NETWORK;
          let mut batch_id = ReportDb::<S>::acquire_batch_id(&mut txn);

          // start with empty batch
          let mut batches = vec![Batch { network, id: batch_id, instructions: vec![] }];
          // We also track the return information for the InInstructions within a Batch in case
          // they error
          let mut return_information = vec![vec![]];

          for Returnable { return_address, in_instruction } in in_instructions {
            let balance = in_instruction.balance;

            let batch = batches.last_mut().unwrap();
            batch.instructions.push(in_instruction);

            // check if batch is over-size
            if batch.encode().len() > MAX_BATCH_SIZE {
              // pop the last instruction so it's back in size
              let in_instruction = batch.instructions.pop().unwrap();

              // bump the id for the new batch
              batch_id = ReportDb::<S>::acquire_batch_id(&mut txn);

              // make a new batch with this instruction included
              batches.push(Batch { network, id: batch_id, instructions: vec![in_instruction] });
              // Since we're allocating a new batch, allocate a new set of return addresses for it
              return_information.push(vec![]);
            }

            // For the set of return addresses for the InInstructions for the batch we just pushed
            // onto, push this InInstruction's return addresses
            return_information
              .last_mut()
              .unwrap()
              .push(return_address.map(|address| ReturnInformation { address, balance }));
          }

          // Now that we've finalized the Batches, save the information for each to the database
          assert_eq!(batches.len(), return_information.len());
          for (batch, return_information) in batches.iter().zip(&return_information) {
            assert_eq!(batch.instructions.len(), return_information.len());
            ReportDb::<S>::save_batch_info(
              &mut txn,
              batch.id,
              block_number,
              session_to_sign_batch,
              external_key_for_session_to_sign_batch,
              Blake2b::<U32>::digest(batch.instructions.encode()).into(),
            );
            ReportDb::<S>::save_return_information(&mut txn, batch.id, return_information);
          }

          for batch in batches {
            InternalBatches::send(
              &mut txn,
              &(session_to_sign_batch, EncodableG(external_key_for_session_to_sign_batch), batch),
            );
          }
        }

        // Update the next to potentially report block
        ReportDb::<S>::set_next_to_potentially_report_block(&mut txn, block_number + 1);

        txn.commit();
      }

      // TODO: This should be its own task. The above doesn't error, doesn't return early, so this
      // is fine, but this is precarious and would be better as its own task
      {
        let mut txn = self.db.txn();
        while let Some((session_to_sign_batch, external_key_for_session_to_sign_batch, batch)) =
          InternalBatches::<KeyFor<S>>::peek(&txn)
        {
          /*
            If this is the handover Batch, the first Batch signed by a session which retires the
            prior validator set, then this should only be signed after the prior validator set's
            actions are fully validated.

            The new session will only be responsible for signing this Batch if the prior key has
            retired, successfully completed all its on-external-network actions.

            We check here the prior session has successfully completed all its on-Serai-network
            actions by ensuring we've validated all Batches expected from it. Only then do we sign
            the Batch confirming the handover.

            We also wait for the Batch confirming the handover to be accepted on-chain, ensuring we
            don't verify the prior session's Batches, sign the handover Batch and the following
            Batch, have the prior session publish a malicious Batch where our handover Batch should
            be, before our following Batch becomes our handover Batch.
          */
          if session_to_sign_batch != Session(0) {
            // We may have Session(1)'s first Batch be Batch 0 if Session(0) never publishes a
            // Batch. This is fine as we'll hit the distinct Session check and then set the correct
            // values into this DB entry. All other sessions must complete the handover process,
            // which requires having published at least one Batch
            let (last_session, first_batch) =
              ReportDb::<S>::last_session_to_sign_batch_and_first_batch(&txn)
                .unwrap_or((Session(0), 0));
            // Because this boolean was expanded, we lose short-circuiting. That's fine
            let handover_batch = last_session != session_to_sign_batch;
            let batch_after_handover_batch =
              (last_session == session_to_sign_batch) && ((first_batch + 1) == batch.id);
            if handover_batch || batch_after_handover_batch {
              let verified_prior_batch = substrate::last_acknowledged_batch::<S>(&txn)
                // Since `batch.id = 0` in the Session(0)-never-published-a-Batch case, we don't
                // check `last_acknowledged_batch >= (batch.id - 1)` but instead this
                .map(|last_acknowledged_batch| (last_acknowledged_batch + 1) >= batch.id)
                // We've never verified any Batches
                .unwrap_or(false);
              if !verified_prior_batch {
                break;
              }
            }

            // If this is the handover Batch, update the last session to sign a Batch
            if handover_batch {
              ReportDb::<S>::set_last_session_to_sign_batch_and_first_batch(
                &mut txn,
                session_to_sign_batch,
                batch.id,
              );
            }
          }

          // Since we should handle this batch now, recv it from the channel
          InternalBatches::<KeyFor<S>>::try_recv(&mut txn).unwrap();

          Batches::send(&mut txn, &batch);
          BatchesToSign::send(&mut txn, &external_key_for_session_to_sign_batch.0, &batch);
        }
        txn.commit();
      }

      // Run dependents if we decided to report any blocks
      Ok(next_to_potentially_report <= highest_reportable)
    }
  }
}
