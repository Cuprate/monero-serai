use core::{marker::PhantomData, future::Future};

use blake2::{digest::typenum::U32, Digest, Blake2b};

use scale::Encode;
use serai_db::{DbTxn, Db};

use serai_in_instructions_primitives::{MAX_BATCH_SIZE, Batch};

use primitives::{EncodableG, task::ContinuallyRan};
use crate::{
  db::{Returnable, ScannerGlobalDb, InInstructionData, ScanToReportDb, Batches, BatchesToSign},
  scan::next_to_scan_for_outputs_block,
  ScannerFeed, KeyFor,
};

mod db;
pub(crate) use db::{BatchInfo, ReturnInformation};
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
            Batches::send(&mut txn, &batch);
            BatchesToSign::send(&mut txn, &external_key_for_session_to_sign_batch, &batch);
          }
        }

        // Update the next to potentially report block
        ReportDb::<S>::set_next_to_potentially_report_block(&mut txn, block_number + 1);

        txn.commit();
      }

      // Run dependents if we decided to report any blocks
      Ok(next_to_potentially_report <= highest_reportable)
    }
  }
}
