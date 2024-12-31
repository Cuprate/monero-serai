use core::{marker::PhantomData, future::Future};

use serai_db::{Get, DbTxn, Db};

use serai_coins_primitives::{OutInstruction, OutInstructionWithBalance};

use messages::substrate::ExecutedBatch;
use primitives::task::ContinuallyRan;
use crate::{
  db::{ScannerGlobalDb, SubstrateToEventualityDb, AcknowledgedBatches},
  index, batch, ScannerFeed, KeyFor,
};

mod db;
use db::*;

pub(crate) fn last_acknowledged_batch<S: ScannerFeed>(getter: &impl Get) -> Option<u32> {
  SubstrateDb::<S>::last_acknowledged_batch(getter)
}
pub(crate) fn queue_acknowledge_batch<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  batch: ExecutedBatch,
  burns: Vec<OutInstructionWithBalance>,
  key_to_activate: Option<KeyFor<S>>,
) {
  SubstrateDb::<S>::queue_acknowledge_batch(txn, batch, burns, key_to_activate)
}
pub(crate) fn queue_queue_burns<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  burns: Vec<OutInstructionWithBalance>,
) {
  SubstrateDb::<S>::queue_queue_burns(txn, burns)
}

/*
  When Serai acknowledges a Batch, we can only handle it once we've scanned the chain and generated
  the same Batch ourselves. This takes the `acknowledge_batch`, `queue_burns` arguments and sits on
  them until we're able to process them.
*/
#[allow(non_snake_case)]
pub(crate) struct SubstrateTask<D: Db, S: ScannerFeed> {
  db: D,
  _S: PhantomData<S>,
}

impl<D: Db, S: ScannerFeed> SubstrateTask<D, S> {
  pub(crate) fn new(db: D) -> Self {
    Self { db, _S: PhantomData }
  }
}

impl<D: Db, S: ScannerFeed> ContinuallyRan for SubstrateTask<D, S> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let mut made_progress = false;
      loop {
        // Fetch the next action to handle
        let mut txn = self.db.txn();
        let Some(action) = SubstrateDb::<S>::next_action(&mut txn) else {
          drop(txn);
          return Ok(made_progress);
        };

        match action {
          Action::AcknowledgeBatch(AcknowledgeBatch { batch, mut burns, key_to_activate }) => {
            // Check if we have the information for this batch
            let Some(batch::BatchInfo {
              block_number,
              session_to_sign_batch,
              external_key_for_session_to_sign_batch,
              in_instructions_hash,
            }) = batch::take_info_for_batch::<S>(&mut txn, batch.id)
            else {
              // If we don't, drop this txn (restoring the action to the database)
              drop(txn);
              return Ok(made_progress);
            };
            assert_eq!(
              batch.publisher, session_to_sign_batch,
              "batch acknowledged on-chain was acknowledged by an unexpected publisher"
            );
            assert_eq!(
              batch.external_network_block_hash,
              index::block_id(&txn, block_number),
              "batch acknowledged on-chain was for a distinct block"
            );
            assert_eq!(
              batch.in_instructions_hash, in_instructions_hash,
              "batch acknowledged on-chain had distinct InInstructions"
            );

            SubstrateDb::<S>::set_last_acknowledged_batch(&mut txn, batch.id);
            AcknowledgedBatches::send(
              &mut txn,
              &external_key_for_session_to_sign_batch.0,
              batch.id,
            );

            // Mark we made progress and handle this
            made_progress = true;

            assert!(
              ScannerGlobalDb::<S>::is_block_notable(&txn, block_number),
              "acknowledging a block which wasn't notable"
            );
            if let Some(prior_highest_acknowledged_block) =
              ScannerGlobalDb::<S>::highest_acknowledged_block(&txn)
            {
              // If a single block produced multiple Batches, the block number won't increment
              assert!(
                block_number >= prior_highest_acknowledged_block,
                "acknowledging blocks out-of-order"
              );
              for b in (prior_highest_acknowledged_block + 1) .. block_number {
                assert!(
                  !ScannerGlobalDb::<S>::is_block_notable(&txn, b),
                  "skipped acknowledging a block which was notable"
                );
              }
            }

            ScannerGlobalDb::<S>::set_highest_acknowledged_block(&mut txn, block_number);
            if let Some(key_to_activate) = key_to_activate {
              ScannerGlobalDb::<S>::queue_key(
                &mut txn,
                block_number + S::WINDOW_LENGTH,
                key_to_activate,
              );
            }

            // Return the balances for any InInstructions which failed to execute
            {
              let return_information = batch::take_return_information::<S>(&mut txn, batch.id)
                .expect("didn't save the return information for Batch we published");
              assert_eq!(
              batch.in_instruction_results.len(),
              return_information.len(),
              "amount of InInstruction succeededs differed from amount of return information saved"
            );

              // We map these into standard Burns
              for (result, return_information) in
                batch.in_instruction_results.into_iter().zip(return_information)
              {
                if result == messages::substrate::InInstructionResult::Succeeded {
                  continue;
                }

                if let Some(batch::ReturnInformation { address, balance }) = return_information {
                  burns.push(OutInstructionWithBalance {
                    instruction: OutInstruction { address: address.into() },
                    balance,
                  });
                }
              }
            }

            // We send these Burns as stemming from this block we just acknowledged
            // This causes them to be acted on after we accumulate the outputs from this block
            SubstrateToEventualityDb::send_burns::<S>(&mut txn, block_number, burns);
          }

          Action::QueueBurns(burns) => {
            // We can instantly handle this so long as we've handled all prior actions
            made_progress = true;

            let queue_as_of = ScannerGlobalDb::<S>::highest_acknowledged_block(&txn)
              .expect("queueing Burns yet never acknowledged a block");

            SubstrateToEventualityDb::send_burns::<S>(&mut txn, queue_as_of, burns);
          }
        }

        txn.commit();
      }
    }
  }
}
