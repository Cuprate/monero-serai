use core::future::Future;
use std::sync::Arc;

#[rustfmt::skip]
use serai_client::{primitives::NetworkId, in_instructions::primitives::SignedBatch, SeraiError, Serai};

use serai_db::{Get, DbTxn, Db, create_db};
use serai_task::ContinuallyRan;

use crate::SignedBatches;

create_db!(
  CoordinatorSubstrate {
    LastPublishedBatch: (network: NetworkId) -> u32,
    BatchesToPublish: (network: NetworkId, batch: u32) -> SignedBatch,
  }
);

/// Publish `SignedBatch`s from `SignedBatches` onto Serai.
pub struct PublishBatchTask<D: Db> {
  db: D,
  serai: Arc<Serai>,
  network: NetworkId,
}

impl<D: Db> PublishBatchTask<D> {
  /// Create a task to publish `SignedBatch`s onto Serai.
  ///
  /// Returns None if `network == NetworkId::Serai`.
  // TODO: ExternalNetworkId
  pub fn new(db: D, serai: Arc<Serai>, network: NetworkId) -> Option<Self> {
    if network == NetworkId::Serai {
      None?
    };
    Some(Self { db, serai, network })
  }
}

impl<D: Db> ContinuallyRan for PublishBatchTask<D> {
  type Error = SeraiError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      // Read from SignedBatches, which is sequential, into our own mapping
      loop {
        let mut txn = self.db.txn();
        let Some(batch) = SignedBatches::try_recv(&mut txn, self.network) else {
          break;
        };

        // If this is a Batch not yet published, save it into our unordered mapping
        if LastPublishedBatch::get(&txn, self.network) < Some(batch.batch.id) {
          BatchesToPublish::set(&mut txn, self.network, batch.batch.id, &batch);
        }

        txn.commit();
      }

      // Synchronize our last published batch with the Serai network's
      let next_to_publish = {
        // This uses the latest finalized block, not the latest cosigned block, which should be
        // fine as in the worst case, the only impact is no longer attempting TX publication
        let serai = self.serai.as_of_latest_finalized_block().await?;
        let last_batch = serai.in_instructions().last_batch_for_network(self.network).await?;

        let mut txn = self.db.txn();
        let mut our_last_batch = LastPublishedBatch::get(&txn, self.network);
        while our_last_batch < last_batch {
          let next_batch = our_last_batch.map(|batch| batch + 1).unwrap_or(0);
          // Clean up the Batch to publish since it's already been published
          BatchesToPublish::take(&mut txn, self.network, next_batch);
          our_last_batch = Some(next_batch);
        }
        if let Some(last_batch) = our_last_batch {
          LastPublishedBatch::set(&mut txn, self.network, &last_batch);
        }
        last_batch.map(|batch| batch + 1).unwrap_or(0)
      };

      let made_progress =
        if let Some(batch) = BatchesToPublish::get(&self.db, self.network, next_to_publish) {
          self
            .serai
            .publish(&serai_client::in_instructions::SeraiInInstructions::execute_batch(batch))
            .await?;
          true
        } else {
          false
        };
      Ok(made_progress)
    }
  }
}
