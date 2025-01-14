use core::future::Future;
use std::sync::Arc;

use serai_db::{DbTxn, Db};

use serai_client::{primitives::NetworkId, SeraiError, Serai};

use serai_task::ContinuallyRan;

use crate::SignedBatches;

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
      let mut made_progress = false;

      loop {
        let mut txn = self.db.txn();
        let Some(batch) = SignedBatches::try_recv(&mut txn, self.network) else {
          // No batch to publish at this time
          break;
        };

        // Publish this Batch if it hasn't already been published
        let serai = self.serai.as_of_latest_finalized_block().await?;
        let last_batch = serai.in_instructions().last_batch_for_network(self.network).await?;
        if last_batch < Some(batch.batch.id) {
          // This stream of Batches *should* be sequential within the larger context of the Serai
          // coordinator. In this library, we use a more relaxed definition and don't assert
          // sequence. This does risk hanging the task, if Batch #n+1 is sent before Batch #n, but
          // that is a documented fault of the `SignedBatches` API.
          self
            .serai
            .publish(&serai_client::in_instructions::SeraiInInstructions::execute_batch(batch))
            .await?;
        }

        txn.commit();
        made_progress = true;
      }
      Ok(made_progress)
    }
  }
}
