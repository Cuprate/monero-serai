use core::future::Future;
use std::sync::Arc;

use serai_db::{DbTxn, Db};

use serai_client::validator_sets::primitives::ValidatorSet;

use serai_task::ContinuallyRan;

use message_queue::{Service, Metadata, client::MessageQueue};

use serai_coordinator_substrate::NewSetInformation;
use serai_coordinator_p2p::P2p;

mod transaction;
pub use transaction::Transaction;

mod db;

mod scan;
pub(crate) use scan::ScanTributaryTask;

pub(crate) struct ScanTributaryMessagesTask<TD: Db> {
  pub(crate) tributary_db: TD,
  pub(crate) set: ValidatorSet,
  pub(crate) message_queue: Arc<MessageQueue>,
}
impl<TD: Db> ContinuallyRan for ScanTributaryMessagesTask<TD> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let mut made_progress = false;
      loop {
        let mut txn = self.tributary_db.txn();
        let Some(msg) = db::TributaryDb::try_recv_message(&mut txn, self.set) else { break };
        let metadata = Metadata {
          from: Service::Coordinator,
          to: Service::Processor(self.set.network),
          intent: msg.intent(),
        };
        let msg = borsh::to_vec(&msg).unwrap();
        // TODO: Make this fallible
        self.message_queue.queue(metadata, msg).await;
        txn.commit();
        made_progress = true;
      }
      Ok(made_progress)
    }
  }
}
