use core::{future::Future, time::Duration};
use std::sync::Arc;

use serai_db::{DbTxn, Db};

use serai_client::validator_sets::primitives::ValidatorSet;

use tributary_sdk::{ProvidedError, Tributary};

use serai_task::{TaskHandle, ContinuallyRan};

use message_queue::{Service, Metadata, client::MessageQueue};

use serai_cosign::Cosigning;
use serai_coordinator_substrate::NewSetInformation;
use serai_coordinator_tributary::{Transaction, ProcessorMessages};
use serai_coordinator_p2p::P2p;

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
        let Some(msg) = ProcessorMessages::try_recv(&mut txn, self.set) else { break };
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

async fn provide_transaction<TD: Db, P: P2p>(
  set: ValidatorSet,
  tributary: &Tributary<TD, Transaction, P>,
  tx: Transaction,
) {
  match tributary.provide_transaction(tx.clone()).await {
    // The Tributary uses its own DB, so we may provide this multiple times if we reboot before
    // committing the txn which provoked this
    Ok(()) | Err(ProvidedError::AlreadyProvided) => {}
    Err(ProvidedError::NotProvided) => {
      panic!("providing a Transaction which wasn't a Provided transaction: {tx:?}");
    }
    Err(ProvidedError::InvalidProvided(e)) => {
      panic!("providing an invalid Provided transaction, tx: {tx:?}, error: {e:?}")
    }
    Err(ProvidedError::LocalMismatchesOnChain) => loop {
      // The Tributary's scan task won't advance if we don't have the Provided transactions
      // present on-chain, and this enters an infinite loop to block the calling task from
      // advancing
      log::error!(
        "Tributary {:?} was supposed to provide {:?} but peers disagree, halting Tributary",
        set,
        tx,
      );
      // Print this every five minutes as this does need to be handled
      tokio::time::sleep(Duration::from_secs(5 * 60)).await;
    },
  }
}

/// Run a Tributary.
///
/// The Tributary handle existing causes the Tributary's consensus engine to be run. We distinctly
/// have `ScanTributaryTask` to scan the produced blocks. This function provides Provided
/// transactions onto the Tributary and invokes ScanTributaryTask whenver a new Tributary block is
/// produced (instead of only on the standard interval).
pub(crate) async fn run<CD: Db, TD: Db, P: P2p>(
  mut db: CD,
  set: NewSetInformation,
  tributary: Tributary<TD, Transaction, P>,
  scan_tributary_task: TaskHandle,
) {
  loop {
    // Break once this Tributary is retired
    if crate::RetiredTributary::get(&db, set.set.network).map(|session| session.0) >=
      Some(set.set.session.0)
    {
      break;
    }

    // Check if we produced any cosigns we were supposed to
    let mut pending_notable_cosign = false;
    loop {
      let mut txn = db.txn();

      // Fetch the next cosign this tributary should handle
      let Some(cosign) = crate::PendingCosigns::try_recv(&mut txn, set.set) else { break };
      pending_notable_cosign = cosign.notable;

      // If we (Serai) haven't cosigned this block, break as this is still pending
      let Ok(latest) = Cosigning::<CD>::latest_cosigned_block_number(&txn) else { break };
      if latest < cosign.block_number {
        break;
      }

      // Because we've cosigned it, provide the TX for that
      provide_transaction(
        set.set,
        &tributary,
        Transaction::Cosigned { substrate_block_hash: cosign.block_hash },
      )
      .await;
      // Clear pending_notable_cosign since this cosign isn't pending
      pending_notable_cosign = false;

      // Commit the txn to clear this from PendingCosigns
      txn.commit();
    }

    // If we don't have any notable cosigns pending, provide the next set of cosign intents
    if pending_notable_cosign {
      let mut txn = db.txn();
      // intended_cosigns will only yield up to and including the next notable cosign
      for cosign in Cosigning::<CD>::intended_cosigns(&mut txn, set.set) {
        // Flag this cosign as pending
        crate::PendingCosigns::send(&mut txn, set.set, &cosign);
        // Provide the transaction to queue it for work
        provide_transaction(
          set.set,
          &tributary,
          Transaction::Cosign { substrate_block_hash: cosign.block_hash },
        )
        .await;
      }
      txn.commit();
    }

    // Have the tributary scanner run as soon as there's a new block
    // This is wrapped in a timeout so we don't go too long without running the above code
    match tokio::time::timeout(
      Duration::from_millis(tributary_sdk::tendermint::TARGET_BLOCK_TIME.into()),
      tributary.next_block_notification().await,
    )
    .await
    {
      // Future resolved within the timeout, notification
      Ok(Ok(())) => scan_tributary_task.run_now(),
      // Future resolved within the timeout, notification failed due to sender being dropped
      // unreachable since this owns the tributary object and doesn't drop it
      Ok(Err(_)) => panic!("tributary was dropped causing notification to error"),
      // Future didn't resolve within the timeout
      Err(_) => {}
    }
  }
}
