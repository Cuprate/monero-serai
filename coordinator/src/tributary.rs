use core::{future::Future, time::Duration};
use std::sync::Arc;

use zeroize::Zeroizing;
use blake2::{digest::typenum::U32, Digest, Blake2s};
use ciphersuite::{Ciphersuite, Ristretto};

use tokio::sync::mpsc;

use serai_db::{DbTxn, Db as DbTrait};

use scale::Encode;
use serai_client::validator_sets::primitives::ValidatorSet;

use tributary_sdk::{ProvidedError, Tributary};

use serai_task::{Task, TaskHandle, ContinuallyRan};

use message_queue::{Service, Metadata, client::MessageQueue};

use serai_cosign::Cosigning;
use serai_coordinator_substrate::NewSetInformation;
use serai_coordinator_tributary::{Transaction, ProcessorMessages, ScanTributaryTask};
use serai_coordinator_p2p::P2p;

use crate::Db;

/// Provides Cosign/Cosigned Transactions onto the Tributary.
pub(crate) struct ProvideCosignCosignedTransactionsTask<CD: DbTrait, TD: DbTrait, P: P2p> {
  pub(crate) db: CD,
  pub(crate) set: NewSetInformation,
  pub(crate) tributary: Tributary<TD, Transaction, P>,
}
impl<CD: DbTrait, TD: DbTrait, P: P2p> ContinuallyRan
  for ProvideCosignCosignedTransactionsTask<CD, TD, P>
{
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    /// Provide a Provided Transaction to the Tributary.
    ///
    /// This is not a well-designed function. This is specific to the context in which its called,
    /// within this file. It should only be considered an internal helper for this domain alone.
    async fn provide_transaction<TD: DbTrait, P: P2p>(
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

    async move {
      let mut made_progress = false;

      // Check if we produced any cosigns we were supposed to
      let mut pending_notable_cosign = false;
      loop {
        let mut txn = self.db.txn();

        // Fetch the next cosign this tributary should handle
        let Some(cosign) = crate::PendingCosigns::try_recv(&mut txn, self.set.set) else { break };
        pending_notable_cosign = cosign.notable;

        // If we (Serai) haven't cosigned this block, break as this is still pending
        let Ok(latest) = Cosigning::<CD>::latest_cosigned_block_number(&txn) else { break };
        if latest < cosign.block_number {
          break;
        }

        // Because we've cosigned it, provide the TX for that
        provide_transaction(
          self.set.set,
          &self.tributary,
          Transaction::Cosigned { substrate_block_hash: cosign.block_hash },
        )
        .await;
        // Clear pending_notable_cosign since this cosign isn't pending
        pending_notable_cosign = false;

        // Commit the txn to clear this from PendingCosigns
        txn.commit();
        made_progress = true;
      }

      // If we don't have any notable cosigns pending, provide the next set of cosign intents
      if !pending_notable_cosign {
        let mut txn = self.db.txn();
        // intended_cosigns will only yield up to and including the next notable cosign
        for cosign in Cosigning::<CD>::intended_cosigns(&mut txn, self.set.set) {
          // Flag this cosign as pending
          crate::PendingCosigns::send(&mut txn, self.set.set, &cosign);
          // Provide the transaction to queue it for work
          provide_transaction(
            self.set.set,
            &self.tributary,
            Transaction::Cosign { substrate_block_hash: cosign.block_hash },
          )
          .await;
        }
        txn.commit();
        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}

/// Takes the messages from ScanTributaryTask and publishes them to the message-queue.
pub(crate) struct TributaryProcessorMessagesTask<TD: DbTrait> {
  pub(crate) tributary_db: TD,
  pub(crate) set: ValidatorSet,
  pub(crate) message_queue: Arc<MessageQueue>,
}
impl<TD: DbTrait> ContinuallyRan for TributaryProcessorMessagesTask<TD> {
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

/// Run the scan task whenever the Tributary adds a new block.
async fn scan_on_new_block<CD: DbTrait, TD: DbTrait, P: P2p>(
  db: CD,
  set: ValidatorSet,
  tributary: Tributary<TD, Transaction, P>,
  scan_tributary_task: TaskHandle,
  tasks_to_keep_alive: Vec<TaskHandle>,
) {
  loop {
    // Break once this Tributary is retired
    if crate::RetiredTributary::get(&db, set.network).map(|session| session.0) >=
      Some(set.session.0)
    {
      drop(tasks_to_keep_alive);
      break;
    }

    // Have the tributary scanner run as soon as there's a new block
    match tributary.next_block_notification().await.await {
      Ok(()) => scan_tributary_task.run_now(),
      // unreachable since this owns the tributary object and doesn't drop it
      Err(_) => panic!("tributary was dropped causing notification to error"),
    }
  }
}

/// Spawn a Tributary.
///
/// This will spawn the Tributary, the Tributary scan task, forward the messages from the scan task
/// to the message queue, provide Cosign/Cosigned transactions, and inform the P2P network.
pub(crate) async fn spawn_tributary<P: P2p>(
  db: Db,
  message_queue: Arc<MessageQueue>,
  p2p: P,
  p2p_add_tributary: &mpsc::UnboundedSender<(ValidatorSet, Tributary<Db, Transaction, P>)>,
  set: NewSetInformation,
  serai_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
) {
  // Don't spawn retired Tributaries
  if crate::db::RetiredTributary::get(&db, set.set.network).map(|session| session.0) >=
    Some(set.set.session.0)
  {
    return;
  }

  let genesis = <[u8; 32]>::from(Blake2s::<U32>::digest((set.serai_block, set.set).encode()));

  // Since the Serai block will be finalized, then cosigned, before we handle this, this time will
  // be a couple of minutes stale. While the Tributary will still function with a start time in the
  // past, the Tributary will immediately incur round timeouts. We reduce these by adding a
  // constant delay of a couple of minutes.
  const TRIBUTARY_START_TIME_DELAY: u64 = 120;
  let start_time = set.declaration_time + TRIBUTARY_START_TIME_DELAY;

  let mut tributary_validators = Vec::with_capacity(set.validators.len());
  for (validator, weight) in set.validators.iter().copied() {
    let validator_key = <Ristretto as Ciphersuite>::read_G(&mut validator.0.as_slice())
      .expect("Serai validator had an invalid public key");
    let weight = u64::from(weight);
    tributary_validators.push((validator_key, weight));
  }

  // Spawn the Tributary
  let tributary_db = crate::db::tributary_db(set.set);
  let tributary =
    Tributary::new(tributary_db.clone(), genesis, start_time, serai_key, tributary_validators, p2p)
      .await
      .unwrap();
  let reader = tributary.reader();

  // Inform the P2P network
  p2p_add_tributary
    .send((set.set, tributary.clone()))
    .expect("p2p's add_tributary channel was closed?");

  // Spawn the task to provide Cosign/Cosigned transactions onto the Tributary
  let (provide_cosign_cosigned_transactions_task_def, provide_cosign_cosigned_transactions_task) =
    Task::new();
  tokio::spawn(
    (ProvideCosignCosignedTransactionsTask {
      db: db.clone(),
      set: set.clone(),
      tributary: tributary.clone(),
    })
    .continually_run(provide_cosign_cosigned_transactions_task_def, vec![]),
  );

  // Spawn the task to send all messages from the Tributary scanner to the message-queue
  let (scan_tributary_messages_task_def, scan_tributary_messages_task) = Task::new();
  tokio::spawn(
    (TributaryProcessorMessagesTask {
      tributary_db: tributary_db.clone(),
      set: set.set,
      message_queue,
    })
    .continually_run(scan_tributary_messages_task_def, vec![]),
  );

  // Spawn the scan task
  let (scan_tributary_task_def, scan_tributary_task) = Task::new();
  tokio::spawn(
    ScanTributaryTask::<_, _, P>::new(db.clone(), tributary_db, &set, reader)
      // This is the only handle for this TributaryProcessorMessagesTask, so when this task is
      // dropped, it will be too
      .continually_run(scan_tributary_task_def, vec![scan_tributary_messages_task]),
  );

  // Whenever a new block occurs, immediately run the scan task
  // This function also preserves the ProvideCosignCosignedTransactionsTask handle until the
  // Tributary is retired, ensuring it isn't dropped prematurely and that the task don't run ad
  // infinitum
  tokio::spawn(scan_on_new_block(
    db,
    set.set,
    tributary,
    scan_tributary_task,
    vec![provide_cosign_cosigned_transactions_task],
  ));
}
