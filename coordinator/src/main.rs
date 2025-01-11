use core::{marker::PhantomData, ops::Deref, future::Future, time::Duration};
use std::{sync::Arc, collections::HashMap, time::Instant};

use zeroize::{Zeroize, Zeroizing};
use rand_core::{RngCore, OsRng};

use blake2::{digest::typenum::U32, Digest, Blake2s};
use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding},
  Ciphersuite, Ristretto,
};

use tokio::sync::mpsc;

use scale::Encode;
use serai_client::{
  primitives::{PublicKey, SeraiAddress},
  validator_sets::primitives::{Session, ValidatorSet},
  Serai,
};
use message_queue::{Service, Metadata, client::MessageQueue};

use serai_task::{Task, TaskHandle, ContinuallyRan};

use serai_cosign::{SignedCosign, Cosigning};
use serai_coordinator_substrate::{NewSetInformation, CanonicalEventStream, EphemeralEventStream};

mod db;
use db::*;

mod tributary;
use tributary::{Transaction, ScanTributaryTask, ScanTributaryMessagesTask};

mod p2p {
  pub use serai_coordinator_p2p::*;
  pub use serai_coordinator_libp2p_p2p::Libp2p;
}

// Use a zeroizing allocator for this entire application
// While secrets should already be zeroized, the presence of secret keys in a networked application
// (at increased risk of OOB reads) justifies the performance hit in case any secrets weren't
// already
#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

type Tributary<P> = ::tributary::Tributary<Db, Transaction, P>;

async fn serai() -> Arc<Serai> {
  const SERAI_CONNECTION_DELAY: Duration = Duration::from_secs(10);
  const MAX_SERAI_CONNECTION_DELAY: Duration = Duration::from_secs(300);

  let mut delay = SERAI_CONNECTION_DELAY;
  loop {
    let Ok(serai) = Serai::new(format!(
      "http://{}:9944",
      serai_env::var("SERAI_HOSTNAME").expect("Serai hostname wasn't provided")
    ))
    .await
    else {
      log::error!("couldn't connect to the Serai node");
      tokio::time::sleep(delay).await;
      delay = (delay + SERAI_CONNECTION_DELAY).min(MAX_SERAI_CONNECTION_DELAY);
      continue;
    };
    log::info!("made initial connection to Serai node");
    return Arc::new(serai);
  }
}

fn spawn_cosigning(
  db: impl serai_db::Db,
  serai: Arc<Serai>,
  p2p: impl p2p::P2p,
  tasks_to_run_upon_cosigning: Vec<TaskHandle>,
  mut p2p_cosigns: mpsc::UnboundedReceiver<SignedCosign>,
  mut signed_cosigns: mpsc::UnboundedReceiver<SignedCosign>,
) {
  let mut cosigning = Cosigning::spawn(db, serai, p2p.clone(), tasks_to_run_upon_cosigning);
  tokio::spawn(async move {
    let last_cosign_rebroadcast = Instant::now();
    loop {
      let time_till_cosign_rebroadcast = (last_cosign_rebroadcast +
        serai_cosign::BROADCAST_FREQUENCY)
        .saturating_duration_since(Instant::now());
      tokio::select! {
        () = tokio::time::sleep(time_till_cosign_rebroadcast) => {
          for cosign in cosigning.cosigns_to_rebroadcast() {
            p2p.publish_cosign(cosign).await;
          }
        }
        cosign = p2p_cosigns.recv() => {
          let cosign = cosign.expect("p2p cosigns channel was dropped?");
          let _: Result<_, _> = cosigning.intake_cosign(&cosign);
        }
        cosign = signed_cosigns.recv() => {
          let cosign = cosign.expect("signed cosigns channel was dropped?");
          // TODO: Handle this error
          let _: Result<_, _> = cosigning.intake_cosign(&cosign);
          p2p.publish_cosign(cosign).await;
        }
      }
    }
  });
}

/// Spawn an existing Tributary.
///
/// This will spawn the Tributary, the Tributary scanning task, and inform the P2P network.
async fn spawn_tributary<P: p2p::P2p>(
  db: Db,
  message_queue: Arc<MessageQueue>,
  p2p: P,
  p2p_add_tributary: &mpsc::UnboundedSender<(ValidatorSet, Tributary<P>)>,
  set: NewSetInformation,
  serai_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
) {
  // Don't spawn retired Tributaries
  if RetiredTributary::get(&db, set.set.network).map(|session| session.0) >= Some(set.set.session.0)
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
  let mut validators = Vec::with_capacity(set.validators.len());
  let mut total_weight = 0;
  let mut validator_weights = HashMap::with_capacity(set.validators.len());
  for (validator, weight) in set.validators.iter().copied() {
    let validator_key = <Ristretto as Ciphersuite>::read_G(&mut validator.0.as_slice())
      .expect("Serai validator had an invalid public key");
    let validator = SeraiAddress::from(validator);
    let weight = u64::from(weight);
    tributary_validators.push((validator_key, weight));
    validators.push(validator);
    total_weight += weight;
    validator_weights.insert(validator, weight);
  }

  let tributary_db = tributary_db(set.set);
  let tributary =
    Tributary::new(tributary_db.clone(), genesis, start_time, serai_key, tributary_validators, p2p)
      .await
      .unwrap();
  let reader = tributary.reader();

  p2p_add_tributary
    .send((set.set, tributary.clone()))
    .expect("p2p's add_tributary channel was closed?");

  // Spawn the task to send all messages from the Tributary scanner to the message-queue
  let (scan_tributary_messages_task_def, scan_tributary_messages_task) = Task::new();
  tokio::spawn(
    (ScanTributaryMessagesTask { tributary_db: tributary_db.clone(), set: set.set, message_queue })
      .continually_run(scan_tributary_messages_task_def, vec![]),
  );

  let (scan_tributary_task_def, scan_tributary_task) = Task::new();
  tokio::spawn(
    (ScanTributaryTask {
      cosign_db: db.clone(),
      tributary_db,
      set: set.set,
      validators,
      total_weight,
      validator_weights,
      tributary: reader,
      _p2p: PhantomData::<P>,
    })
    // This is the only handle for this ScanTributaryMessagesTask, so when this task is dropped, it
    // will be too
    .continually_run(scan_tributary_task_def, vec![scan_tributary_messages_task]),
  );

  tokio::spawn(tributary::run(db, set, tributary, scan_tributary_task));
}

struct SubstrateTask<P: p2p::P2p> {
  serai_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  db: Db,
  message_queue: Arc<MessageQueue>,
  p2p: P,
  p2p_add_tributary: mpsc::UnboundedSender<(ValidatorSet, Tributary<P>)>,
  p2p_retire_tributary: mpsc::UnboundedSender<ValidatorSet>,
}

impl<P: p2p::P2p> ContinuallyRan for SubstrateTask<P> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let mut made_progress = false;

      // Handle the Canonical events
      for network in serai_client::primitives::NETWORKS {
        loop {
          let mut txn = self.db.txn();
          let Some(msg) = serai_coordinator_substrate::Canonical::try_recv(&mut txn, network)
          else {
            break;
          };

          match msg {
            // TODO: Stop trying to confirm the DKG
            messages::substrate::CoordinatorMessage::SetKeys { .. } => todo!("TODO"),
            messages::substrate::CoordinatorMessage::SlashesReported { session } => {
              let prior_retired = RetiredTributary::get(&txn, network);
              let next_to_be_retired =
                prior_retired.map(|session| Session(session.0 + 1)).unwrap_or(Session(0));
              assert_eq!(session, next_to_be_retired);
              RetiredTributary::set(&mut txn, network, &session);
              self
                .p2p_retire_tributary
                .send(ValidatorSet { network, session })
                .expect("p2p retire_tributary channel dropped?");
            }
            messages::substrate::CoordinatorMessage::Block { .. } => {}
          }

          let msg = messages::CoordinatorMessage::from(msg);
          let metadata = Metadata {
            from: Service::Coordinator,
            to: Service::Processor(network),
            intent: msg.intent(),
          };
          let msg = borsh::to_vec(&msg).unwrap();
          // TODO: Make this fallible
          self.message_queue.queue(metadata, msg).await;
          txn.commit();
          made_progress = true;
        }
      }

      // Handle the NewSet events
      loop {
        let mut txn = self.db.txn();
        let Some(new_set) = serai_coordinator_substrate::NewSet::try_recv(&mut txn) else { break };

        if let Some(historic_session) = new_set.set.session.0.checked_sub(2) {
          // We should have retired this session if we're here
          if RetiredTributary::get(&txn, new_set.set.network).map(|session| session.0) <
            Some(historic_session)
          {
            /*
              If we haven't, it's because we're processing the NewSet event before the retiry
              event from the Canonical event stream. This happens if the Canonical event, and
              then the NewSet event, is fired while we're already iterating over NewSet events.

              We break, dropping the txn, restoring this NewSet to the database, so we'll only
              handle it once a future iteration of this loop handles the retiry event.
            */
            break;
          }

          /*
            Queue this historical Tributary for deletion.

            We explicitly don't queue this upon Tributary retire, instead here, to give time to
            investigate retired Tributaries if questions are raised post-retiry. This gives a
            week (the duration of the following session) after the Tributary has been retired to
            make a backup of the data directory for any investigations.
          */
          TributaryCleanup::send(
            &mut txn,
            &ValidatorSet { network: new_set.set.network, session: Session(historic_session) },
          );
        }

        // Save this Tributary as active to the database
        {
          let mut active_tributaries =
            ActiveTributaries::get(&txn).unwrap_or(Vec::with_capacity(1));
          active_tributaries.push(new_set.clone());
          ActiveTributaries::set(&mut txn, &active_tributaries);
        }

        // Send GenerateKey to the processor
        let msg = messages::key_gen::CoordinatorMessage::GenerateKey {
          session: new_set.set.session,
          threshold: new_set.threshold,
          evrf_public_keys: new_set.evrf_public_keys.clone(),
        };
        let msg = messages::CoordinatorMessage::from(msg);
        let metadata = Metadata {
          from: Service::Coordinator,
          to: Service::Processor(new_set.set.network),
          intent: msg.intent(),
        };
        let msg = borsh::to_vec(&msg).unwrap();
        // TODO: Make this fallible
        self.message_queue.queue(metadata, msg).await;

        // Commit the transaction for all of this
        txn.commit();

        // Now spawn the Tributary
        // If we reboot after committing the txn, but before this is called, this will be called
        // on boot
        spawn_tributary(
          self.db.clone(),
          self.message_queue.clone(),
          self.p2p.clone(),
          &self.p2p_add_tributary,
          new_set,
          self.serai_key.clone(),
        )
        .await;

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}

#[tokio::main]
async fn main() {
  // Override the panic handler with one which will panic if any tokio task panics
  {
    let existing = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
      existing(panic);
      const MSG: &str = "exiting the process due to a task panicking";
      println!("{MSG}");
      log::error!("{MSG}");
      std::process::exit(1);
    }));
  }

  // Initialize the logger
  if std::env::var("RUST_LOG").is_err() {
    std::env::set_var("RUST_LOG", serai_env::var("RUST_LOG").unwrap_or_else(|| "info".to_string()));
  }
  env_logger::init();
  log::info!("starting coordinator service...");

  // Read the Serai key from the env
  let serai_key = {
    let mut key_hex = serai_env::var("SERAI_KEY").expect("Serai key wasn't provided");
    let mut key_vec = hex::decode(&key_hex).map_err(|_| ()).expect("Serai key wasn't hex-encoded");
    key_hex.zeroize();
    if key_vec.len() != 32 {
      key_vec.zeroize();
      panic!("Serai key had an invalid length");
    }
    let mut key_bytes = [0; 32];
    key_bytes.copy_from_slice(&key_vec);
    key_vec.zeroize();
    let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::from_repr(key_bytes).unwrap());
    key_bytes.zeroize();
    key
  };

  // Open the database
  let mut db = coordinator_db();

  let existing_tributaries_at_boot = {
    let mut txn = db.txn();

    // Cleanup all historic Tributaries
    while let Some(to_cleanup) = TributaryCleanup::try_recv(&mut txn) {
      prune_tributary_db(to_cleanup);
      // Drain the cosign intents created for this set
      while !Cosigning::<Db>::intended_cosigns(&mut txn, to_cleanup).is_empty() {}
    }

    // Remove retired Tributaries from ActiveTributaries
    let mut active_tributaries = ActiveTributaries::get(&txn).unwrap_or(vec![]);
    active_tributaries.retain(|tributary| {
      RetiredTributary::get(&txn, tributary.set.network).map(|session| session.0) <
        Some(tributary.set.session.0)
    });
    ActiveTributaries::set(&mut txn, &active_tributaries);

    txn.commit();

    active_tributaries
  };

  // Connect to the message-queue
  let message_queue = Arc::new(MessageQueue::from_env(Service::Coordinator));

  // Connect to the Serai node
  let serai = serai().await;

  let (p2p_add_tributary_send, p2p_add_tributary_recv) = mpsc::unbounded_channel();
  let (p2p_retire_tributary_send, p2p_retire_tributary_recv) = mpsc::unbounded_channel();
  let (p2p_cosigns_send, p2p_cosigns_recv) = mpsc::unbounded_channel();

  // Spawn the P2P network
  let p2p = {
    let serai_keypair = {
      let mut key_bytes = serai_key.to_bytes();
      // Schnorrkel SecretKey is the key followed by 32 bytes of entropy for nonces
      let mut expanded_key = Zeroizing::new([0; 64]);
      expanded_key.as_mut_slice()[.. 32].copy_from_slice(&key_bytes);
      OsRng.fill_bytes(&mut expanded_key.as_mut_slice()[32 ..]);
      key_bytes.zeroize();
      Zeroizing::new(
        schnorrkel::SecretKey::from_bytes(expanded_key.as_slice()).unwrap().to_keypair(),
      )
    };
    let p2p = p2p::Libp2p::new(&serai_keypair, serai.clone());
    tokio::spawn(p2p::run::<Db, Transaction, _>(
      db.clone(),
      p2p.clone(),
      p2p_add_tributary_recv,
      p2p_retire_tributary_recv,
      p2p_cosigns_send,
    ));
    p2p
  };

  // Spawn the Substrate scanners
  // TODO: SignSlashReport
  let (substrate_task_def, substrate_task) = Task::new();
  let (substrate_canonical_task_def, substrate_canonical_task) = Task::new();
  tokio::spawn(
    CanonicalEventStream::new(db.clone(), serai.clone())
      .continually_run(substrate_canonical_task_def, vec![substrate_task.clone()]),
  );
  let (substrate_ephemeral_task_def, substrate_ephemeral_task) = Task::new();
  tokio::spawn(
    EphemeralEventStream::new(
      db.clone(),
      serai.clone(),
      PublicKey::from_raw((<Ristretto as Ciphersuite>::generator() * serai_key.deref()).to_bytes()),
    )
    .continually_run(substrate_ephemeral_task_def, vec![substrate_task]),
  );

  // Spawn the cosign handler
  let (signed_cosigns_send, signed_cosigns_recv) = mpsc::unbounded_channel();
  spawn_cosigning(
    db.clone(),
    serai.clone(),
    p2p.clone(),
    // Run the Substrate scanners once we cosign new blocks
    vec![substrate_canonical_task, substrate_ephemeral_task],
    p2p_cosigns_recv,
    signed_cosigns_recv,
  );

  // Spawn all Tributaries on-disk
  for tributary in existing_tributaries_at_boot {
    spawn_tributary(
      db.clone(),
      message_queue.clone(),
      p2p.clone(),
      &p2p_add_tributary_send,
      tributary,
      serai_key.clone(),
    )
    .await;
  }

  // Handle the events from the Substrate scanner
  tokio::spawn(
    (SubstrateTask {
      serai_key: serai_key.clone(),
      db: db.clone(),
      message_queue: message_queue.clone(),
      p2p: p2p.clone(),
      p2p_add_tributary: p2p_add_tributary_send.clone(),
      p2p_retire_tributary: p2p_retire_tributary_send.clone(),
    })
    .continually_run(substrate_task_def, vec![]),
  );

  // TODO: Handle processor messages

  todo!("TODO")
}
