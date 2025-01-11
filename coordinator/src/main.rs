use core::{ops::Deref, time::Duration};
use std::{sync::Arc, time::Instant};

use zeroize::{Zeroize, Zeroizing};
use rand_core::{RngCore, OsRng};

use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding},
  Ciphersuite, Ristretto,
};

use tokio::sync::mpsc;

use serai_client::{primitives::PublicKey, Serai};
use message_queue::{Service, client::MessageQueue};

use serai_task::{Task, TaskHandle, ContinuallyRan};

use serai_cosign::{SignedCosign, Cosigning};
use serai_coordinator_substrate::{CanonicalEventStream, EphemeralEventStream};
use serai_coordinator_tributary::Transaction;

mod db;
use db::*;

mod tributary;

mod substrate;
use substrate::SubstrateTask;

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
    crate::tributary::spawn_tributary(
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
