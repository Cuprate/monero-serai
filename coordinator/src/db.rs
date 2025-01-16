use std::{path::Path, fs};

pub(crate) use serai_db::{Get, DbTxn, Db as DbTrait};
use serai_db::{create_db, db_channel};

use dkg::Participant;

use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet, KeyPair},
};

use serai_cosign::SignedCosign;
use serai_coordinator_substrate::NewSetInformation;
use serai_coordinator_tributary::Transaction;

#[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
pub(crate) type Db = std::sync::Arc<serai_db::ParityDb>;
#[cfg(feature = "rocksdb")]
pub(crate) type Db = serai_db::RocksDB;

#[allow(unused_variables, unreachable_code)]
fn db(path: &str) -> Db {
  {
    let path: &Path = path.as_ref();
    // This may error if this path already exists, which we shouldn't propagate/panic on. If this
    // is a problem (such as we don't have the necessary permissions to write to this path), we
    // expect the following DB opening to error.
    let _: Result<_, _> = fs::create_dir_all(path.parent().unwrap());
  }

  #[cfg(all(feature = "parity-db", feature = "rocksdb"))]
  panic!("built with parity-db and rocksdb");
  #[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
  let db = serai_db::new_parity_db(path);
  #[cfg(feature = "rocksdb")]
  let db = serai_db::new_rocksdb(path);
  db
}

pub(crate) fn coordinator_db() -> Db {
  let root_path = serai_env::var("DB_PATH").expect("path to DB wasn't specified");
  db(&format!("{root_path}/coordinator/db"))
}

fn tributary_db_folder(set: ValidatorSet) -> String {
  let root_path = serai_env::var("DB_PATH").expect("path to DB wasn't specified");
  let network = match set.network {
    NetworkId::Serai => panic!("creating Tributary for the Serai network"),
    NetworkId::Bitcoin => "Bitcoin",
    NetworkId::Ethereum => "Ethereum",
    NetworkId::Monero => "Monero",
  };
  format!("{root_path}/tributary-{network}-{}", set.session.0)
}

pub(crate) fn tributary_db(set: ValidatorSet) -> Db {
  db(&format!("{}/db", tributary_db_folder(set)))
}

pub(crate) fn prune_tributary_db(set: ValidatorSet) {
  log::info!("pruning data directory for tributary {set:?}");
  let db = tributary_db_folder(set);
  if fs::exists(&db).expect("couldn't check if tributary DB exists") {
    fs::remove_dir_all(db).unwrap();
  }
}

create_db! {
  Coordinator {
    // The currently active Tributaries
    ActiveTributaries: () -> Vec<NewSetInformation>,
    // The latest Tributary to have been retired for a network
    // Since Tributaries are retired sequentially, this is informative to if any Tributary has been
    // retired
    RetiredTributary: (network: NetworkId) -> Session,
    // The last handled message from a Processor
    LastProcessorMessage: (network: NetworkId) -> u64,
    // Cosigns we produced and tried to intake yet incurred an error while doing so
    ErroneousCosigns: () -> Vec<SignedCosign>,
    // The keys to confirm and set on the Serai network
    KeysToConfirm: (set: ValidatorSet) -> KeyPair,
  }
}

db_channel! {
  Coordinator {
    // Cosigns we produced
    SignedCosigns: () -> SignedCosign,
    // Tributaries to clean up upon reboot
    TributaryCleanup: () -> ValidatorSet,
  }
}

mod _internal_db {
  use super::*;

  db_channel! {
    Coordinator {
      // Tributary transactions to publish from the Processor messages
      TributaryTransactionsFromProcessorMessages: (set: ValidatorSet) -> Transaction,
      // Tributary transactions to publish from the DKG confirmation task
      TributaryTransactionsFromDkgConfirmation: (set: ValidatorSet) -> Transaction,
      // Participants to remove
      RemoveParticipant: (set: ValidatorSet) -> Participant,
    }
  }
}

pub(crate) struct TributaryTransactionsFromProcessorMessages;
impl TributaryTransactionsFromProcessorMessages {
  pub(crate) fn send(txn: &mut impl DbTxn, set: ValidatorSet, tx: &Transaction) {
    // If this set has yet to be retired, send this transaction
    if RetiredTributary::get(txn, set.network).map(|session| session.0) < Some(set.session.0) {
      _internal_db::TributaryTransactionsFromProcessorMessages::send(txn, set, tx);
    }
  }
  pub(crate) fn try_recv(txn: &mut impl DbTxn, set: ValidatorSet) -> Option<Transaction> {
    _internal_db::TributaryTransactionsFromProcessorMessages::try_recv(txn, set)
  }
}

pub(crate) struct TributaryTransactionsFromDkgConfirmation;
impl TributaryTransactionsFromDkgConfirmation {
  pub(crate) fn send(txn: &mut impl DbTxn, set: ValidatorSet, tx: &Transaction) {
    // If this set has yet to be retired, send this transaction
    if RetiredTributary::get(txn, set.network).map(|session| session.0) < Some(set.session.0) {
      _internal_db::TributaryTransactionsFromDkgConfirmation::send(txn, set, tx);
    }
  }
  pub(crate) fn try_recv(txn: &mut impl DbTxn, set: ValidatorSet) -> Option<Transaction> {
    _internal_db::TributaryTransactionsFromDkgConfirmation::try_recv(txn, set)
  }
}

pub(crate) struct RemoveParticipant;
impl RemoveParticipant {
  pub(crate) fn send(txn: &mut impl DbTxn, set: ValidatorSet, participant: Participant) {
    // If this set has yet to be retired, send this transaction
    if RetiredTributary::get(txn, set.network).map(|session| session.0) < Some(set.session.0) {
      _internal_db::RemoveParticipant::send(txn, set, &participant);
    }
  }
  pub(crate) fn try_recv(txn: &mut impl DbTxn, set: ValidatorSet) -> Option<Participant> {
    _internal_db::RemoveParticipant::try_recv(txn, set)
  }
}
