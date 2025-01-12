use std::{path::Path, fs};

pub(crate) use serai_db::{Get, DbTxn, Db as DbTrait};
use serai_db::{create_db, db_channel};

use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet},
};

use serai_cosign::SignedCosign;

use serai_coordinator_substrate::NewSetInformation;

#[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
pub(crate) type Db = serai_db::ParityDb;
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
  }
}

db_channel! {
  Coordinator {
    // Tributaries to clean up upon reboot
    TributaryCleanup: () -> ValidatorSet,
    // Cosigns we produced
    SignedCosigns: () -> SignedCosign,
  }
}
