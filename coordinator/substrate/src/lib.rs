#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use scale::{Encode, Decode};
use borsh::{io, BorshSerialize, BorshDeserialize};

use serai_client::{
  primitives::{PublicKey, NetworkId},
  validator_sets::primitives::ValidatorSet,
};

use serai_db::*;

mod canonical;
mod ephemeral;

fn borsh_serialize_validators<W: io::Write>(
  validators: &Vec<(PublicKey, u16)>,
  writer: &mut W,
) -> Result<(), io::Error> {
  // This doesn't use `encode_to` as `encode_to` panics if the writer returns an error
  writer.write_all(&validators.encode())
}

fn borsh_deserialize_validators<R: io::Read>(
  reader: &mut R,
) -> Result<Vec<(PublicKey, u16)>, io::Error> {
  Decode::decode(&mut scale::IoReader(reader)).map_err(io::Error::other)
}

/// The information for a new set.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct NewSetInformation {
  set: ValidatorSet,
  serai_block: [u8; 32],
  start_time: u64,
  threshold: u16,
  #[borsh(
    serialize_with = "borsh_serialize_validators",
    deserialize_with = "borsh_deserialize_validators"
  )]
  validators: Vec<(PublicKey, u16)>,
  evrf_public_keys: Vec<([u8; 32], Vec<u8>)>,
}

mod _public_db {
  use serai_client::{primitives::NetworkId, validator_sets::primitives::ValidatorSet};

  use serai_db::*;

  use crate::NewSetInformation;

  db_channel!(
    CoordinatorSubstrate {
      // Canonical messages to send to the processor
      Canonical: (network: NetworkId) -> messages::substrate::CoordinatorMessage,

      // Relevant new set, from an ephemeral event stream
      NewSet: () -> NewSetInformation,
      // Relevant sign slash report, from an ephemeral event stream
      SignSlashReport: () -> ValidatorSet,
    }
  );
}

/// The canonical event stream.
pub struct Canonical;
impl Canonical {
  pub(crate) fn send(
    txn: &mut impl DbTxn,
    network: NetworkId,
    msg: &messages::substrate::CoordinatorMessage,
  ) {
    _public_db::Canonical::send(txn, network, msg);
  }
  /// Try to receive a canonical event, returning `None` if there is none to receive.
  pub fn try_recv(
    txn: &mut impl DbTxn,
    network: NetworkId,
  ) -> Option<messages::substrate::CoordinatorMessage> {
    _public_db::Canonical::try_recv(txn, network)
  }
}

/// The channel for new set events emitted by an ephemeral event stream.
pub struct NewSet;
impl NewSet {
  pub(crate) fn send(txn: &mut impl DbTxn, msg: &NewSetInformation) {
    _public_db::NewSet::send(txn, msg);
  }
  /// Try to receive a new set's information, returning `None` if there is none to receive.
  pub fn try_recv(txn: &mut impl DbTxn) -> Option<NewSetInformation> {
    _public_db::NewSet::try_recv(txn)
  }
}

/// The channel for notifications to sign a slash report, as emitted by an ephemeral event stream.
pub struct SignSlashReport;
impl SignSlashReport {
  pub(crate) fn send(txn: &mut impl DbTxn, set: &ValidatorSet) {
    _public_db::SignSlashReport::send(txn, set);
  }
  /// Try to receive a notification to sign a slash report, returning `None` if there is none to
  /// receive.
  pub fn try_recv(txn: &mut impl DbTxn) -> Option<ValidatorSet> {
    _public_db::SignSlashReport::try_recv(txn)
  }
}
