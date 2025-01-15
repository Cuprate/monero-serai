use sp_core::{ConstU32, bounded::BoundedVec};

pub use serai_validator_sets_primitives as primitives;

use serai_primitives::*;
use serai_validator_sets_primitives::*;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Call {
  set_keys {
    network: NetworkId,
    key_pair: KeyPair,
    signature_participants: bitvec::vec::BitVec<u8, bitvec::order::Lsb0>,
    signature: Signature,
  },
  set_embedded_elliptic_curve_key {
    embedded_elliptic_curve: EmbeddedEllipticCurve,
    key: BoundedVec<u8, ConstU32<{ MAX_KEY_LEN }>>,
  },
  report_slashes {
    network: NetworkId,
    slashes: SlashReport,
    signature: Signature,
  },
  allocate {
    network: NetworkId,
    amount: Amount,
  },
  deallocate {
    network: NetworkId,
    amount: Amount,
  },
  claim_deallocation {
    network: NetworkId,
    session: Session,
  },
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Event {
  NewSet {
    set: ValidatorSet,
  },
  ParticipantRemoved {
    set: ValidatorSet,
    removed: SeraiAddress,
  },
  KeyGen {
    set: ValidatorSet,
    key_pair: KeyPair,
  },
  AcceptedHandover {
    set: ValidatorSet,
  },
  SetRetired {
    set: ValidatorSet,
  },
  AllocationIncreased {
    validator: SeraiAddress,
    network: NetworkId,
    amount: Amount,
  },
  AllocationDecreased {
    validator: SeraiAddress,
    network: NetworkId,
    amount: Amount,
    delayed_until: Option<Session>,
  },
  DeallocationClaimed {
    validator: SeraiAddress,
    network: NetworkId,
    session: Session,
  },
}
