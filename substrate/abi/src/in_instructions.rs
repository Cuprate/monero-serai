use serai_primitives::*;

pub use serai_in_instructions_primitives as primitives;
use primitives::SignedBatch;
use serai_validator_sets_primitives::Session;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Call {
  execute_batch { batch: SignedBatch },
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Event {
  Batch {
    network: NetworkId,
    publishing_session: Session,
    id: u32,
    in_instructions_hash: [u8; 32],
    in_instruction_results: bitvec::vec::BitVec<u8, bitvec::order::Lsb0>,
  },
  Halt {
    network: NetworkId,
  },
}
