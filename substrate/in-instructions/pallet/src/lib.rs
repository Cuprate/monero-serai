#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use sp_io::hashing::blake2_256;

use serai_primitives::{BlockHash, NetworkId};

pub use in_instructions_primitives as primitives;
use primitives::*;

// TODO: Investigate why Substrate generates these
#[allow(
  unreachable_patterns,
  clippy::cast_possible_truncation,
  clippy::no_effect_underscore_binding,
  clippy::empty_docs
)]
#[frame_support::pallet]
pub mod pallet {
  use sp_std::vec;
  use sp_application_crypto::RuntimePublic;
  use sp_runtime::traits::Zero;
  use sp_core::sr25519::Public;

  use serai_primitives::{Coin, Amount, Balance};

  use frame_support::pallet_prelude::*;
  use frame_system::{pallet_prelude::*, RawOrigin};

  use coins_pallet::{
    Config as CoinsConfig, Pallet as Coins,
    primitives::{OutInstruction, OutInstructionWithBalance},
  };
  use dex_pallet::{Config as DexConfig, Pallet as Dex};
  use validator_sets_pallet::{
    primitives::{Session, ValidatorSet},
    Config as ValidatorSetsConfig, Pallet as ValidatorSets,
  };

  use genesis_liquidity_pallet::{
    Pallet as GenesisLiq, Config as GenesisLiqConfig, primitives::GENESIS_LIQUIDITY_ACCOUNT,
  };
  use emissions_pallet::{Pallet as Emissions, Config as EmissionsConfig, primitives::POL_ACCOUNT};

  use super::*;

  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + CoinsConfig
    + DexConfig
    + ValidatorSetsConfig
    + GenesisLiqConfig
    + EmissionsConfig
  {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    Batch {
      network: NetworkId,
      publishing_session: Session,
      external_network_block_hash: [u8; 32],
      id: u32,
      in_instructions_hash: [u8; 32],
      in_instruction_results: BitVec<u8, Lsb0>,
    },
    Halt {
      network: NetworkId,
    },
  }

  #[pallet::error]
  pub enum Error<T> {
    /// Coin and OutAddress types don't match.
    InvalidAddressForCoin,
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  // The ID of the last executed Batch for a network.
  #[pallet::storage]
  #[pallet::getter(fn batches)]
  pub(crate) type LastBatch<T: Config> = StorageMap<_, Identity, NetworkId, u32, OptionQuery>;

  // The last Serai block in which this validator set included a batch
  #[pallet::storage]
  #[pallet::getter(fn last_batch_block)]
  pub(crate) type LastBatchBlock<T: Config> =
    StorageMap<_, Identity, NetworkId, BlockNumberFor<T>, OptionQuery>;

  // Halted networks.
  #[pallet::storage]
  pub(crate) type Halted<T: Config> = StorageMap<_, Identity, NetworkId, (), OptionQuery>;

  impl<T: Config> Pallet<T> {
    // Use a dedicated transaction layer when executing this InInstruction
    // This lets it individually error without causing any storage modifications
    #[frame_support::transactional]
    fn execute(instruction: InInstructionWithBalance) -> Result<(), DispatchError> {
      match instruction.instruction {
        InInstruction::Transfer(address) => {
          Coins::<T>::mint(address.into(), instruction.balance)?;
        }
        InInstruction::Dex(call) => {
          // This will only be initiated by external chain transactions. That is why we only need
          // add liquidity and swaps. Other functionalities (such as remove_liq, etc) will be
          // called directly from Serai with a native transaction.
          match call {
            DexCall::SwapAndAddLiquidity(address) => {
              let origin = RawOrigin::Signed(IN_INSTRUCTION_EXECUTOR.into());
              let coin = instruction.balance.coin;

              // mint the given coin on the account
              Coins::<T>::mint(IN_INSTRUCTION_EXECUTOR.into(), instruction.balance)?;

              // swap half of it for SRI
              let half = instruction.balance.amount.0 / 2;
              let path = BoundedVec::try_from(vec![coin, Coin::Serai]).unwrap();
              Dex::<T>::swap_exact_tokens_for_tokens(
                origin.clone().into(),
                path,
                half,
                1, // minimum out, so we accept whatever we get.
                IN_INSTRUCTION_EXECUTOR.into(),
              )?;

              // get how much we got for our swap
              let sri_amount = Coins::<T>::balance(IN_INSTRUCTION_EXECUTOR.into(), Coin::Serai).0;

              // add liquidity
              Dex::<T>::add_liquidity(
                origin.clone().into(),
                coin,
                half,
                sri_amount,
                1,
                1,
                address.into(),
              )?;

              // TODO: minimums are set to 1 above to guarantee successful adding liq call.
              // Ideally we either get this info from user or send the leftovers back to user.
              // Let's send the leftovers back to user for now.
              let coin_balance = Coins::<T>::balance(IN_INSTRUCTION_EXECUTOR.into(), coin);
              let sri_balance = Coins::<T>::balance(IN_INSTRUCTION_EXECUTOR.into(), Coin::Serai);
              if coin_balance != Amount(0) {
                Coins::<T>::transfer_internal(
                  IN_INSTRUCTION_EXECUTOR.into(),
                  address.into(),
                  Balance { coin, amount: coin_balance },
                )?;
              }
              if sri_balance != Amount(0) {
                Coins::<T>::transfer_internal(
                  IN_INSTRUCTION_EXECUTOR.into(),
                  address.into(),
                  Balance { coin: Coin::Serai, amount: sri_balance },
                )?;
              }
            }
            DexCall::Swap(out_balance, out_address) => {
              let send_to_external = !out_address.is_native();
              let native_coin = out_balance.coin.is_native();

              // we can't send native coin to external chain
              if native_coin && send_to_external {
                Err(Error::<T>::InvalidAddressForCoin)?;
              }

              // mint the given coin on our account
              Coins::<T>::mint(IN_INSTRUCTION_EXECUTOR.into(), instruction.balance)?;

              // get the path
              let mut path = vec![instruction.balance.coin, Coin::Serai];
              if !native_coin {
                path.push(out_balance.coin);
              }

              // get the swap address
              // if the address is internal, we can directly swap to it. if not, we swap to
              // ourselves and burn the coins to send them back on the external chain.
              let send_to = if send_to_external {
                IN_INSTRUCTION_EXECUTOR
              } else {
                out_address.clone().as_native().unwrap()
              };

              // do the swap
              let origin = RawOrigin::Signed(IN_INSTRUCTION_EXECUTOR.into());
              Dex::<T>::swap_exact_tokens_for_tokens(
                origin.clone().into(),
                BoundedVec::try_from(path).unwrap(),
                instruction.balance.amount.0,
                out_balance.amount.0,
                send_to.into(),
              )?;

              // burn the received coins so that they sent back to the user
              // if it is requested to an external address.
              if send_to_external {
                // see how much we got
                let coin_balance =
                  Coins::<T>::balance(IN_INSTRUCTION_EXECUTOR.into(), out_balance.coin);
                let instruction = OutInstructionWithBalance {
                  instruction: OutInstruction { address: out_address.as_external().unwrap() },
                  balance: Balance { coin: out_balance.coin, amount: coin_balance },
                };
                Coins::<T>::burn_with_instruction(origin.into(), instruction)?;
              }
            }
          }
        }
        InInstruction::GenesisLiquidity(address) => {
          Coins::<T>::mint(GENESIS_LIQUIDITY_ACCOUNT.into(), instruction.balance)?;
          GenesisLiq::<T>::add_coin_liquidity(address.into(), instruction.balance)?;
        }
        InInstruction::SwapToStakedSRI(address, network) => {
          Coins::<T>::mint(POL_ACCOUNT.into(), instruction.balance)?;
          Emissions::<T>::swap_to_staked_sri(address.into(), network, instruction.balance)?;
        }
      }
      Ok(())
    }

    pub fn halt(network: NetworkId) -> Result<(), DispatchError> {
      Halted::<T>::set(network, Some(()));
      Self::deposit_event(Event::Halt { network });
      Ok(())
    }
  }

  fn keys_for_network<T: Config>(
    network: NetworkId,
  ) -> Result<(Session, Option<Public>, Option<Public>), InvalidTransaction> {
    // If there's no session set, and therefore no keys set, then this must be an invalid signature
    let Some(session) = ValidatorSets::<T>::session(network) else {
      Err(InvalidTransaction::BadProof)?
    };
    let mut set = ValidatorSet { session, network };
    let latest = ValidatorSets::<T>::keys(set).map(|keys| keys.0);
    let prior = if set.session.0 != 0 {
      set.session.0 -= 1;
      ValidatorSets::<T>::keys(set).map(|keys| keys.0)
    } else {
      None
    };
    if prior.is_none() && latest.is_none() {
      Err(InvalidTransaction::BadProof)?;
    }
    Ok((session, prior, latest))
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn execute_batch(origin: OriginFor<T>, batch: SignedBatch) -> DispatchResult {
      ensure_none(origin)?;

      // The entire Batch execution is handled in pre_dispatch

      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      // Match to be exhaustive
      let batch = match call {
        Call::execute_batch { ref batch } => batch,
        Call::__Ignore(_, _) => unreachable!(),
      };

      // verify the batch size
      // TODO: Merge this encode with the one done by batch_message
      if batch.batch.encode().len() > MAX_BATCH_SIZE {
        Err(InvalidTransaction::ExhaustsResources)?;
      }

      let network = batch.batch.network;
      // Don't allow the Serai set to publish `Batch`s as-if Serai itself was an external network
      if network == NetworkId::Serai {
        Err(InvalidTransaction::Custom(0))?;
      }

      // verify the signature
      let (current_session, prior, current) = keys_for_network::<T>(network)?;
      let prior_session = Session(current_session.0 - 1);
      let batch_message = batch_message(&batch.batch);
      // Check the prior key first since only a single `Batch` (the last one) will be when prior is
      // Some yet prior wasn't the signing key
      let valid_by_prior =
        if let Some(key) = prior { key.verify(&batch_message, &batch.signature) } else { false };
      let valid = valid_by_prior ||
        (if let Some(key) = current {
          key.verify(&batch_message, &batch.signature)
        } else {
          false
        });
      if !valid {
        Err(InvalidTransaction::BadProof)?;
      }

      let batch = batch.batch;

      if Halted::<T>::contains_key(network) {
        Err(InvalidTransaction::Custom(1))?;
      }

      // If it wasn't valid by the prior key, meaning it was valid by the current key, the current
      // key is publishing `Batch`s. This should only happen once the current key has verified all
      // `Batch`s published by the prior key, meaning they are accepting the hand-over.
      if prior.is_some() && (!valid_by_prior) {
        ValidatorSets::<T>::retire_set(ValidatorSet { network, session: prior_session });
      }

      // check that this validator set isn't publishing a batch more than once per block
      let current_block = <frame_system::Pallet<T>>::block_number();
      let last_block = LastBatchBlock::<T>::get(network).unwrap_or(Zero::zero());
      if last_block >= current_block {
        Err(InvalidTransaction::Future)?;
      }
      LastBatchBlock::<T>::insert(batch.network, frame_system::Pallet::<T>::block_number());

      // Verify the batch is sequential
      // LastBatch has the last ID set. The next ID should be it + 1
      // If there's no ID, the next ID should be 0
      let expected = LastBatch::<T>::get(network).map_or(0, |prev| prev + 1);
      if batch.id < expected {
        Err(InvalidTransaction::Stale)?;
      }
      if batch.id > expected {
        Err(InvalidTransaction::Future)?;
      }
      LastBatch::<T>::insert(batch.network, batch.id);

      let in_instructions_hash = blake2_256(&batch.instructions.encode());
      let mut in_instruction_results = BitVec::new();
      for (i, instruction) in batch.instructions.into_iter().enumerate() {
        // Verify this coin is for this network
        if instruction.balance.coin.network() != batch.network {
          Err(InvalidTransaction::Custom(2))?;
        }

        in_instruction_results.push(Self::execute(instruction).is_ok());
      }

      Self::deposit_event(Event::Batch {
        network: batch.network,
        publishing_session: if valid_by_prior { prior_session } else { current_session },
        id: batch.id,
        external_network_block_hash: batch.external_network_block_hash,
        in_instructions_hash,
        in_instruction_results,
      });

      ValidTransaction::with_tag_prefix("in-instructions")
        .and_provides((batch.batch.network, batch.batch.id))
        // Set a 10 block longevity, though this should be included in the next block
        .longevity(10)
        .propagate(true)
        .build()
    }

    // Explicitly provide a pre-dispatch which calls validate_unsigned
    fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
      Self::validate_unsigned(TransactionSource::InBlock, call).map(|_| ()).map_err(Into::into)
    }
  }
}

pub use pallet::*;
