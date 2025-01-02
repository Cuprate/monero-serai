use std::collections::HashMap;

use scale::Encode;
use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{primitives::SeraiAddress, validator_sets::primitives::ValidatorSet};

use processor_messages::sign::VariantSignId;

use serai_db::*;

use crate::tributary::transaction::SigningProtocolRound;

/// A topic within the database which the group participates in
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, BorshSerialize, BorshDeserialize)]
pub enum Topic {
  /// Vote to remove a participant
  RemoveParticipant { participant: SeraiAddress },

  // DkgParticipation isn't represented here as participations are immediately sent to the
  // processor, not accumulated within this databse
  /// Participation in the signing protocol to confirm the DKG results on Substrate
  DkgConfirmation { attempt: u32, label: SigningProtocolRound },

  /// The local view of the SlashReport, to be aggregated into the final SlashReport
  SlashReport,

  /// Participation in a signing protocol
  Sign { id: VariantSignId, attempt: u32, label: SigningProtocolRound },
}

enum Participating {
  Participated,
  Everyone,
}

impl Topic {
  // The topic used by the next attempt of this protocol
  fn next_attempt_topic(self) -> Option<Topic> {
    #[allow(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, label: _ } => Some(Topic::DkgConfirmation {
        attempt: attempt + 1,
        label: SigningProtocolRound::Preprocess,
      }),
      Topic::SlashReport { .. } => None,
      Topic::Sign { id, attempt, label: _ } => {
        Some(Topic::Sign { id, attempt: attempt + 1, label: SigningProtocolRound::Preprocess })
      }
    }
  }

  // The topic for the re-attempt to schedule
  fn reattempt_topic(self) -> Option<(u32, Topic)> {
    #[allow(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, label } => match label {
        SigningProtocolRound::Preprocess => {
          let attempt = attempt + 1;
          Some((
            attempt,
            Topic::DkgConfirmation { attempt, label: SigningProtocolRound::Preprocess },
          ))
        }
        SigningProtocolRound::Share => None,
      },
      Topic::SlashReport { .. } => None,
      Topic::Sign { id, attempt, label } => match label {
        SigningProtocolRound::Preprocess => {
          let attempt = attempt + 1;
          Some((attempt, Topic::Sign { id, attempt, label: SigningProtocolRound::Preprocess }))
        }
        SigningProtocolRound::Share => None,
      },
    }
  }

  /// The topic which precedes this topic as a prerequisite
  ///
  /// The preceding topic must define this topic as succeeding
  fn preceding_topic(self) -> Option<Topic> {
    #[allow(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, label } => match label {
        SigningProtocolRound::Preprocess => None,
        SigningProtocolRound::Share => {
          Some(Topic::DkgConfirmation { attempt, label: SigningProtocolRound::Preprocess })
        }
      },
      Topic::SlashReport { .. } => None,
      Topic::Sign { id, attempt, label } => match label {
        SigningProtocolRound::Preprocess => None,
        SigningProtocolRound::Share => {
          Some(Topic::Sign { id, attempt, label: SigningProtocolRound::Preprocess })
        }
      },
    }
  }

  /// The topic which succeeds this topic, with this topic as a prerequisite
  ///
  /// The succeeding topic must define this topic as preceding
  fn succeeding_topic(self) -> Option<Topic> {
    #[allow(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, label } => match label {
        SigningProtocolRound::Preprocess => {
          Some(Topic::DkgConfirmation { attempt, label: SigningProtocolRound::Share })
        }
        SigningProtocolRound::Share => None,
      },
      Topic::SlashReport { .. } => None,
      Topic::Sign { id, attempt, label } => match label {
        SigningProtocolRound::Preprocess => {
          Some(Topic::Sign { id, attempt, label: SigningProtocolRound::Share })
        }
        SigningProtocolRound::Share => None,
      },
    }
  }

  fn requires_whitelisting(&self) -> bool {
    #[allow(clippy::match_same_arms)]
    match self {
      // We don't require whitelisting to remove a participant
      Topic::RemoveParticipant { .. } => false,
      // We don't require whitelisting for the first attempt, solely the re-attempts
      Topic::DkgConfirmation { attempt, .. } => *attempt != 0,
      // We don't require whitelisting for the slash report
      Topic::SlashReport { .. } => false,
      // We do require whitelisting for every sign protocol
      Topic::Sign { .. } => true,
    }
  }

  fn required_participation(&self, n: u64) -> u64 {
    let _ = self;
    // All of our topics require 2/3rds participation
    ((2 * n) / 3) + 1
  }

  fn participating(&self) -> Participating {
    #[allow(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => Participating::Everyone,
      Topic::DkgConfirmation { .. } => Participating::Participated,
      Topic::SlashReport { .. } => Participating::Everyone,
      Topic::Sign { .. } => Participating::Participated,
    }
  }
}

/// The resulting data set from an accumulation
pub enum DataSet<D: Borshy> {
  /// Accumulating this did not produce a data set to act on
  /// (non-existent, not ready, prior handled, not participating, etc.)
  None,
  /// The data set was ready and we are participating in this event
  Participating(HashMap<SeraiAddress, D>),
}

trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

create_db!(
  CoordinatorTributary {
    // The last handled tributary block's (number, hash)
    LastHandledTributaryBlock: (set: ValidatorSet) -> (u64, [u8; 32]),

    // The slash points a validator has accrued, with u64::MAX representing a fatal slash.
    SlashPoints: (set: ValidatorSet, validator: SeraiAddress) -> u64,

    // The latest Substrate block to cosign.
    LatestSubstrateBlockToCosign: (set: ValidatorSet) -> [u8; 32],

    // The weight accumulated for a topic.
    AccumulatedWeight: (set: ValidatorSet, topic: Topic) -> u64,
    // The entries accumulated for a topic, by validator.
    Accumulated: <D: Borshy>(set: ValidatorSet, topic: Topic, validator: SeraiAddress) -> D,

    // Topics to be recognized as of a certain block number due to the reattempt protocol.
    Reattempt: (set: ValidatorSet, block_number: u64) -> Vec<Topic>,
  }
);

pub struct TributaryDb;
impl TributaryDb {
  pub fn last_handled_tributary_block(
    getter: &impl Get,
    set: ValidatorSet,
  ) -> Option<(u64, [u8; 32])> {
    LastHandledTributaryBlock::get(getter, set)
  }
  pub fn set_last_handled_tributary_block(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    block_number: u64,
    block_hash: [u8; 32],
  ) {
    LastHandledTributaryBlock::set(txn, set, &(block_number, block_hash));
  }

  pub fn recognize_topic(txn: &mut impl DbTxn, set: ValidatorSet, topic: Topic) {
    AccumulatedWeight::set(txn, set, topic, &0);
  }

  pub fn start_of_block(txn: &mut impl DbTxn, set: ValidatorSet, block_number: u64) {
    for topic in Reattempt::take(txn, set, block_number).unwrap_or(vec![]) {
      // TODO: Slash all people who preprocessed but didn't share
      Self::recognize_topic(txn, set, topic);
    }
  }

  pub fn fatal_slash(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    validator: SeraiAddress,
    reason: &str,
  ) {
    log::warn!("{validator} fatally slashed: {reason}");
    SlashPoints::set(txn, set, validator, &u64::MAX);
  }

  pub fn is_fatally_slashed(getter: &impl Get, set: ValidatorSet, validator: SeraiAddress) -> bool {
    SlashPoints::get(getter, set, validator).unwrap_or(0) == u64::MAX
  }

  #[allow(clippy::too_many_arguments)]
  pub fn accumulate<D: Borshy>(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    validators: &[SeraiAddress],
    total_weight: u64,
    block_number: u64,
    topic: Topic,
    validator: SeraiAddress,
    validator_weight: u64,
    data: &D,
  ) -> DataSet<D> {
    // This function will only be called once for a (validator, topic) tuple due to how we handle
    // nonces on transactions (deterministically to the topic)

    let accumulated_weight = AccumulatedWeight::get(txn, set, topic);
    if topic.requires_whitelisting() && accumulated_weight.is_none() {
      Self::fatal_slash(txn, set, validator, "participated in unrecognized topic");
      return DataSet::None;
    }
    let mut accumulated_weight = accumulated_weight.unwrap_or(0);

    // Check if there's a preceding topic, this validator participated
    let preceding_topic = topic.preceding_topic();
    if let Some(preceding_topic) = preceding_topic {
      if Accumulated::<D>::get(txn, set, preceding_topic, validator).is_none() {
        Self::fatal_slash(
          txn,
          set,
          validator,
          "participated in topic without participating in prior",
        );
        return DataSet::None;
      }
    }

    // The complete lack of validation on the data by these NOPs opens the potential for spam here

    // If we've already accumulated past the threshold, NOP
    if accumulated_weight >= topic.required_participation(total_weight) {
      return DataSet::None;
    }
    // If this is for an old attempt, NOP
    if let Some(next_attempt_topic) = topic.next_attempt_topic() {
      if AccumulatedWeight::get(txn, set, next_attempt_topic).is_some() {
        return DataSet::None;
      }
    }

    // Accumulate the data
    accumulated_weight += validator_weight;
    AccumulatedWeight::set(txn, set, topic, &accumulated_weight);
    Accumulated::set(txn, set, topic, validator, data);

    // Check if we now cross the weight threshold
    if accumulated_weight >= topic.required_participation(total_weight) {
      // Queue this for re-attempt after enough time passes
      if let Some((attempt, reattempt_topic)) = topic.reattempt_topic() {
        // 5 minutes
        #[cfg(not(feature = "longer-reattempts"))]
        const BASE_REATTEMPT_DELAY: u32 =
          (5u32 * 60 * 1000).div_ceil(tributary::tendermint::TARGET_BLOCK_TIME);

        // 10 minutes, intended for latent environments like the GitHub CI
        #[cfg(feature = "longer-reattempts")]
        const BASE_REATTEMPT_DELAY: u32 =
          (10u32 * 60 * 1000).div_ceil(tributary::tendermint::TARGET_BLOCK_TIME);

        // Linearly scale the time for the protocol with the attempt number
        let blocks_till_reattempt = u64::from(attempt * BASE_REATTEMPT_DELAY);

        let recognize_at = block_number + blocks_till_reattempt;
        let mut queued = Reattempt::get(txn, set, recognize_at).unwrap_or(Vec::with_capacity(1));
        queued.push(reattempt_topic);
        Reattempt::set(txn, set, recognize_at, &queued);
      }

      // Register the succeeding topic
      let succeeding_topic = topic.succeeding_topic();
      if let Some(succeeding_topic) = succeeding_topic {
        Self::recognize_topic(txn, set, succeeding_topic);
      }

      // Fetch and return all participations
      let mut data_set = HashMap::with_capacity(validators.len());
      for validator in validators {
        if let Some(data) = Accumulated::<D>::get(txn, set, topic, *validator) {
          // Clean this data up if there's not a succeeding topic
          // If there is, we wait as the succeeding topic checks our participation in this topic
          if succeeding_topic.is_none() {
            Accumulated::<D>::del(txn, set, topic, *validator);
          }
          // If this *was* the succeeding topic, clean up the preceding topic's data
          if let Some(preceding_topic) = preceding_topic {
            Accumulated::<D>::del(txn, set, preceding_topic, *validator);
          }
          data_set.insert(*validator, data);
        }
      }
      let participated = data_set.contains_key(&validator);
      match topic.participating() {
        Participating::Participated => {
          if participated {
            DataSet::Participating(data_set)
          } else {
            DataSet::None
          }
        }
        Participating::Everyone => DataSet::Participating(data_set),
      }
    } else {
      DataSet::None
    }
  }
}
