use std::collections::HashMap;

use scale::Encode;
use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{primitives::SeraiAddress, validator_sets::primitives::ValidatorSet};

use messages::sign::{VariantSignId, SignId};

use serai_db::*;

use crate::transaction::SigningProtocolRound;

/// A topic within the database which the group participates in
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, BorshSerialize, BorshDeserialize)]
pub(crate) enum Topic {
  /// Vote to remove a participant
  RemoveParticipant { participant: SeraiAddress },

  // DkgParticipation isn't represented here as participations are immediately sent to the
  // processor, not accumulated within this databse
  /// Participation in the signing protocol to confirm the DKG results on Substrate
  DkgConfirmation { attempt: u32, round: SigningProtocolRound },

  /// The local view of the SlashReport, to be aggregated into the final SlashReport
  SlashReport,

  /// Participation in a signing protocol
  Sign { id: VariantSignId, attempt: u32, round: SigningProtocolRound },
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
      Topic::DkgConfirmation { attempt, round: _ } => Some(Topic::DkgConfirmation {
        attempt: attempt + 1,
        round: SigningProtocolRound::Preprocess,
      }),
      Topic::SlashReport { .. } => None,
      Topic::Sign { id, attempt, round: _ } => {
        Some(Topic::Sign { id, attempt: attempt + 1, round: SigningProtocolRound::Preprocess })
      }
    }
  }

  // The topic for the re-attempt to schedule
  fn reattempt_topic(self) -> Option<(u32, Topic)> {
    #[allow(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, round } => match round {
        SigningProtocolRound::Preprocess => {
          let attempt = attempt + 1;
          Some((
            attempt,
            Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Preprocess },
          ))
        }
        SigningProtocolRound::Share => None,
      },
      Topic::SlashReport { .. } => None,
      Topic::Sign { id, attempt, round } => match round {
        SigningProtocolRound::Preprocess => {
          let attempt = attempt + 1;
          Some((attempt, Topic::Sign { id, attempt, round: SigningProtocolRound::Preprocess }))
        }
        SigningProtocolRound::Share => None,
      },
    }
  }

  // The SignId for this topic
  //
  // Returns None if Topic isn't Topic::Sign
  pub(crate) fn sign_id(self, set: ValidatorSet) -> Option<messages::sign::SignId> {
    #[allow(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { .. } => None,
      Topic::SlashReport { .. } => None,
      Topic::Sign { id, attempt, round: _ } => Some(SignId { session: set.session, id, attempt }),
    }
  }

  /// The topic which precedes this topic as a prerequisite
  ///
  /// The preceding topic must define this topic as succeeding
  fn preceding_topic(self) -> Option<Topic> {
    #[allow(clippy::match_same_arms)]
    match self {
      Topic::RemoveParticipant { .. } => None,
      Topic::DkgConfirmation { attempt, round } => match round {
        SigningProtocolRound::Preprocess => None,
        SigningProtocolRound::Share => {
          Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Preprocess })
        }
      },
      Topic::SlashReport { .. } => None,
      Topic::Sign { id, attempt, round } => match round {
        SigningProtocolRound::Preprocess => None,
        SigningProtocolRound::Share => {
          Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Preprocess })
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
      Topic::DkgConfirmation { attempt, round } => match round {
        SigningProtocolRound::Preprocess => {
          Some(Topic::DkgConfirmation { attempt, round: SigningProtocolRound::Share })
        }
        SigningProtocolRound::Share => None,
      },
      Topic::SlashReport { .. } => None,
      Topic::Sign { id, attempt, round } => match round {
        SigningProtocolRound::Preprocess => {
          Some(Topic::Sign { id, attempt, round: SigningProtocolRound::Share })
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

pub(crate) trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

/// The resulting data set from an accumulation
pub(crate) enum DataSet<D: Borshy> {
  /// Accumulating this did not produce a data set to act on
  /// (non-existent, not ready, prior handled, not participating, etc.)
  None,
  /// The data set was ready and we are participating in this event
  Participating(HashMap<SeraiAddress, D>),
}

create_db!(
  CoordinatorTributary {
    // The last handled tributary block's (number, hash)
    LastHandledTributaryBlock: (set: ValidatorSet) -> (u64, [u8; 32]),

    // The slash points a validator has accrued, with u64::MAX representing a fatal slash.
    SlashPoints: (set: ValidatorSet, validator: SeraiAddress) -> u64,

    // The latest Substrate block to cosign.
    LatestSubstrateBlockToCosign: (set: ValidatorSet) -> [u8; 32],
    // The hash of the block we're actively cosigning.
    ActivelyCosigning: (set: ValidatorSet) -> [u8; 32],
    // If this block has already been cosigned.
    Cosigned: (set: ValidatorSet, substrate_block_hash: [u8; 32]) -> (),

    // The weight accumulated for a topic.
    AccumulatedWeight: (set: ValidatorSet, topic: Topic) -> u64,
    // The entries accumulated for a topic, by validator.
    Accumulated: <D: Borshy>(set: ValidatorSet, topic: Topic, validator: SeraiAddress) -> D,

    // Topics to be recognized as of a certain block number due to the reattempt protocol.
    Reattempt: (set: ValidatorSet, block_number: u64) -> Vec<Topic>,
  }
);

db_channel!(
  CoordinatorTributary {
    ProcessorMessages: (set: ValidatorSet) -> messages::CoordinatorMessage,
  }
);

pub(crate) struct TributaryDb;
impl TributaryDb {
  pub(crate) fn last_handled_tributary_block(
    getter: &impl Get,
    set: ValidatorSet,
  ) -> Option<(u64, [u8; 32])> {
    LastHandledTributaryBlock::get(getter, set)
  }
  pub(crate) fn set_last_handled_tributary_block(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    block_number: u64,
    block_hash: [u8; 32],
  ) {
    LastHandledTributaryBlock::set(txn, set, &(block_number, block_hash));
  }

  pub(crate) fn latest_substrate_block_to_cosign(
    getter: &impl Get,
    set: ValidatorSet,
  ) -> Option<[u8; 32]> {
    LatestSubstrateBlockToCosign::get(getter, set)
  }
  pub(crate) fn set_latest_substrate_block_to_cosign(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    substrate_block_hash: [u8; 32],
  ) {
    LatestSubstrateBlockToCosign::set(txn, set, &substrate_block_hash);
  }
  pub(crate) fn actively_cosigning(txn: &mut impl DbTxn, set: ValidatorSet) -> Option<[u8; 32]> {
    ActivelyCosigning::get(txn, set)
  }
  pub(crate) fn start_cosigning(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    substrate_block_hash: [u8; 32],
    substrate_block_number: u64,
  ) {
    assert!(
      ActivelyCosigning::get(txn, set).is_none(),
      "starting cosigning while already cosigning"
    );
    ActivelyCosigning::set(txn, set, &substrate_block_hash);

    TributaryDb::recognize_topic(
      txn,
      set,
      Topic::Sign {
        id: VariantSignId::Cosign(substrate_block_number),
        attempt: 0,
        round: SigningProtocolRound::Preprocess,
      },
    );
  }
  pub(crate) fn finish_cosigning(txn: &mut impl DbTxn, set: ValidatorSet) {
    assert!(ActivelyCosigning::take(txn, set).is_some(), "finished cosigning but not cosigning");
  }
  pub(crate) fn mark_cosigned(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    substrate_block_hash: [u8; 32],
  ) {
    Cosigned::set(txn, set, substrate_block_hash, &());
  }
  pub(crate) fn cosigned(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    substrate_block_hash: [u8; 32],
  ) -> bool {
    Cosigned::get(txn, set, substrate_block_hash).is_some()
  }

  pub(crate) fn recognize_topic(txn: &mut impl DbTxn, set: ValidatorSet, topic: Topic) {
    AccumulatedWeight::set(txn, set, topic, &0);
  }

  pub(crate) fn start_of_block(txn: &mut impl DbTxn, set: ValidatorSet, block_number: u64) {
    for topic in Reattempt::take(txn, set, block_number).unwrap_or(vec![]) {
      /*
        TODO: Slash all people who preprocessed but didn't share, and add a delay to their
        participations in future protocols. When we call accumulate, if the participant has no
        delay, their accumulation occurs immediately. Else, the accumulation occurs after the
        specified delay.

        This means even if faulty validators are first to preprocess, they won't be selected for
        the signing set unless there's a lack of less faulty validators available.

        We need to decrease this delay upon successful partipations, and set it to the maximum upon
        `f + 1` validators voting to fatally slash the validator in question. This won't issue the
        fatal slash but should still be effective.
      */
      Self::recognize_topic(txn, set, topic);
      if let Some(id) = topic.sign_id(set) {
        Self::send_message(txn, set, messages::sign::CoordinatorMessage::Reattempt { id });
      }
    }
  }

  pub(crate) fn fatal_slash(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    validator: SeraiAddress,
    reason: &str,
  ) {
    log::warn!("{validator} fatally slashed: {reason}");
    SlashPoints::set(txn, set, validator, &u64::MAX);
  }

  pub(crate) fn is_fatally_slashed(
    getter: &impl Get,
    set: ValidatorSet,
    validator: SeraiAddress,
  ) -> bool {
    SlashPoints::get(getter, set, validator).unwrap_or(0) == u64::MAX
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) fn accumulate<D: Borshy>(
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
      let reattempt_topic = topic.reattempt_topic();
      if let Some((attempt, reattempt_topic)) = reattempt_topic {
        // 5 minutes
        #[cfg(not(feature = "longer-reattempts"))]
        const BASE_REATTEMPT_DELAY: u32 =
          (5u32 * 60 * 1000).div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME);

        // 10 minutes, intended for latent environments like the GitHub CI
        #[cfg(feature = "longer-reattempts")]
        const BASE_REATTEMPT_DELAY: u32 =
          (10u32 * 60 * 1000).div_ceil(tributary_sdk::tendermint::TARGET_BLOCK_TIME);

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
          // Clean this data up if there's not a re-attempt topic
          // If there is a re-attempt topic, we clean it up upon re-attempt
          if reattempt_topic.is_none() {
            Accumulated::<D>::del(txn, set, topic, *validator);
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

  pub(crate) fn send_message(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    message: impl Into<messages::CoordinatorMessage>,
  ) {
    ProcessorMessages::send(txn, set, &message.into());
  }
}
