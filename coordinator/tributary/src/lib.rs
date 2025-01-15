#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{marker::PhantomData, future::Future};
use std::collections::HashMap;

use ciphersuite::group::GroupEncoding;

use serai_client::{
  primitives::SeraiAddress,
  validator_sets::primitives::{ValidatorSet, Slash},
};

use serai_db::*;
use serai_task::ContinuallyRan;

use tributary_sdk::{
  tendermint::{
    tx::{TendermintTx, Evidence, decode_signed_message},
    TendermintNetwork,
  },
  Signed as TributarySigned, TransactionKind, TransactionTrait,
  Transaction as TributaryTransaction, Block, TributaryReader, P2p,
};

use serai_cosign::CosignIntent;
use serai_coordinator_substrate::NewSetInformation;

use messages::sign::VariantSignId;

mod transaction;
pub use transaction::{SigningProtocolRound, Signed, Transaction};

mod db;
use db::*;
pub use db::Topic;

/// Messages to send to the Processors.
pub struct ProcessorMessages;
impl ProcessorMessages {
  /// Try to receive a message to send to a Processor.
  pub fn try_recv(txn: &mut impl DbTxn, set: ValidatorSet) -> Option<messages::CoordinatorMessage> {
    db::ProcessorMessages::try_recv(txn, set)
  }
}

/// The cosign intents.
pub struct CosignIntents;
impl CosignIntents {
  /// Provide a CosignIntent for this Tributary.
  ///
  /// This must be done before the associated `Transaction::Cosign` is provided.
  pub fn provide(txn: &mut impl DbTxn, set: ValidatorSet, intent: &CosignIntent) {
    db::CosignIntents::set(txn, set, intent.block_hash, intent);
  }
  fn take(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    substrate_block_hash: [u8; 32],
  ) -> Option<CosignIntent> {
    db::CosignIntents::take(txn, set, substrate_block_hash)
  }
}

/// An interface to the topics recognized on this Tributary.
pub struct RecognizedTopics;
impl RecognizedTopics {
  /// If this topic has been recognized by this Tributary.
  ///
  /// This will either be by explicit recognition or participation.
  pub fn recognized(getter: &impl Get, set: ValidatorSet, topic: Topic) -> bool {
    TributaryDb::recognized(getter, set, topic)
  }
  /// The next topic requiring recognition which has been recognized by this Tributary.
  pub fn try_recv_topic_requiring_recognition(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
  ) -> Option<Topic> {
    db::RecognizedTopics::try_recv(txn, set)
  }
}

/// The plans to recognize upon a `Transaction::SubstrateBlock` being included on-chain.
pub struct SubstrateBlockPlans;
impl SubstrateBlockPlans {
  /// Set the plans to recognize upon the associated `Transaction::SubstrateBlock` being included
  /// on-chain.
  ///
  /// This must be done before the associated `Transaction::Cosign` is provided.
  pub fn set(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    substrate_block_hash: [u8; 32],
    plans: &Vec<[u8; 32]>,
  ) {
    db::SubstrateBlockPlans::set(txn, set, substrate_block_hash, plans);
  }
  fn take(
    txn: &mut impl DbTxn,
    set: ValidatorSet,
    substrate_block_hash: [u8; 32],
  ) -> Option<Vec<[u8; 32]>> {
    db::SubstrateBlockPlans::take(txn, set, substrate_block_hash)
  }
}

struct ScanBlock<'a, TD: Db, TDT: DbTxn, P: P2p> {
  _td: PhantomData<TD>,
  _p2p: PhantomData<P>,
  tributary_txn: &'a mut TDT,
  set: ValidatorSet,
  validators: &'a [SeraiAddress],
  total_weight: u64,
  validator_weights: &'a HashMap<SeraiAddress, u64>,
}
impl<'a, TD: Db, TDT: DbTxn, P: P2p> ScanBlock<'a, TD, TDT, P> {
  fn potentially_start_cosign(&mut self) {
    // Don't start a new cosigning instance if we're actively running one
    if TributaryDb::actively_cosigning(self.tributary_txn, self.set).is_some() {
      return;
    }

    // Fetch the latest intended-to-be-cosigned block
    let Some(latest_substrate_block_to_cosign) =
      TributaryDb::latest_substrate_block_to_cosign(self.tributary_txn, self.set)
    else {
      return;
    };

    // If it was already cosigned, return
    if TributaryDb::cosigned(self.tributary_txn, self.set, latest_substrate_block_to_cosign) {
      return;
    }

    let intent =
      CosignIntents::take(self.tributary_txn, self.set, latest_substrate_block_to_cosign)
        .expect("Transaction::Cosign locally provided but CosignIntents wasn't populated");
    assert_eq!(
      intent.block_hash, latest_substrate_block_to_cosign,
      "provided CosignIntent wasn't saved by its block hash"
    );

    // Mark us as actively cosigning
    TributaryDb::start_cosigning(
      self.tributary_txn,
      self.set,
      latest_substrate_block_to_cosign,
      intent.block_number,
    );
    // Send the message for the processor to start signing
    TributaryDb::send_message(
      self.tributary_txn,
      self.set,
      messages::coordinator::CoordinatorMessage::CosignSubstrateBlock {
        session: self.set.session,
        intent,
      },
    );
  }
  fn handle_application_tx(&mut self, block_number: u64, tx: Transaction) {
    let signer = |signed: Signed| SeraiAddress(signed.signer().to_bytes());

    if let TransactionKind::Signed(_, TributarySigned { signer, .. }) = tx.kind() {
      // Don't handle transactions from those fatally slashed
      // TODO: The fact they can publish these TXs makes this a notable spam vector
      if TributaryDb::is_fatally_slashed(
        self.tributary_txn,
        self.set,
        SeraiAddress(signer.to_bytes()),
      ) {
        return;
      }
    }

    let topic = tx.topic();
    match tx {
      // Accumulate this vote and fatally slash the participant if past the threshold
      Transaction::RemoveParticipant { participant, signed } => {
        let signer = signer(signed);

        // Check the participant voted to be removed actually exists
        if !self.validators.iter().any(|validator| *validator == participant) {
          TributaryDb::fatal_slash(
            self.tributary_txn,
            self.set,
            signer,
            "voted to remove non-existent participant",
          );
          return;
        }

        match TributaryDb::accumulate(
          self.tributary_txn,
          self.set,
          self.validators,
          self.total_weight,
          block_number,
          topic.unwrap(),
          signer,
          self.validator_weights[&signer],
          &(),
        ) {
          DataSet::None => {}
          DataSet::Participating(_) => {
            TributaryDb::fatal_slash(self.tributary_txn, self.set, participant, "voted to remove");
          }
        };
      }

      // Send the participation to the processor
      Transaction::DkgParticipation { participation, signed } => {
        TributaryDb::send_message(
          self.tributary_txn,
          self.set,
          messages::key_gen::CoordinatorMessage::Participation {
            session: self.set.session,
            participant: todo!("TODO"),
            participation,
          },
        );
      }
      Transaction::DkgConfirmationPreprocess { attempt, preprocess, signed } => {
        // Accumulate the preprocesses into our own FROST attempt manager
        todo!("TODO")
      }
      Transaction::DkgConfirmationShare { attempt, share, signed } => {
        // Accumulate the shares into our own FROST attempt manager
        todo!("TODO: SetKeysTask")
      }

      Transaction::Cosign { substrate_block_hash } => {
        // Update the latest intended-to-be-cosigned Substrate block
        TributaryDb::set_latest_substrate_block_to_cosign(
          self.tributary_txn,
          self.set,
          substrate_block_hash,
        );
        // Start a new cosign if we aren't already working on one
        self.potentially_start_cosign();
      }
      Transaction::Cosigned { substrate_block_hash } => {
        /*
          We provide one Cosigned per Cosign transaction, but they have independent orders. This
          means we may receive Cosigned before Cosign. In order to ensure we only start work on
          not-yet-Cosigned cosigns, we flag all cosigned blocks as cosigned. Then, when we choose
          the next block to work on, we won't if it's already been cosigned.
        */
        TributaryDb::mark_cosigned(self.tributary_txn, self.set, substrate_block_hash);

        // If we aren't actively cosigning this block, return
        // This occurs when we have Cosign TXs A, B, C, we received Cosigned for A and start on C,
        // and then receive Cosigned for B
        if TributaryDb::actively_cosigning(self.tributary_txn, self.set) !=
          Some(substrate_block_hash)
        {
          return;
        }

        // Since this is the block we were cosigning, mark us as having finished cosigning
        TributaryDb::finish_cosigning(self.tributary_txn, self.set);

        // Start working on the next cosign
        self.potentially_start_cosign();
      }
      Transaction::SubstrateBlock { hash } => {
        // Recognize all of the IDs this Substrate block causes to be signed
        let plans = SubstrateBlockPlans::take(self.tributary_txn, self.set, hash).expect(
          "Transaction::SubstrateBlock locally provided but SubstrateBlockPlans wasn't populated",
        );
        for plan in plans {
          TributaryDb::recognize_topic(
            self.tributary_txn,
            self.set,
            Topic::Sign {
              id: VariantSignId::Transaction(plan),
              attempt: 0,
              round: SigningProtocolRound::Preprocess,
            },
          );
        }
      }
      Transaction::Batch { hash } => {
        // Recognize the signing of this batch
        TributaryDb::recognize_topic(
          self.tributary_txn,
          self.set,
          Topic::Sign {
            id: VariantSignId::Batch(hash),
            attempt: 0,
            round: SigningProtocolRound::Preprocess,
          },
        );
      }

      Transaction::SlashReport { slash_points, signed } => {
        let signer = signer(signed);

        if slash_points.len() != self.validators.len() {
          TributaryDb::fatal_slash(
            self.tributary_txn,
            self.set,
            signer,
            "slash report was for a distinct amount of signers",
          );
          return;
        }

        // Accumulate, and if past the threshold, calculate *the* slash report and start signing it
        match TributaryDb::accumulate(
          self.tributary_txn,
          self.set,
          self.validators,
          self.total_weight,
          block_number,
          topic.unwrap(),
          signer,
          self.validator_weights[&signer],
          &slash_points,
        ) {
          DataSet::None => {}
          DataSet::Participating(data_set) => {
            // Find the median reported slashes for this validator
            /*
              TODO: This lets 34% perform a fatal slash. That shouldn't be allowed. We need
              to accept slash reports for a period past the threshold, and only fatally slash if we
              have a supermajority agree the slash should be fatal. If there isn't a supermajority,
              but the median believe the slash should be fatal, we need to fallback to a large
              constant.

              Also, TODO, each slash point should probably be considered as
              `MAX_KEY_SHARES_PER_SET * BLOCK_TIME` seconds of downtime. As this time crosses
              various thresholds (1 day, 3 days, etc), a multiplier should be attached.
            */
            let mut median_slash_report = Vec::with_capacity(self.validators.len());
            for i in 0 .. self.validators.len() {
              let mut this_validator =
                data_set.values().map(|report| report[i]).collect::<Vec<_>>();
              this_validator.sort_unstable();
              // Choose the median, where if there are two median values, the lower one is chosen
              let median_index = if (this_validator.len() % 2) == 1 {
                this_validator.len() / 2
              } else {
                (this_validator.len() / 2) - 1
              };
              median_slash_report.push(this_validator[median_index]);
            }

            // We only publish slashes for the `f` worst performers to:
            // 1) Effect amnesty if there were network disruptions which affected everyone
            // 2) Ensure the signing threshold doesn't have a disincentive to do their job

            // Find the worst performer within the signing threshold's slash points
            let f = (self.validators.len() - 1) / 3;
            let worst_validator_in_supermajority_slash_points = {
              let mut sorted_slash_points = median_slash_report.clone();
              sorted_slash_points.sort_unstable();
              // This won't be a valid index if `f == 0`, which means we don't have any validators
              // to slash
              let index_of_first_validator_to_slash = self.validators.len() - f;
              let index_of_worst_validator_in_supermajority = index_of_first_validator_to_slash - 1;
              sorted_slash_points[index_of_worst_validator_in_supermajority]
            };

            // Perform the amortization
            for slash_points in &mut median_slash_report {
              *slash_points =
                slash_points.saturating_sub(worst_validator_in_supermajority_slash_points)
            }
            let amortized_slash_report = median_slash_report;

            // Create the resulting slash report
            let mut slash_report = vec![];
            for (_, points) in self.validators.iter().copied().zip(amortized_slash_report) {
              // TODO: Natively store this as a `Slash`
              if points == u32::MAX {
                slash_report.push(Slash::Fatal);
              } else {
                slash_report.push(Slash::Points(points));
              }
            }
            assert!(slash_report.len() <= f);

            // Recognize the topic for signing the slash report
            TributaryDb::recognize_topic(
              self.tributary_txn,
              self.set,
              Topic::Sign {
                id: VariantSignId::SlashReport,
                attempt: 0,
                round: SigningProtocolRound::Preprocess,
              },
            );
            // Send the message for the processor to start signing
            TributaryDb::send_message(
              self.tributary_txn,
              self.set,
              messages::coordinator::CoordinatorMessage::SignSlashReport {
                session: self.set.session,
                report: slash_report,
              },
            );
          }
        };
      }

      Transaction::Sign { id, attempt, round, data, signed } => {
        let topic = topic.unwrap();
        let signer = signer(signed);

        if u64::try_from(data.len()).unwrap() != self.validator_weights[&signer] {
          TributaryDb::fatal_slash(
            self.tributary_txn,
            self.set,
            signer,
            "signer signed with a distinct amount of key shares than they had key shares",
          );
          return;
        }

        match TributaryDb::accumulate(
          self.tributary_txn,
          self.set,
          self.validators,
          self.total_weight,
          block_number,
          topic,
          signer,
          self.validator_weights[&signer],
          &data,
        ) {
          DataSet::None => {}
          DataSet::Participating(data_set) => {
            let id = topic.sign_id(self.set).expect("Topic::Sign didn't have SignId");
            let flatten_data_set = |data_set| todo!("TODO");
            let data_set = flatten_data_set(data_set);
            TributaryDb::send_message(
              self.tributary_txn,
              self.set,
              match round {
                SigningProtocolRound::Preprocess => {
                  messages::sign::CoordinatorMessage::Preprocesses { id, preprocesses: data_set }
                }
                SigningProtocolRound::Share => {
                  messages::sign::CoordinatorMessage::Shares { id, shares: data_set }
                }
              },
            )
          }
        };
      }
    }
  }

  fn handle_block(mut self, block_number: u64, block: Block<Transaction>) {
    TributaryDb::start_of_block(self.tributary_txn, self.set, block_number);

    for tx in block.transactions {
      match tx {
        TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(ev)) => {
          // Since the evidence is on the chain, it will have already been validated
          // We can just punish the signer
          let data = match ev {
            Evidence::ConflictingMessages(first, second) => (first, Some(second)),
            Evidence::InvalidPrecommit(first) | Evidence::InvalidValidRound(first) => (first, None),
          };
          let msgs = (
            decode_signed_message::<TendermintNetwork<TD, Transaction, P>>(&data.0).unwrap(),
            if data.1.is_some() {
              Some(
                decode_signed_message::<TendermintNetwork<TD, Transaction, P>>(&data.1.unwrap())
                  .unwrap(),
              )
            } else {
              None
            },
          );

          // Since anything with evidence is fundamentally faulty behavior, not just temporal
          // errors, mark the node as fatally slashed
          TributaryDb::fatal_slash(
            self.tributary_txn,
            self.set,
            SeraiAddress(msgs.0.msg.sender),
            &format!("invalid tendermint messages: {msgs:?}"),
          );
        }
        TributaryTransaction::Application(tx) => {
          self.handle_application_tx(block_number, tx);
        }
      }
    }
  }
}

/// The task to scan the Tributary, populating `ProcessorMessages`.
pub struct ScanTributaryTask<TD: Db, P: P2p> {
  tributary_db: TD,
  set: ValidatorSet,
  validators: Vec<SeraiAddress>,
  total_weight: u64,
  validator_weights: HashMap<SeraiAddress, u64>,
  tributary: TributaryReader<TD, Transaction>,
  _p2p: PhantomData<P>,
}

impl<TD: Db, P: P2p> ScanTributaryTask<TD, P> {
  /// Create a new instance of this task.
  pub fn new(
    tributary_db: TD,
    new_set: &NewSetInformation,
    tributary: TributaryReader<TD, Transaction>,
  ) -> Self {
    let mut validators = Vec::with_capacity(new_set.validators.len());
    let mut total_weight = 0;
    let mut validator_weights = HashMap::with_capacity(new_set.validators.len());
    for (validator, weight) in new_set.validators.iter().copied() {
      let validator = SeraiAddress::from(validator);
      let weight = u64::from(weight);
      validators.push(validator);
      total_weight += weight;
      validator_weights.insert(validator, weight);
    }

    ScanTributaryTask {
      tributary_db,
      set: new_set.set,
      validators,
      total_weight,
      validator_weights,
      tributary,
      _p2p: PhantomData,
    }
  }
}

impl<TD: Db, P: P2p> ContinuallyRan for ScanTributaryTask<TD, P> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let (mut last_block_number, mut last_block_hash) =
        TributaryDb::last_handled_tributary_block(&self.tributary_db, self.set)
          .unwrap_or((0, self.tributary.genesis()));

      let mut made_progress = false;
      while let Some(next) = self.tributary.block_after(&last_block_hash) {
        let block = self.tributary.block(&next).unwrap();
        let block_number = last_block_number + 1;
        let block_hash = block.hash();

        // Make sure we have all of the provided transactions for this block
        for tx in &block.transactions {
          let TransactionKind::Provided(order) = tx.kind() else {
            continue;
          };

          // make sure we have all the provided txs in this block locally
          if !self.tributary.locally_provided_txs_in_block(&block_hash, order) {
            return Err(format!(
              "didn't have the provided Transactions on-chain for set (ephemeral error): {:?}",
              self.set
            ));
          }
        }

        let mut tributary_txn = self.tributary_db.txn();
        (ScanBlock {
          _td: PhantomData::<TD>,
          _p2p: PhantomData::<P>,
          tributary_txn: &mut tributary_txn,
          set: self.set,
          validators: &self.validators,
          total_weight: self.total_weight,
          validator_weights: &self.validator_weights,
        })
        .handle_block(block_number, block);
        TributaryDb::set_last_handled_tributary_block(
          &mut tributary_txn,
          self.set,
          block_number,
          block_hash,
        );
        last_block_number = block_number;
        last_block_hash = block_hash;
        tributary_txn.commit();

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}

/// Create the Transaction::SlashReport to publish per the local view.
pub fn slash_report_transaction(getter: &impl Get, set: &NewSetInformation) -> Transaction {
  let mut slash_points = Vec::with_capacity(set.validators.len());
  for (validator, _weight) in set.validators.iter().copied() {
    let validator = SeraiAddress::from(validator);
    slash_points.push(SlashPoints::get(getter, set.set, validator).unwrap_or(0));
  }
  Transaction::SlashReport { slash_points, signed: Signed::default() }
}
