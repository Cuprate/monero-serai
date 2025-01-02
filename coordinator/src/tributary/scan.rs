use core::future::Future;
use std::collections::HashMap;

use ciphersuite::group::GroupEncoding;

use serai_client::{primitives::SeraiAddress, validator_sets::primitives::ValidatorSet};

use tributary::{
  Signed as TributarySigned, TransactionError, TransactionKind, TransactionTrait,
  Transaction as TributaryTransaction, Block, TributaryReader,
  tendermint::{
    tx::{TendermintTx, Evidence, decode_signed_message},
    TendermintNetwork,
  },
};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::tributary::{
  db::*,
  transaction::{Signed, Transaction},
};

struct ScanBlock<'a, D: DbTxn, TD: Db> {
  txn: &'a mut D,
  set: ValidatorSet,
  validators: &'a [SeraiAddress],
  total_weight: u64,
  validator_weights: &'a HashMap<SeraiAddress, u64>,
  tributary: &'a TributaryReader<TD, Transaction>,
}
impl<'a, D: DbTxn, TD: Db> ScanBlock<'a, D, TD> {
  fn handle_application_tx(&mut self, block_number: u64, tx: Transaction) {
    let signer = |signed: Signed| SeraiAddress(signed.signer.to_bytes());

    if let TransactionKind::Signed(_, TributarySigned { signer, .. }) = tx.kind() {
      // Don't handle transactions from those fatally slashed
      // TODO: The fact they can publish these TXs makes this a notable spam vector
      if TributaryDb::is_fatally_slashed(self.txn, self.set, SeraiAddress(signer.to_bytes())) {
        return;
      }
    }

    match tx {
      Transaction::RemoveParticipant { participant, signed } => {
        // Accumulate this vote and fatally slash the participant if past the threshold
        let signer = signer(signed);
        match TributaryDb::accumulate(
          self.txn,
          self.set,
          self.validators,
          self.total_weight,
          block_number,
          Topic::RemoveParticipant { participant },
          signer,
          self.validator_weights[&signer],
          &(),
        ) {
          DataSet::None => {}
          DataSet::Participating(_) => {
            TributaryDb::fatal_slash(self.txn, self.set, participant, "voted to remove")
          }
        }
      }

      Transaction::DkgParticipation { participation, signed } => {
        // Send the participation to the processor
        todo!("TODO")
      }
      Transaction::DkgConfirmationPreprocess { attempt, preprocess, signed } => {
        // Accumulate the preprocesses into our own FROST attempt manager
        todo!("TODO")
      }
      Transaction::DkgConfirmationShare { attempt, share, signed } => {
        // Accumulate the shares into our own FROST attempt manager
        todo!("TODO")
      }

      Transaction::Cosign { substrate_block_hash } => {
        // Update the latest intended-to-be-cosigned Substrate block
        todo!("TODO")
      }
      Transaction::Cosigned { substrate_block_hash } => {
        // Start cosigning the latest intended-to-be-cosigned block
        todo!("TODO")
      }
      Transaction::SubstrateBlock { hash } => {
        // Whitelist all of the IDs this Substrate block causes to be signed
        todo!("TODO")
      }
      Transaction::Batch { hash } => {
        // Whitelist the signing of this batch, publishing our own preprocess
        todo!("TODO")
      }

      Transaction::SlashReport { slash_points, signed } => {
        // Accumulate, and if past the threshold, calculate *the* slash report and start signing it
        todo!("TODO")
      }

      Transaction::Sign { id, attempt, label, data, signed } => todo!("TODO"),
    }
  }

  fn handle_block(mut self, block_number: u64, block: Block<Transaction>) {
    TributaryDb::start_of_block(self.txn, self.set, block_number);

    for tx in block.transactions {
      match tx {
        TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(ev)) => {
          // Since the evidence is on the chain, it will have already been validated
          // We can just punish the signer
          let data = match ev {
            Evidence::ConflictingMessages(first, second) => (first, Some(second)),
            Evidence::InvalidPrecommit(first) | Evidence::InvalidValidRound(first) => (first, None),
          };
          /* TODO
          let msgs = (
            decode_signed_message::<TendermintNetwork<D, Transaction, P>>(&data.0).unwrap(),
            if data.1.is_some() {
              Some(
                decode_signed_message::<TendermintNetwork<D, Transaction, P>>(&data.1.unwrap())
                  .unwrap(),
              )
            } else {
              None
            },
          );

          // Since anything with evidence is fundamentally faulty behavior, not just temporal
          // errors, mark the node as fatally slashed
          TributaryDb::fatal_slash(
            self.txn, msgs.0.msg.sender, &format!("invalid tendermint messages: {msgs:?}"));
          */
          todo!("TODO")
        }
        TributaryTransaction::Application(tx) => {
          self.handle_application_tx(block_number, tx);
        }
      }
    }
  }
}

struct ScanTributaryTask<D: Db, TD: Db> {
  db: D,
  set: ValidatorSet,
  validators: Vec<SeraiAddress>,
  total_weight: u64,
  validator_weights: HashMap<SeraiAddress, u64>,
  tributary: TributaryReader<TD, Transaction>,
}
impl<D: Db, TD: Db> ContinuallyRan for ScanTributaryTask<D, TD> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let (mut last_block_number, mut last_block_hash) =
        TributaryDb::last_handled_tributary_block(&self.db, self.set)
          .unwrap_or((0, self.tributary.genesis()));

      let mut made_progess = false;
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

        let mut txn = self.db.txn();
        (ScanBlock {
          txn: &mut txn,
          set: self.set,
          validators: &self.validators,
          total_weight: self.total_weight,
          validator_weights: &self.validator_weights,
          tributary: &self.tributary,
        })
        .handle_block(block_number, block);
        TributaryDb::set_last_handled_tributary_block(&mut txn, self.set, block_number, block_hash);
        last_block_number = block_number;
        last_block_hash = block_hash;
        txn.commit();

        made_progess = true;
      }

      Ok(made_progess)
    }
  }
}
