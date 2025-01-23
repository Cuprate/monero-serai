#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::borrow::Borrow;
use std::{sync::Arc, collections::HashMap};

use alloy_core::primitives::{Address, U256};

use alloy_sol_types::{SolInterface, SolEvent};

use alloy_rpc_types_eth::{Log, Filter, TransactionTrait};
use alloy_transport::{TransportErrorKind, RpcError};
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use ethereum_primitives::LogIndex;

use futures_util::stream::{StreamExt, FuturesUnordered};

#[rustfmt::skip]
#[expect(warnings)]
#[expect(needless_pass_by_value)]
#[expect(missing_docs)]
#[expect(clippy::all)]
#[expect(clippy::ignored_unit_patterns)]
#[expect(clippy::redundant_closure_for_method_calls)]
mod abi {
  alloy_sol_macro::sol!("contracts/IERC20.sol");
}
use abi::IERC20::{IERC20Calls, transferCall, transferFromCall};
use abi::SeraiIERC20::SeraiIERC20Calls;
pub use abi::IERC20::Transfer;
pub use abi::SeraiIERC20::{
  transferWithInInstruction01BB244A8ACall as transferWithInInstructionCall,
  transferFromWithInInstruction00081948E0Call as transferFromWithInInstructionCall,
};

#[cfg(test)]
mod tests;

/// A top-level ERC20 transfer
///
/// This does not include `token`, `to` fields. Those are assumed contextual to the creation of
/// this.
#[derive(Clone, Debug)]
pub struct TopLevelTransfer {
  /// The ID of the event for this transfer.
  pub id: LogIndex,
  /// The hash of the transaction which caused this transfer.
  pub transaction_hash: [u8; 32],
  /// The address which made the transfer.
  pub from: Address,
  /// The amount transferred.
  pub amount: U256,
  /// The data appended after the call itself.
  pub data: Vec<u8>,
}

/// A view for an ERC20 contract.
#[derive(Clone, Debug)]
pub struct Erc20 {
  provider: Arc<RootProvider<SimpleRequest>>,
  address: Address,
}
impl Erc20 {
  /// Construct a new view of the specified ERC20 contract.
  pub fn new(provider: Arc<RootProvider<SimpleRequest>>, address: Address) -> Self {
    Self { provider, address }
  }

  /// The filter for transfer logs of the specified ERC20, to the specified recipient.
  pub fn transfer_filter(from_block: u64, to_block: u64, erc20: Address, to: Address) -> Filter {
    let filter = Filter::new().from_block(from_block).to_block(to_block);
    filter.address(erc20).event_signature(Transfer::SIGNATURE_HASH).topic2(to.into_word())
  }

  /// Yield the top-level transfer for the specified transaction (if one exists).
  ///
  /// The passed-in logs MUST be the logs for this transaction. The logs MUST be filtered to the
  /// `Transfer` events of the intended token(s) and the intended `to` transferred to. These
  /// properties are completely unchecked and assumed to be the case.
  ///
  /// This does NOT yield THE top-level transfer. If multiple `Transfer` events have identical
  /// structure to the top-level transfer call, the earliest `Transfer` event present in the logs
  /// is considered the top-level transfer.
  // Yielding THE top-level transfer would require tracing the transaction execution and isn't
  // worth the effort.
  pub async fn top_level_transfer(
    provider: impl AsRef<RootProvider<SimpleRequest>>,
    transaction_hash: [u8; 32],
    mut transfer_logs: Vec<impl Borrow<Log>>,
  ) -> Result<Option<TopLevelTransfer>, RpcError<TransportErrorKind>> {
    // Fetch the transaction
    let transaction =
      provider.as_ref().get_transaction_by_hash(transaction_hash.into()).await?.ok_or_else(
        || {
          TransportErrorKind::Custom(
            "node didn't have the transaction which emitted a log it had".to_string().into(),
          )
        },
      )?;

    // If this is a top-level call...
    // Don't validate the encoding as this can't be re-encoded to an identical bytestring due
    // to the `InInstruction` appended after the call itself
    let Ok(call) = IERC20Calls::abi_decode(transaction.inner.input(), false) else {
      return Ok(None);
    };

    // Extract the top-level call's from/to/value
    let (from, to, value) = match call {
      IERC20Calls::transfer(transferCall { to, value }) => (transaction.from, to, value),
      IERC20Calls::transferFrom(transferFromCall { from, to, value }) => (from, to, value),
      // Treat any other function selectors as unrecognized
      _ => return Ok(None),
    };

    // Sort the logs to ensure the the earliest logs are first
    transfer_logs.sort_by_key(|log| log.borrow().log_index);
    // Find the log for this top-level transfer
    for log in transfer_logs {
      // Check the log is for the called contract
      // This handles the edge case where we're checking if transfers of token X were top-level and
      // a transfer of token Y (with equivalent structure) was top-level
      if Some(log.borrow().address()) != transaction.inner.to() {
        continue;
      }

      // Since the caller is responsible for filtering these to `Transfer` events, we can assume
      // this is a non-compliant ERC20 or an error with the logs fetched. We assume ERC20
      // compliance here, making this an RPC error
      let log = log.borrow().log_decode::<Transfer>().map_err(|_| {
        TransportErrorKind::Custom("log didn't include a valid transfer event".to_string().into())
      })?;

      let block_hash = log.block_hash.ok_or_else(|| {
        TransportErrorKind::Custom("log didn't have its block hash set".to_string().into())
      })?;
      let log_index = log.log_index.ok_or_else(|| {
        TransportErrorKind::Custom("log didn't have its index set".to_string().into())
      })?;
      let log = log.inner.data;

      // Ensure the top-level transfer is equivalent to the transfer this log represents
      if !((log.from == from) && (log.to == to) && (log.value == value)) {
        continue;
      }

      // Read the data appended after
      let data = if let Ok(call) = SeraiIERC20Calls::abi_decode(transaction.inner.input(), true) {
        match call {
          SeraiIERC20Calls::transferWithInInstruction01BB244A8A(
            transferWithInInstructionCall { inInstruction, .. },
          ) |
          SeraiIERC20Calls::transferFromWithInInstruction00081948E0(
            transferFromWithInInstructionCall { inInstruction, .. },
          ) => Vec::from(inInstruction),
        }
      } else {
        // We don't error here so this transfer is propagated up the stack, even without the
        // InInstruction. In practice, Serai should acknowledge this and return it to the sender
        vec![]
      };

      return Ok(Some(TopLevelTransfer {
        id: LogIndex { block_hash: *block_hash, index_within_block: log_index },
        transaction_hash,
        from: log.from,
        amount: log.value,
        data,
      }));
    }

    Ok(None)
  }

  /// Fetch all top-level transfers to the specified address for this token.
  ///
  /// The result of this function is unordered.
  pub async fn top_level_transfers_unordered(
    &self,
    from_block: u64,
    to_block: u64,
    to: Address,
  ) -> Result<Vec<TopLevelTransfer>, RpcError<TransportErrorKind>> {
    // Get all transfers within these blocks
    let logs = self
      .provider
      .get_logs(&Self::transfer_filter(from_block, to_block, self.address, to))
      .await?;

    // The logs, indexed by their transactions
    let mut transaction_logs = HashMap::new();
    // Index the logs by their transactions
    for log in logs {
      // Double check the address which emitted this log
      if log.address() != self.address {
        Err(TransportErrorKind::Custom(
          "node returned logs for a different address than requested".to_string().into(),
        ))?;
      }
      // Double check the event signature for this log
      if log.topics().first() != Some(&Transfer::SIGNATURE_HASH) {
        Err(TransportErrorKind::Custom(
          "node returned a log for a different topic than filtered to".to_string().into(),
        ))?;
      }
      // Double check the `to` topic
      if log.topics().get(2) != Some(&to.into_word()) {
        Err(TransportErrorKind::Custom(
          "node returned a transfer for a different `to` than filtered to".to_string().into(),
        ))?;
      }

      let tx_id = log
        .transaction_hash
        .ok_or_else(|| {
          TransportErrorKind::Custom("log didn't specify its transaction hash".to_string().into())
        })?
        .0;

      transaction_logs.entry(tx_id).or_insert_with(|| Vec::with_capacity(1)).push(log);
    }

    // Use `FuturesUnordered` so these RPC calls run in parallel
    let mut futures = FuturesUnordered::new();
    for (tx_id, transfer_logs) in transaction_logs {
      futures.push(Self::top_level_transfer(&self.provider, tx_id, transfer_logs));
    }

    let mut top_level_transfers = vec![];
    while let Some(top_level_transfer) = futures.next().await {
      match top_level_transfer {
        // Top-level transfer
        Ok(Some(top_level_transfer)) => top_level_transfers.push(top_level_transfer),
        // Not a top-level transfer
        Ok(None) => continue,
        // Failed to get this transaction's information so abort
        Err(e) => Err(e)?,
      }
    }
    Ok(top_level_transfers)
  }
}
