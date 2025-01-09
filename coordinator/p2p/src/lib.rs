#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::future::Future;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{primitives::NetworkId, validator_sets::primitives::ValidatorSet};

use tokio::sync::oneshot;

use serai_cosign::SignedCosign;

/// The heartbeat task, effecting sync of Tributaries
pub mod heartbeat;

/// A tributary block and its commit.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct TributaryBlockWithCommit {
  /// The serialized block.
  pub block: Vec<u8>,
  /// The serialized commit.
  pub commit: Vec<u8>,
}

/// A representation of a peer.
pub trait Peer<'a>: Send {
  /// Send a heartbeat to this peer.
  fn send_heartbeat(
    &self,
    set: ValidatorSet,
    latest_block_hash: [u8; 32],
  ) -> impl Send + Future<Output = Option<Vec<TributaryBlockWithCommit>>>;
}

/// The representation of the P2P network.
pub trait P2p: Send + Sync + Clone + tributary::P2p + serai_cosign::RequestNotableCosigns {
  /// The representation of a peer.
  type Peer<'a>: Peer<'a>;

  /// Fetch the peers for this network.
  fn peers(&self, network: NetworkId) -> impl Send + Future<Output = Vec<Self::Peer<'_>>>;

  /// A cancel-safe future for the next heartbeat received over the P2P network.
  ///
  /// Yields the validator set its for, the latest block hash observed, and a channel to return the
  /// descending blocks.
  fn heartbeat(
    &self,
  ) -> impl Send
       + Future<Output = (ValidatorSet, [u8; 32], oneshot::Sender<Vec<TributaryBlockWithCommit>>)>;

  /// A cancel-safe future for the next request for the notable cosigns of a gloabl session.
  ///
  /// Yields the global session the request is for and a channel to return the notable cosigns.
  fn notable_cosigns_request(
    &self,
  ) -> impl Send + Future<Output = ([u8; 32], oneshot::Sender<Vec<SignedCosign>>)>;

  /// A cancel-safe future for the next message regarding a Tributary.
  ///
  /// Yields the message's Tributary's genesis block hash and the message.
  fn tributary_message(&self) -> impl Send + Future<Output = ([u8; 32], Vec<u8>)>;

  /// A cancel-safe future for the next cosign received.
  fn cosign(&self) -> impl Send + Future<Output = SignedCosign>;
}
