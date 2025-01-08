use core::future::Future;

use tokio::time::error::Elapsed;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{primitives::NetworkId, validator_sets::primitives::ValidatorSet};

/// The libp2p-backed P2p network
mod libp2p;

/// The heartbeat task, effecting sync of Tributaries
mod heartbeat;

/// A tributary block and its commit.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct TributaryBlockWithCommit {
  pub(crate) block: Vec<u8>,
  pub(crate) commit: Vec<u8>,
}

trait Peer: Send {
  fn send_heartbeat(
    &self,
    set: ValidatorSet,
    latest_block_hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<TributaryBlockWithCommit>, Elapsed>>;
}

trait P2p: Send + Sync + tributary::P2p {
  type Peer: Peer;
  fn peers(&self, network: NetworkId) -> impl Send + Future<Output = Vec<Self::Peer>>;
}
