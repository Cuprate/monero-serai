use core::future::Future;
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use serai_client::primitives::{NetworkId, PublicKey};

use tokio::sync::RwLock;

use serai_task::ContinuallyRan;

use libp2p::{multihash::Multihash, identity::PeerId, swarm::NetworkBehaviour};

/// A struct to sync the validators from the Serai node in order to keep track of them.
mod validators;
use validators::{Validators, update_shared_validators};

/// The authentication protocol upgrade to limit the P2P network to active validators.
mod authenticate;

/// The dial task, to find new peers to connect to
mod dial;

/// The request-response messages and behavior
mod reqres;
use reqres::{Request, Response};

/// The gossip messages and behavior
mod gossip;

/// The heartbeat task, effecting sync of Tributaries
mod heartbeat;

/// The swarm task, running it and dispatching to/from it
mod swarm;

const PORT: u16 = 30563; // 5132 ^ (('c' << 8) | 'o')

fn peer_id_from_public(public: PublicKey) -> PeerId {
  // 0 represents the identity Multihash, that no hash was performed
  // It's an internal constant so we can't refer to the constant inside libp2p
  PeerId::from_multihash(Multihash::wrap(0, &public.0).unwrap()).unwrap()
}

struct Peer;
impl Peer {
  async fn send(&self, request: Request) -> Result<Response, tokio::time::error::Elapsed> {
    (async move { todo!("TODO") }).await
  }
}

#[derive(Clone)]
struct Peers {
  peers: Arc<RwLock<HashMap<NetworkId, HashSet<PeerId>>>>,
}

#[derive(Clone, Debug)]
struct P2p;
impl P2p {
  async fn peers(&self, set: NetworkId) -> Vec<Peer> {
    (async move { todo!("TODO") }).await
  }
}

#[async_trait::async_trait]
impl tributary::P2p for P2p {
  async fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) {
    todo!("TODO")
  }
}

#[derive(NetworkBehaviour)]
struct Behavior {
  reqres: reqres::Behavior,
  gossip: gossip::Behavior,
}

struct UpdateSharedValidatorsTask {
  validators: Arc<RwLock<Validators>>,
}

impl ContinuallyRan for UpdateSharedValidatorsTask {
  // Only run every minute, not the default of every five seconds
  const DELAY_BETWEEN_ITERATIONS: u64 = 60;
  const MAX_DELAY_BETWEEN_ITERATIONS: u64 = 5 * 60;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      update_shared_validators(&self.validators).await.map_err(|e| format!("{e:?}"))?;
      Ok(true)
    }
  }
}
