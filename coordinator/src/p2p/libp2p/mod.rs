use core::{future::Future, time::Duration};
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use zeroize::Zeroizing;
use schnorrkel::Keypair;

use serai_client::{
  primitives::{NetworkId, PublicKey},
  validator_sets::primitives::ValidatorSet,
  Serai,
};

use tokio::sync::{mpsc, oneshot, RwLock};

use serai_task::{Task, ContinuallyRan};

use libp2p::{
  multihash::Multihash,
  identity::{self, PeerId},
  tcp::Config as TcpConfig,
  yamux,
  swarm::NetworkBehaviour,
  SwarmBuilder,
};

use crate::p2p::TributaryBlockWithCommit;

/// A struct to sync the validators from the Serai node in order to keep track of them.
mod validators;
use validators::UpdateValidatorsTask;

/// The authentication protocol upgrade to limit the P2P network to active validators.
mod authenticate;
use authenticate::OnlyValidators;

/// The dial task, to find new peers to connect to
mod dial;
use dial::DialTask;

/// The request-response messages and behavior
mod reqres;
use reqres::{Request, Response};

/// The gossip messages and behavior
mod gossip;

/// The swarm task, running it and dispatching to/from it
mod swarm;
use swarm::SwarmTask;

const PORT: u16 = 30563; // 5132 ^ (('c' << 8) | 'o')

// usize::max, manually implemented, as max isn't a const fn
const MAX_LIBP2P_MESSAGE_SIZE: usize =
  if gossip::MAX_LIBP2P_GOSSIP_MESSAGE_SIZE > reqres::MAX_LIBP2P_REQRES_MESSAGE_SIZE {
    gossip::MAX_LIBP2P_GOSSIP_MESSAGE_SIZE
  } else {
    reqres::MAX_LIBP2P_REQRES_MESSAGE_SIZE
  };

fn peer_id_from_public(public: PublicKey) -> PeerId {
  // 0 represents the identity Multihash, that no hash was performed
  // It's an internal constant so we can't refer to the constant inside libp2p
  PeerId::from_multihash(Multihash::wrap(0, &public.0).unwrap()).unwrap()
}

struct Peer<'a> {
  outbound_requests: &'a mpsc::UnboundedSender<(PeerId, Request, oneshot::Sender<Response>)>,
  id: PeerId,
}
impl crate::p2p::Peer<'_> for Peer<'_> {
  fn send_heartbeat(
    &self,
    set: ValidatorSet,
    latest_block_hash: [u8; 32],
  ) -> impl Send + Future<Output = Option<Vec<TributaryBlockWithCommit>>> {
    const HEARBEAT_TIMEOUT: Duration = Duration::from_secs(5);
    async move {
      let request = Request::Heartbeat { set, latest_block_hash };
      let (sender, receiver) = oneshot::channel();
      self
        .outbound_requests
        .send((self.id, request, sender))
        .expect("outbound requests recv channel was dropped?");
      match tokio::time::timeout(HEARBEAT_TIMEOUT, receiver).await.ok()?.ok()? {
        Response::None => Some(vec![]),
        Response::Blocks(blocks) => Some(blocks),
        // TODO: Disconnect this peer
        Response::NotableCosigns(_) => None,
      }
    }
  }
}

#[derive(Clone)]
struct Peers {
  peers: Arc<RwLock<HashMap<NetworkId, HashSet<PeerId>>>>,
}

#[derive(NetworkBehaviour)]
struct Behavior {
  reqres: reqres::Behavior,
  gossip: gossip::Behavior,
}

#[derive(Clone)]
struct Libp2p {
  peers: Peers,
  outbound_requests: mpsc::UnboundedSender<(PeerId, Request, oneshot::Sender<Response>)>,
}

impl Libp2p {
  pub(crate) fn new(serai_key: &Zeroizing<Keypair>, serai: Serai) -> Libp2p {
    // Define the object we track peers with
    let peers = Peers { peers: Arc::new(RwLock::new(HashMap::new())) };

    // Define the dial task
    let (dial_task_def, dial_task) = Task::new();
    let (to_dial_send, to_dial_recv) = mpsc::unbounded_channel();
    tokio::spawn(
      DialTask::new(serai.clone(), peers.clone(), to_dial_send)
        .continually_run(dial_task_def, vec![]),
    );

    // Define the Validators object used for validating new connections
    let connection_validators = UpdateValidatorsTask::spawn(serai.clone());
    let new_only_validators = |noise_keypair: &identity::Keypair| -> Result<_, ()> {
      Ok(OnlyValidators {
        serai_key: serai_key.clone(),
        validators: connection_validators.clone(),
        noise_keypair: noise_keypair.clone(),
      })
    };

    let new_yamux = || {
      let mut config = yamux::Config::default();
      // 1 MiB default + max message size
      config.set_max_buffer_size((1024 * 1024) + MAX_LIBP2P_MESSAGE_SIZE);
      // 256 KiB default + max message size
      config.set_receive_window_size(((256 * 1024) + MAX_LIBP2P_MESSAGE_SIZE).try_into().unwrap());
      config
    };

    let behavior = Behavior { reqres: reqres::new_behavior(), gossip: gossip::new_behavior() };

    let mut swarm = SwarmBuilder::with_existing_identity(identity::Keypair::generate_ed25519())
      .with_tokio()
      .with_tcp(TcpConfig::default().nodelay(false), new_only_validators, new_yamux)
      .unwrap()
      .with_behaviour(|_| behavior)
      .unwrap()
      .build();
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{PORT}").parse().unwrap()).unwrap();
    swarm.listen_on(format!("/ip6/::/tcp/{PORT}").parse().unwrap()).unwrap();

    let swarm_validators = UpdateValidatorsTask::spawn(serai);

    let (gossip_send, gossip_recv) = mpsc::unbounded_channel();
    let (signed_cosigns_send, signed_cosigns_recv) = mpsc::unbounded_channel();
    let (tributary_gossip_send, tributary_gossip_recv) = mpsc::unbounded_channel();

    let (outbound_requests_send, outbound_requests_recv) = mpsc::unbounded_channel();

    let (heartbeat_requests_send, heartbeat_requests_recv) = mpsc::unbounded_channel();
    let (notable_cosign_requests_send, notable_cosign_requests_recv) = mpsc::unbounded_channel();
    let (inbound_request_responses_send, inbound_request_responses_recv) =
      mpsc::unbounded_channel();

    // Create the swarm task
    SwarmTask::spawn(
      dial_task,
      to_dial_recv,
      swarm_validators,
      peers,
      swarm,
      gossip_recv,
      signed_cosigns_send,
      tributary_gossip_send,
      outbound_requests_recv,
      heartbeat_requests_send,
      notable_cosign_requests_send,
      inbound_request_responses_recv,
    );

    // gossip_send, signed_cosigns_recv, tributary_gossip_recv, outbound_requests_send,
    // heartbeat_requests_recv, notable_cosign_requests_recv, inbound_request_responses_send
    todo!("TODO");
  }
}

impl tributary::P2p for Libp2p {
  fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) -> impl Send + Future<Output = ()> {
    async move { todo!("TODO") }
  }
}

impl crate::p2p::P2p for Libp2p {
  type Peer<'a> = Peer<'a>;
  fn peers(&self, network: NetworkId) -> impl Send + Future<Output = Vec<Self::Peer<'_>>> {
    async move {
      let Some(peer_ids) = self.peers.peers.read().await.get(&network).cloned() else {
        return vec![];
      };
      let mut res = vec![];
      for id in peer_ids {
        res.push(Peer { outbound_requests: &self.outbound_requests, id });
      }
      res
    }
  }
}
