use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
  time::{Duration, Instant},
};

use borsh::BorshDeserialize;

use serai_client::primitives::{NetworkId, PublicKey};

use tokio::sync::{mpsc, RwLock};

use serai_db::Db;
use serai_task::TaskHandle;

use serai_cosign::Cosigning;

use futures_util::StreamExt;
use libp2p::{
  multihash::Multihash,
  identity::PeerId,
  swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmEvent, Swarm},
};

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

struct SwarmTask<D: Db> {
  dial_task: TaskHandle,
  to_dial: mpsc::UnboundedReceiver<DialOpts>,
  last_dial_task_run: Instant,

  validators: Arc<RwLock<Validators>>,
  last_refreshed_validators: Instant,
  next_refresh_validators: Instant,

  peers: Peers,
  rebuild_peers_at: Instant,

  db: D,
  swarm: Swarm<Behavior>,
}

impl<D: Db> SwarmTask<D> {
  async fn run(mut self) {
    loop {
      let time_till_refresh_validators =
        self.next_refresh_validators.saturating_duration_since(Instant::now());
      let time_till_rebuild_peers = self.rebuild_peers_at.saturating_duration_since(Instant::now());

      tokio::select! {
        biased;

        // Refresh the instance of validators we use to track peers/share with authenticate
        // TODO: Move this to a task
        () = tokio::time::sleep(time_till_refresh_validators) => {
          const TIME_BETWEEN_REFRESH_VALIDATORS: Duration = Duration::from_secs(60);
          const MAX_TIME_BETWEEN_REFRESH_VALIDATORS: Duration = Duration::from_secs(5 * 60);

          let update = update_shared_validators(&self.validators).await;
          match update {
            Ok(removed) => {
              for removed in removed {
                let _: Result<_, _> = self.swarm.disconnect_peer_id(removed);
              }
              self.last_refreshed_validators = Instant::now();
              self.next_refresh_validators = Instant::now() + TIME_BETWEEN_REFRESH_VALIDATORS;
            }
            Err(e) => {
              log::warn!("couldn't refresh validators: {e:?}");
              // Increase the delay before the next refresh by using the time since the last
              // refresh. This will be 5 seconds, then 5 seconds, then 10 seconds, then 20...
              let time_since_last = self
                .next_refresh_validators
                .saturating_duration_since(self.last_refreshed_validators);
              // But limit the delay
              self.next_refresh_validators =
                Instant::now() + time_since_last.min(MAX_TIME_BETWEEN_REFRESH_VALIDATORS);
            },
          }
        }

        // Rebuild the peers every 10 minutes
        //
        // This handles edge cases such as when a validator changes the networks they're present
        // in, race conditions, or any other edge cases/quirks which would otherwise risk spiraling
        // out of control
        () = tokio::time::sleep(time_till_rebuild_peers) => {
          const TIME_BETWEEN_REBUILD_PEERS: Duration = Duration::from_secs(10 * 60);

          let validators_by_network = self.validators.read().await.by_network().clone();
          let connected = self.swarm.connected_peers().copied().collect::<HashSet<_>>();
          let mut peers = HashMap::new();
          for (network, validators) in validators_by_network {
            peers.insert(network, validators.intersection(&connected).copied().collect());
          }
          *self.peers.peers.write().await = peers;

          self.rebuild_peers_at = Instant::now() + TIME_BETWEEN_REBUILD_PEERS;
        }

        // Dial peers we're instructed to
        dial_opts = self.to_dial.recv() => {
          let dial_opts = dial_opts.expect("DialTask was closed?");
          let _: Result<_, _> = self.swarm.dial(dial_opts);
        }

        // Handle swarm events
        event = self.swarm.next() => {
          // `Swarm::next` will never return `Poll::Ready(None)`
          // https://docs.rs/
          //   libp2p/0.54.1/libp2p/struct.Swarm.html#impl-Stream-for-Swarm%3CTBehaviour%3E
          let event = event.unwrap();
          match event {
            SwarmEvent::Behaviour(BehaviorEvent::Reqres(event)) => match event {
              reqres::Event::Message { message, .. } => match message {
                reqres::Message::Request { request_id: _, request, channel } => {
                  match request {
                    // TODO: Send these
                    reqres::Request::KeepAlive => {},
                    reqres::Request::Heartbeat { set, latest_block_hash } => todo!("TODO"),
                    reqres::Request::NotableCosigns { global_session } => {
                      let cosigns = Cosigning::<D>::notable_cosigns(&self.db, global_session);
                      let res = reqres::Response::NotableCosigns(cosigns);
                      let _: Result<_, _> =
                        self.swarm.behaviour_mut().reqres.send_response(channel, res);
                    },
                  }
                }
                reqres::Message::Response { request_id, response } => todo!("TODO"),
              }
              reqres::Event::OutboundFailure { request_id, .. } => todo!("TODO"),
              reqres::Event::InboundFailure { .. } | reqres::Event::ResponseSent { .. } => {},
            },
            SwarmEvent::Behaviour(BehaviorEvent::Gossip(event)) => match event {
              gossip::Event::Message { message, .. } =>  {
                let Ok(message) = gossip::Message::deserialize(&mut message.data.as_slice()) else {
                  continue
                };
                match message {
                  gossip::Message::Tributary { set, message } => todo!("TODO"),
                  gossip::Message::Cosign(signed_cosign) => todo!("TODO"),
                }
              }
              gossip::Event::Subscribed { .. } | gossip::Event::Unsubscribed { .. } => {},
              gossip::Event::GossipsubNotSupported { peer_id } => {
                let _: Result<_, _> = self.swarm.disconnect_peer_id(peer_id);
              }
            },

            // New connection, so update peers
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
              let Some(networks) =
                self.validators.read().await.networks(&peer_id).cloned() else { continue };
              for network in networks {
                self
                  .peers
                  .peers
                  .write()
                  .await
                  .entry(network)
                  .or_insert_with(HashSet::new)
                  .insert(peer_id);
              }
            },

            // Connection closed, so update peers
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
              let Some(networks) =
                self.validators.read().await.networks(&peer_id).cloned() else { continue };
              for network in networks {
                self
                  .peers
                  .peers
                  .write()
                  .await
                  .entry(network)
                  .or_insert_with(HashSet::new)
                  .remove(&peer_id);
              }

              /*
                We want to re-run the dial task, since we lost a peer, in case we should find new
                peers. This opens a DoS where a validator repeatedly opens/closes connections to
                force iterations of the dial task. We prevent this by setting a minimum distance
                since the last explicit iteration.

                This is suboptimal. If we have several disconnects in immediate proximity, we'll
                trigger the dial task upon the first (where we may still have enough peers we
                shouldn't dial more) but not the last (where we may have so few peers left we
                should dial more). This is accepted as the dial task will eventually run on its
                natural timer.
              */
              const MINIMUM_TIME_SINCE_LAST_EXPLICIT_DIAL: Duration = Duration::from_secs(60);
              let now = Instant::now();
              if (self.last_dial_task_run + MINIMUM_TIME_SINCE_LAST_EXPLICIT_DIAL) < now {
                self.dial_task.run_now();
                self.last_dial_task_run = now;
              }
            },

            // We don't handle any of these
            SwarmEvent::IncomingConnection { .. } |
            SwarmEvent::IncomingConnectionError { .. } |
            SwarmEvent::OutgoingConnectionError { .. } |
            SwarmEvent::NewListenAddr { .. } |
            SwarmEvent::ExpiredListenAddr { .. } |
            SwarmEvent::ListenerClosed { .. } |
            SwarmEvent::ListenerError { .. } |
            SwarmEvent::Dialing { .. } => {}
          }
        }
      }
    }
  }
}
