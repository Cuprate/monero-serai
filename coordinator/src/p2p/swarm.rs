use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
  time::{Duration, Instant},
};

use borsh::BorshDeserialize;

use serai_client::validator_sets::primitives::ValidatorSet;

use tokio::sync::{mpsc, oneshot, RwLock};

use serai_task::TaskHandle;

use serai_cosign::SignedCosign;

use futures_util::StreamExt;
use libp2p::{
  identity::PeerId,
  request_response::{RequestId, ResponseChannel},
  swarm::{dial_opts::DialOpts, SwarmEvent, Swarm},
};

use crate::p2p::{
  Peers, BehaviorEvent, Behavior,
  validators::Validators,
  reqres::{self, Request, Response},
  gossip,
};

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(80);
const TIME_BETWEEN_REBUILD_PEERS: Duration = Duration::from_secs(10 * 60);

/*
  `SwarmTask` handles everything we need the `Swarm` object for. The goal is to minimize the
  contention on this task. Unfortunately, the `Swarm` object itself is needed for a variety of
  purposes making this a rather large task.

  Responsibilities include:
  - Actually dialing new peers (the selection process occurs in another task)
  - Maintaining the peers structure (as we need the Swarm object to see who our peers are)
  - Gossiping messages
  - Dispatching gossiped messages
  - Sending requests
  - Dispatching responses to requests
  - Dispatching received requests
  - Sending responses
*/
pub(crate) struct SwarmTask {
  dial_task: TaskHandle,
  to_dial: mpsc::UnboundedReceiver<DialOpts>,
  last_dial_task_run: Instant,

  validators: Arc<RwLock<Validators>>,
  peers: Peers,
  rebuild_peers_at: Instant,

  swarm: Swarm<Behavior>,

  last_message: Instant,

  gossip: mpsc::UnboundedReceiver<gossip::Message>,
  signed_cosigns: mpsc::UnboundedSender<SignedCosign>,
  tributary_gossip: mpsc::UnboundedSender<(ValidatorSet, Vec<u8>)>,

  outbound_requests: mpsc::UnboundedReceiver<(PeerId, Request, oneshot::Sender<Option<Response>>)>,
  outbound_request_responses: HashMap<RequestId, oneshot::Sender<Option<Response>>>,

  inbound_request_response_channels: HashMap<RequestId, ResponseChannel<Response>>,
  heartbeat_requests: mpsc::UnboundedSender<(RequestId, ValidatorSet, [u8; 32])>,
  /* TODO
    let cosigns = Cosigning::<D>::notable_cosigns(&self.db, global_session);
    let res = reqres::Response::NotableCosigns(cosigns);
    let _: Result<_, _> = self.swarm.behaviour_mut().reqres.send_response(channel, res);
  */
  notable_cosign_requests: mpsc::UnboundedSender<(RequestId, [u8; 32])>,
  inbound_request_responses: mpsc::UnboundedReceiver<(RequestId, Response)>,
}

impl SwarmTask {
  fn handle_gossip(&mut self, event: gossip::Event) {
    match event {
      gossip::Event::Message { message, .. } => {
        let Ok(message) = gossip::Message::deserialize(&mut message.data.as_slice()) else {
          // TODO: Penalize the PeerId which sent this message
          return;
        };
        match message {
          gossip::Message::Tributary { set, message } => {
            let _: Result<_, _> = self.tributary_gossip.send((set, message));
          }
          gossip::Message::Cosign(signed_cosign) => {
            let _: Result<_, _> = self.signed_cosigns.send(signed_cosign);
          }
        }
      }
      gossip::Event::Subscribed { .. } | gossip::Event::Unsubscribed { .. } => {}
      gossip::Event::GossipsubNotSupported { peer_id } => {
        let _: Result<_, _> = self.swarm.disconnect_peer_id(peer_id);
      }
    }
  }

  fn handle_reqres(&mut self, event: reqres::Event) {
    match event {
      reqres::Event::Message { message, .. } => match message {
        reqres::Message::Request { request_id, request, channel } => match request {
          reqres::Request::KeepAlive => {
            let _: Result<_, _> =
              self.swarm.behaviour_mut().reqres.send_response(channel, Response::None);
          }
          reqres::Request::Heartbeat { set, latest_block_hash } => {
            self.inbound_request_response_channels.insert(request_id, channel);
            let _: Result<_, _> =
              self.heartbeat_requests.send((request_id, set, latest_block_hash));
          }
          reqres::Request::NotableCosigns { global_session } => {
            self.inbound_request_response_channels.insert(request_id, channel);
            let _: Result<_, _> = self.notable_cosign_requests.send((request_id, global_session));
          }
        },
        reqres::Message::Response { request_id, response } => {
          // Send Some(response) as the response for the request
          if let Some(channel) = self.outbound_request_responses.remove(&request_id) {
            let _: Result<_, _> = channel.send(Some(response));
          }
        }
      },
      reqres::Event::OutboundFailure { request_id, .. } => {
        // Send None as the response for the request
        if let Some(channel) = self.outbound_request_responses.remove(&request_id) {
          let _: Result<_, _> = channel.send(None);
        }
      }
      reqres::Event::InboundFailure { .. } | reqres::Event::ResponseSent { .. } => {}
    }
  }

  async fn run(mut self) {
    loop {
      let time_till_keep_alive = Instant::now().saturating_duration_since(self.last_message);
      let time_till_rebuild_peers = self.rebuild_peers_at.saturating_duration_since(Instant::now());

      tokio::select! {
        () = tokio::time::sleep(time_till_keep_alive) => {
          let peers = self.swarm.connected_peers().copied().collect::<Vec<_>>();
          let behavior = self.swarm.behaviour_mut();
          for peer in peers {
            behavior.reqres.send_request(&peer, Request::KeepAlive);
          }
          self.last_message = Instant::now();
        }

        // Dial peers we're instructed to
        dial_opts = self.to_dial.recv() => {
          let dial_opts = dial_opts.expect("DialTask was closed?");
          let _: Result<_, _> = self.swarm.dial(dial_opts);
        }

        /*
          Rebuild the peers every 10 minutes.

          This protects against any race conditions/edge cases we have in our logic to track peers,
          along with unrepresented behavior such as when a peer changes the networks they're active
          in. This lets the peer tracking logic simply be 'good enough' to not become horribly
          corrupt over the span of `TIME_BETWEEN_REBUILD_PEERS`.

          We also use this to disconnect all peers who are no longer active in any network.
        */
        () = tokio::time::sleep(time_till_rebuild_peers) => {
          let validators_by_network = self.validators.read().await.by_network().clone();
          let connected_peers = self.swarm.connected_peers().copied().collect::<HashSet<_>>();

          // We initially populate the list of peers to disconnect with all peers
          let mut to_disconnect = connected_peers.clone();

          // Build the new peers object
          let mut peers = HashMap::new();
          for (network, validators) in validators_by_network {
            peers.insert(network, validators.intersection(&connected_peers).copied().collect());

            // If this peer is in this validator set, don't keep it flagged for disconnection
            to_disconnect.retain(|peer| !validators.contains(peer));
          }

          // Write the new peers object
          *self.peers.peers.write().await = peers;
          self.rebuild_peers_at = Instant::now() + TIME_BETWEEN_REBUILD_PEERS;

          // Disconnect all peers marked for disconnection
          for peer in to_disconnect {
            let _: Result<_, _> = self.swarm.disconnect_peer_id(peer);
          }
        }

        // Handle swarm events
        event = self.swarm.next() => {
          // `Swarm::next` will never return `Poll::Ready(None)`
          // https://docs.rs/
          //   libp2p/0.54.1/libp2p/struct.Swarm.html#impl-Stream-for-Swarm%3CTBehaviour%3E
          let event = event.unwrap();
          match event {
            // New connection, so update peers
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
              let Some(networks) =
                self.validators.read().await.networks(&peer_id).cloned() else { continue };
              let mut peers = self.peers.peers.write().await;
              for network in networks {
                peers.entry(network).or_insert_with(HashSet::new).insert(peer_id);
              }
            }

            // Connection closed, so update peers
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
              let Some(networks) =
                self.validators.read().await.networks(&peer_id).cloned() else { continue };
              let mut peers = self.peers.peers.write().await;
              for network in networks {
                peers.entry(network).or_insert_with(HashSet::new).remove(&peer_id);
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
            }

            SwarmEvent::Behaviour(BehaviorEvent::Reqres(event)) => {
              self.handle_reqres(event)
            }
            SwarmEvent::Behaviour(BehaviorEvent::Gossip(event)) => {
              self.handle_gossip(event)
            }

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

        message = self.gossip.recv() => {
          let message = message.expect("channel for messages to gossip was closed?");
          let topic = message.topic();
          let message = borsh::to_vec(&message).unwrap();
          let _: Result<_, _> = self.swarm.behaviour_mut().gossip.publish(topic, message);
          self.last_message = Instant::now();
        }

        request = self.outbound_requests.recv() => {
          let (peer, request, response_channel) =
            request.expect("channel for requests was closed?");
          let request_id = self.swarm.behaviour_mut().reqres.send_request(&peer, request);
          self.outbound_request_responses.insert(request_id, response_channel);
        }

        response = self.inbound_request_responses.recv() => {
          let (request_id, response) =
            response.expect("channel for inbound request responses was closed?");
          if let Some(channel) = self.inbound_request_response_channels.remove(&request_id) {
            let _: Result<_, _> =
              self.swarm.behaviour_mut().reqres.send_response(channel, response);
          }
        }
      }
    }
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    dial_task: TaskHandle,
    to_dial: mpsc::UnboundedReceiver<DialOpts>,

    validators: Arc<RwLock<Validators>>,
    peers: Peers,

    swarm: Swarm<Behavior>,

    gossip: mpsc::UnboundedReceiver<gossip::Message>,
    signed_cosigns: mpsc::UnboundedSender<SignedCosign>,
    tributary_gossip: mpsc::UnboundedSender<(ValidatorSet, Vec<u8>)>,

    outbound_requests: mpsc::UnboundedReceiver<(
      PeerId,
      Request,
      oneshot::Sender<Option<Response>>,
    )>,

    heartbeat_requests: mpsc::UnboundedSender<(RequestId, ValidatorSet, [u8; 32])>,
    notable_cosign_requests: mpsc::UnboundedSender<(RequestId, [u8; 32])>,
    inbound_request_responses: mpsc::UnboundedReceiver<(RequestId, Response)>,
  ) {
    tokio::spawn(
      SwarmTask {
        dial_task,
        to_dial,
        last_dial_task_run: Instant::now(),

        validators,
        peers,
        rebuild_peers_at: Instant::now() + TIME_BETWEEN_REBUILD_PEERS,

        swarm,

        last_message: Instant::now(),

        gossip,
        signed_cosigns,
        tributary_gossip,

        outbound_requests,
        outbound_request_responses: HashMap::new(),

        inbound_request_response_channels: HashMap::new(),
        heartbeat_requests,
        notable_cosign_requests,
        inbound_request_responses,
      }
      .run(),
    );
  }
}
