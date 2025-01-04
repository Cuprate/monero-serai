use core::future::Future;
use std::collections::HashMap;

use rand_core::{RngCore, OsRng};

use tokio::sync::mpsc;

use serai_client::{
  primitives::{NetworkId, PublicKey},
  validator_sets::primitives::Session,
  Serai,
};

use libp2p::{
  core::multiaddr::{Protocol, Multiaddr},
  swarm::dial_opts::DialOpts,
};

use serai_task::ContinuallyRan;

use crate::p2p::{PORT, Peers};

const TARGET_PEERS_PER_NETWORK: usize = 5;

struct DialTask {
  serai: Serai,

  sessions: HashMap<NetworkId, Session>,
  validators: HashMap<NetworkId, Vec<PublicKey>>,

  peers: Peers,
  to_dial: mpsc::UnboundedSender<DialOpts>,
}

impl ContinuallyRan for DialTask {
  const DELAY_BETWEEN_ITERATIONS: u64 = 30;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let temporal_serai =
        self.serai.as_of_latest_finalized_block().await.map_err(|e| format!("{e:?}"))?;
      let temporal_serai = temporal_serai.validator_sets();
      for network in serai_client::primitives::NETWORKS {
        if network == NetworkId::Serai {
          continue;
        }
        let Some(session) = temporal_serai.session(network).await.map_err(|e| format!("{e:?}"))?
        else {
          continue;
        };
        // If the session has changed, populate it with the current validators
        if self.sessions.get(&network) != Some(&session) {
          self.validators.insert(
            network,
            temporal_serai
              .active_network_validators(network)
              .await
              .map_err(|e| format!("{e:?}"))?,
          );
          self.sessions.insert(network, session);
        }
      }

      // If any of our peers is lacking, try to connect to more
      let mut dialed = false;
      let peer_counts = self
        .peers
        .peers
        .read()
        .unwrap()
        .iter()
        .map(|(network, peers)| (*network, peers.len()))
        .collect::<Vec<_>>();
      for (network, peer_count) in peer_counts {
        /*
          If we don't have the target amount of peers, and we don't have all the validators in the
          set but one, attempt to connect to more validators within this set.

          The latter clause is so if there's a set with only 3 validators, we don't infinitely try
          to connect to the target amount of peers for this network as we never will. Instead, we
          only try to connect to most of the validators actually present.
        */
        if (peer_count < TARGET_PEERS_PER_NETWORK) &&
          (peer_count < self.validators[&network].len().saturating_sub(1))
        {
          let mut potential_peers =
            self.serai.p2p_validators(network).await.map_err(|e| format!("{e:?}"))?;
          for _ in 0 .. (TARGET_PEERS_PER_NETWORK - peer_count) {
            if potential_peers.is_empty() {
              break;
            }
            let index_to_dial =
              usize::try_from(OsRng.next_u64() % u64::try_from(potential_peers.len()).unwrap())
                .unwrap();
            let randomly_selected_peer = potential_peers.swap_remove(index_to_dial);

            log::info!("found peer from substrate: {randomly_selected_peer}");

            // Map the peer from a Substrate P2P network peer to a Coordinator P2P network peer
            let mapped_peer = randomly_selected_peer
              .into_iter()
              .filter_map(|protocol| match protocol {
                // Drop PeerIds from the Substrate P2p network
                Protocol::P2p(_) => None,
                // Use our own TCP port
                Protocol::Tcp(_) => Some(Protocol::Tcp(PORT)),
                // Pass-through any other specifications (IPv4, IPv6, etc)
                other => Some(other),
              })
              .collect::<Multiaddr>();

            log::debug!("mapped found peer: {mapped_peer}");

            self
              .to_dial
              .send(DialOpts::unknown_peer_id().address(mapped_peer).build())
              .expect("dial receiver closed?");
            dialed = true;
          }
        }
      }

      Ok(dialed)
    }
  }
}
