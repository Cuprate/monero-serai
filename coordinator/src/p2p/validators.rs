use std::collections::{HashSet, HashMap};

use serai_client::{primitives::NetworkId, validator_sets::primitives::Session, Serai};

use libp2p::PeerId;

use crate::p2p::peer_id_from_public;

pub(crate) struct Validators {
  serai: Serai,

  // A cache for which session we're populated with the validators of
  sessions: HashMap<NetworkId, Session>,
  // The validators by network
  by_network: HashMap<NetworkId, HashSet<PeerId>>,
  // The validators and their networks
  validators: HashMap<PeerId, HashSet<NetworkId>>,
}

impl Validators {
  /// Update the view of the validators.
  ///
  /// Returns all validators removed from the active validator set.
  pub(crate) async fn update(&mut self) -> Result<HashSet<PeerId>, String> {
    let mut removed = HashSet::new();

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
        let new_validators =
          temporal_serai.active_network_validators(network).await.map_err(|e| format!("{e:?}"))?;
        let new_validators =
          new_validators.into_iter().map(peer_id_from_public).collect::<HashSet<_>>();

        // Remove the existing validators
        for validator in self.by_network.remove(&network).unwrap_or_else(HashSet::new) {
          let mut networks = self.validators.remove(&validator).unwrap();
          networks.remove(&network);
          if networks.is_empty() {
            removed.insert(validator);
          } else {
            self.validators.insert(validator, networks);
          }
        }

        // Add the new validators
        for validator in new_validators.iter().copied() {
          self.validators.entry(validator).or_insert_with(HashSet::new).insert(network);
        }
        self.by_network.insert(network, new_validators);

        // Update the session we have populated
        self.sessions.insert(network, session);
      }
    }

    Ok(removed)
  }

  pub(crate) fn by_network(&self) -> &HashMap<NetworkId, HashSet<PeerId>> {
    &self.by_network
  }

  pub(crate) fn contains(&self, peer_id: &PeerId) -> bool {
    self.validators.contains_key(peer_id)
  }

  pub(crate) fn networks(&self, peer_id: &PeerId) -> Option<&HashSet<NetworkId>> {
    self.validators.get(peer_id)
  }
}
