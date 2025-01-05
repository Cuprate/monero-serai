use std::collections::HashMap;

use serai_client::{primitives::NetworkId, validator_sets::primitives::Session, Serai};

use libp2p::PeerId;

use crate::p2p::peer_id_from_public;

pub(crate) struct Validators {
  serai: Serai,

  // A cache for which session we're populated with the validators of
  sessions: HashMap<NetworkId, Session>,
  // The validators by network
  by_network: HashMap<NetworkId, Vec<PeerId>>,
  // The set of all validators (as a HashMap<PeerId, usize> to represent the amount of inclusions)
  set: HashMap<PeerId, usize>,
}

impl Validators {
  pub(crate) async fn update(&mut self) -> Result<(), String> {
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
          new_validators.into_iter().map(peer_id_from_public).collect::<Vec<_>>();

        // Remove the existing validators
        for validator in self.by_network.remove(&network).unwrap_or(vec![]) {
          let mut inclusions = self.set.remove(&validator).unwrap();
          inclusions -= 1;
          if inclusions != 0 {
            self.set.insert(validator, inclusions);
          }
        }

        // Add the new validators
        for validator in new_validators.iter().copied() {
          *self.set.entry(validator).or_insert(0) += 1;
        }
        self.by_network.insert(network, new_validators);

        // Update the session we have populated
        self.sessions.insert(network, session);
      }
    }
    Ok(())
  }

  pub(crate) fn validators(&self) -> &HashMap<NetworkId, Vec<PeerId>> {
    &self.by_network
  }

  pub(crate) fn contains(&self, peer_id: &PeerId) -> bool {
    self.set.contains_key(peer_id)
  }
}
