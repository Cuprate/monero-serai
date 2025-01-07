use core::borrow::Borrow;
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use serai_client::{primitives::NetworkId, validator_sets::primitives::Session, Serai};

use libp2p::PeerId;

use futures_util::stream::{StreamExt, FuturesUnordered};
use tokio::sync::RwLock;

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
  async fn session_changes(
    serai: impl Borrow<Serai>,
    sessions: impl Borrow<HashMap<NetworkId, Session>>,
  ) -> Result<Vec<(NetworkId, Session, HashSet<PeerId>)>, String> {
    let temporal_serai =
      serai.borrow().as_of_latest_finalized_block().await.map_err(|e| format!("{e:?}"))?;
    let temporal_serai = temporal_serai.validator_sets();

    let mut session_changes = vec![];
    {
      // FuturesUnordered can be bad practice as it'll cause timeouts if infrequently polled, but
      // we poll it till it yields all futures with the most minimal processing possible
      let mut futures = FuturesUnordered::new();
      for network in serai_client::primitives::NETWORKS {
        if network == NetworkId::Serai {
          continue;
        }
        let sessions = sessions.borrow();
        futures.push(async move {
          let session = match temporal_serai.session(network).await {
            Ok(Some(session)) => session,
            Ok(None) => return Ok(None),
            Err(e) => return Err(format!("{e:?}")),
          };

          if sessions.get(&network) == Some(&session) {
            Ok(None)
          } else {
            match temporal_serai.active_network_validators(network).await {
              Ok(validators) => Ok(Some((
                network,
                session,
                validators.into_iter().map(peer_id_from_public).collect(),
              ))),
              Err(e) => Err(format!("{e:?}")),
            }
          }
        });
      }
      while let Some(session_change) = futures.next().await {
        if let Some(session_change) = session_change? {
          session_changes.push(session_change);
        }
      }
    }

    Ok(session_changes)
  }

  fn incorporate_session_changes(
    &mut self,
    session_changes: Vec<(NetworkId, Session, HashSet<PeerId>)>,
  ) -> HashSet<PeerId> {
    let mut removed = HashSet::new();

    for (network, session, validators) in session_changes {
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
      for validator in validators.iter().copied() {
        self.validators.entry(validator).or_insert_with(HashSet::new).insert(network);
      }
      self.by_network.insert(network, validators);

      // Update the session we have populated
      self.sessions.insert(network, session);
    }

    removed
  }

  /// Update the view of the validators.
  ///
  /// Returns all validators removed from the active validator set.
  pub(crate) async fn update(&mut self) -> Result<HashSet<PeerId>, String> {
    let session_changes = Self::session_changes(&self.serai, &self.sessions).await?;
    Ok(self.incorporate_session_changes(session_changes))
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

/// Update the view of the validators.
///
/// This minimizes the time an exclusive lock is held over the validators to minimize the
/// disruption to functioning.
///
/// Returns all validators removed from the active validator set.
pub(crate) async fn update_shared_validators(
  validators: &Arc<RwLock<Validators>>,
) -> Result<HashSet<PeerId>, String> {
  let session_changes = {
    let validators = validators.read().await;
    Validators::session_changes(validators.serai.clone(), validators.sessions.clone()).await?
  };
  Ok(validators.write().await.incorporate_session_changes(session_changes))
}
