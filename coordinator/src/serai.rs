use core::future::Future;
use std::sync::Arc;

use serai_db::{Get, DbTxn, Db as DbTrait, create_db};

use scale::Decode;
use serai_client::{primitives::NetworkId, validator_sets::primitives::Session, Serai};

use serai_task::ContinuallyRan;

create_db! {
  CoordinatorSerai {
    SlashReports: (network: NetworkId) -> (Session, Vec<u8>),
  }
}

/// Publish `SlashReport`s from `SlashReports` onto Serai.
pub struct PublishSlashReportTask<CD: DbTrait> {
  db: CD,
  serai: Arc<Serai>,
}
impl<CD: DbTrait> ContinuallyRan for PublishSlashReportTask<CD> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let mut made_progress = false;
      for network in serai_client::primitives::NETWORKS {
        if network == NetworkId::Serai {
          continue;
        };

        let mut txn = self.db.txn();
        let Some((session, slash_report)) = SlashReports::take(&mut txn, network) else {
          // No slash report to publish
          continue;
        };
        let slash_report = serai_client::Transaction::decode(&mut slash_report.as_slice()).unwrap();

        let serai =
          self.serai.as_of_latest_finalized_block().await.map_err(|e| format!("{e:?}"))?;
        let serai = serai.validator_sets();
        let session_after_slash_report = Session(session.0 + 1);
        let current_session = serai.session(network).await.map_err(|e| format!("{e:?}"))?;
        let current_session = current_session.map(|session| session.0);
        // Only attempt to publish the slash report for session #n while session #n+1 is still
        // active
        let session_after_slash_report_retired =
          current_session > Some(session_after_slash_report.0);
        if session_after_slash_report_retired {
          // Commit the txn to drain this SlashReport from the database and not try it again later
          txn.commit();
          continue;
        }

        if Some(session_after_slash_report.0) != current_session {
          // We already checked the current session wasn't greater, and they're not equal
          assert!(current_session < Some(session_after_slash_report.0));
          // This would mean the Serai node is resyncing and is behind where it prior was
          Err("have a SlashReport for a session Serai has yet to retire".to_string())?;
        }

        // If this session which should publish a slash report already has, move on
        let key_pending_slash_report =
          serai.key_pending_slash_report(network).await.map_err(|e| format!("{e:?}"))?;
        if key_pending_slash_report.is_none() {
          txn.commit();
          continue;
        };

        /*
        let tx = serai_client::SeraiValidatorSets::report_slashes(
          network,
          slash_report,
          signature.clone(),
        );
        */

        match self.serai.publish(&slash_report).await {
          Ok(()) => {
            txn.commit();
            made_progress = true;
          }
          // This could be specific to this TX (such as an already in mempool error) and it may be
          // worthwhile to continue iteration with the other pending slash reports. We assume this
          // error ephemeral and that the latency incurred for this ephemeral error to resolve is
          // miniscule compared to the window available to publish the slash report. That makes
          // this a non-issue.
          Err(e) => Err(format!("couldn't publish slash report transaction: {e:?}"))?,
        }
      }
      Ok(made_progress)
    }
  }
}
