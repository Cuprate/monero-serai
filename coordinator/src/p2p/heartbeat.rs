use core::future::Future;

use std::time::{Duration, SystemTime};

use serai_client::validator_sets::primitives::ValidatorSet;

use tributary::{ReadWrite, Block, Tributary, TributaryReader};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::{
  tributary::Transaction,
  p2p::{
    reqres::{Request, Response},
    P2p,
  },
};

// Amount of blocks in a minute
const BLOCKS_PER_MINUTE: usize = (60 / (tributary::tendermint::TARGET_BLOCK_TIME / 1000)) as usize;

// Maximum amount of blocks to send in a batch of blocks
pub const BLOCKS_PER_BATCH: usize = BLOCKS_PER_MINUTE + 1;

/// Sends a heartbeat to other validators on regular intervals informing them of our Tributary's
/// tip.
///
/// If the other validator has more blocks then we do, they're expected to inform us. This forms
/// the sync protocol for our Tributaries.
struct HeartbeatTask<TD: Db> {
  set: ValidatorSet,
  tributary: Tributary<TD, Transaction, P2p>,
  reader: TributaryReader<TD, Transaction>,
  p2p: P2p,
}

impl<TD: Db> ContinuallyRan for HeartbeatTask<TD> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      // If our blockchain hasn't had a block in the past minute, trigger the heartbeat protocol
      const TIME_TO_TRIGGER_SYNCING: Duration = Duration::from_secs(60);

      // Fetch the state from the tip of the blockchain
      let state = |reader: &TributaryReader<_, _>| {
        let tip = reader.tip();
        let block_time = if let Some(time_of_block) = reader.time_of_block(&tip) {
          SystemTime::UNIX_EPOCH + Duration::from_secs(time_of_block)
        } else {
          // If we couldn't fetch this block's time, assume it's old
          // We don't want to declare its unix time as 0 and claim it's 50+ years old though
          SystemTime::now() - TIME_TO_TRIGGER_SYNCING
        };
        (tip, SystemTime::now().duration_since(block_time).unwrap_or(Duration::ZERO))
      };

      // The current state, and a boolean of it's stale
      let (mut tip, mut time_since) = state(&self.reader);
      let mut state_is_stale = false;

      let mut synced_block = false;
      if TIME_TO_TRIGGER_SYNCING <= time_since {
        log::warn!(
          "last known tributary block for {:?} was {} seconds ago",
          self.set,
          time_since.as_secs()
        );

        // This requests all peers for this network, without differentiating by session
        // This should be fine as most validators should overlap across sessions
        'peer: for peer in self.p2p.peers(self.set.network).await {
          loop {
            // Create the request for blocks
            if state_is_stale {
              (tip, time_since) = state(&self.reader);
              state_is_stale = false;
            }
            let request = Request::Heartbeat { set: self.set, latest_block_hash: tip };
            let Ok(Response::Blocks(blocks)) = peer.send(request).await else { continue 'peer };

            // This is the final batch if it has less than the maximum amount of blocks
            // (signifying there weren't more blocks after this to fill the batch with)
            let final_batch = blocks.len() < BLOCKS_PER_BATCH;

            // Sync each block
            for block_with_commit in blocks {
              let Ok(block) = Block::read(&mut block_with_commit.block.as_slice()) else {
                // TODO: Disconnect/slash this peer
                log::warn!("received invalid Block inside response to heartbeat");
                continue 'peer;
              };

              // Attempt to sync the block
              if !self.tributary.sync_block(block, block_with_commit.commit).await {
                // The block may be invalid or may simply be stale
                continue 'peer;
              }

              // Because we synced a block, flag the state as stale
              state_is_stale = true;
              // And that we did sync a block
              synced_block = true;
            }

            // If this was the final batch, move on from this peer
            // We could assume they were honest and we are done syncing the chain, but this is a
            // bit more robust
            if final_batch {
              continue 'peer;
            }
          }
        }
      }

      Ok(synced_block)
    }
  }
}
