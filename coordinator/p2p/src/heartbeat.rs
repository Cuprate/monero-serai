use core::future::Future;
use std::time::{Duration, SystemTime};

use serai_client::validator_sets::primitives::{MAX_KEY_SHARES_PER_SET, ValidatorSet};

use futures_lite::FutureExt;

use tributary::{ReadWrite, TransactionTrait, Block, Tributary, TributaryReader};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::{Heartbeat, Peer, P2p};

// Amount of blocks in a minute
const BLOCKS_PER_MINUTE: usize = (60 / (tributary::tendermint::TARGET_BLOCK_TIME / 1000)) as usize;

/// The minimum amount of blocks to include/included within a batch, assuming there's blocks to
/// include in the batch.
///
/// This decides the size limit of the Batch (the Block size limit multiplied by the minimum amount
/// of blocks we'll send). The actual amount of blocks sent will be the amount which fits within
/// the size limit.
pub const MIN_BLOCKS_PER_BATCH: usize = BLOCKS_PER_MINUTE + 1;

/// The size limit for a batch of blocks sent in response to a Heartbeat.
///
/// This estimates the size of a commit as `32 + (MAX_VALIDATORS * 128)`. At the time of writing, a
/// commit is `8 + (validators * 32) + (32 + (validators * 32))` (for the time, list of validators,
/// and aggregate signature). Accordingly, this should be a safe over-estimate.
pub const BATCH_SIZE_LIMIT: usize = MIN_BLOCKS_PER_BATCH *
  (tributary::BLOCK_SIZE_LIMIT + 32 + ((MAX_KEY_SHARES_PER_SET as usize) * 128));

/// Sends a heartbeat to other validators on regular intervals informing them of our Tributary's
/// tip.
///
/// If the other validator has more blocks then we do, they're expected to inform us. This forms
/// the sync protocol for our Tributaries.
pub(crate) struct HeartbeatTask<TD: Db, Tx: TransactionTrait, P: P2p> {
  pub(crate) set: ValidatorSet,
  pub(crate) tributary: Tributary<TD, Tx, P>,
  pub(crate) reader: TributaryReader<TD, Tx>,
  pub(crate) p2p: P,
}

impl<TD: Db, Tx: TransactionTrait, P: P2p> ContinuallyRan for HeartbeatTask<TD, Tx, P> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      // If our blockchain hasn't had a block in the past minute, trigger the heartbeat protocol
      const TIME_TO_TRIGGER_SYNCING: Duration = Duration::from_secs(60);

      let mut tip = self.reader.tip();
      let time_since = {
        let block_time = if let Some(time_of_block) = self.reader.time_of_block(&tip) {
          SystemTime::UNIX_EPOCH + Duration::from_secs(time_of_block)
        } else {
          // If we couldn't fetch this block's time, assume it's old
          // We don't want to declare its unix time as 0 and claim it's 50+ years old though
          log::warn!(
            "heartbeat task couldn't fetch the time of a block, flagging it as a minute old"
          );
          SystemTime::now() - TIME_TO_TRIGGER_SYNCING
        };
        SystemTime::now().duration_since(block_time).unwrap_or(Duration::ZERO)
      };
      let mut tip_is_stale = false;

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
            if tip_is_stale {
              tip = self.reader.tip();
              tip_is_stale = false;
            }
            // Necessary due to https://github.com/rust-lang/rust/issues/100013
            let Some(blocks) = peer
              .send_heartbeat(Heartbeat { set: self.set, latest_block_hash: tip })
              .boxed()
              .await
            else {
              continue 'peer;
            };

            // This is the final batch if it has less than the maximum amount of blocks
            // (signifying there weren't more blocks after this to fill the batch with)
            let final_batch = blocks.len() < MIN_BLOCKS_PER_BATCH;

            // Sync each block
            for block_with_commit in blocks {
              let Ok(block) = Block::read(&mut block_with_commit.block.as_slice()) else {
                // TODO: Disconnect/slash this peer
                log::warn!("received invalid Block inside response to heartbeat");
                continue 'peer;
              };

              // Attempt to sync the block
              if !self.tributary.sync_block(block, block_with_commit.commit).await {
                // The block may be invalid or stale if we added a block elsewhere
                if (!tip_is_stale) && (tip != self.reader.tip()) {
                  // Since the Tributary's tip advanced on its own, return
                  return Ok(false);
                }

                // Since this block was invalid or stale in a way non-trivial to detect, try to
                // sync with the next peer
                continue 'peer;
              }

              // Because we synced a block, flag the tip as stale
              tip_is_stale = true;
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

        // This will cause the tak to be run less and less often, ensuring we aren't spamming the
        // net if we legitimately aren't making progress
        if !synced_block {
          Err(format!(
            "tried to sync blocks for {:?} since we haven't seen one in {} seconds but didn't",
            self.set,
            time_since.as_secs(),
          ))?;
        }
      }

      Ok(synced_block)
    }
  }
}
