use metrics::Histogram;
use reth_metrics::Metrics;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct DurationsRecorder {
    //某个操作或时间段的开始时间。Instant类型通常用于记录时间间隔。
    start: Instant,
    //与数据库提供者相关的度量指标
    current_metrics: DatabaseProviderMetrics,
    //一系列的操作和它们各自的持续时间
    pub(crate) actions: Vec<(Action, Duration)>,
    //最新的持续时间
    latest: Option<Duration>,
}

impl Default for DurationsRecorder {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            actions: Vec::new(),
            latest: None,
            current_metrics: DatabaseProviderMetrics::default(),
        }
    }
}

impl DurationsRecorder {
    /// Saves the provided duration for future logging and instantly reports as a metric with
    /// `action` label.
    pub(crate) fn record_duration(&mut self, action: Action, duration: Duration) {
        //将action和duration作为一个元组添加到actions向量中，用于记录操作和持续时间。
        self.actions.push((action, duration));
        //更新度量指标
        self.current_metrics.record_duration(action, duration);
        //更新latest字段为从start时间点到现在的持续时间。
        self.latest = Some(self.start.elapsed());
    }

    /// Records the duration since last record, saves it for future logging and instantly reports as
    /// a metric with `action` label.
    /// 计算从上次记录以来经过的时间
    pub(crate) fn record_relative(&mut self, action: Action) {
        //计算从start时间点到现在的总持续时间
        let elapsed = self.start.elapsed();
        //计算自上次记录以来经过的时间。如果latest是Some，则从elapsed中减去latest值，
        //否则使用unwrap_or_default()，这意味着如果latest是None，则使用默认的Duration值
        let duration = elapsed - self.latest.unwrap_or_default();

        //将计算出的相对持续时间和action作为元组添加到actions向量中
        self.actions.push((action, duration));
        //更新度量指标
        self.current_metrics.record_duration(action, duration);
        //更新latest字段为当前的总持续时间
        self.latest = Some(elapsed);
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum Action {
    InsertStorageHashing,
    InsertAccountHashing,
    InsertMerkleTree,
    InsertBlock,
    InsertState,
    InsertHashes,
    InsertHistoryIndices,
    UpdatePipelineStages,
    InsertCanonicalHeaders,
    InsertHeaders,
    InsertHeaderNumbers,
    InsertHeaderTerminalDifficulties,
    InsertBlockOmmers,
    InsertTransactionSenders,
    InsertTransactions,
    InsertTransactionHashNumbers,
    InsertBlockWithdrawals,
    InsertBlockRequests,
    InsertBlockBodyIndices,
    InsertTransactionBlocks,
    GetNextTxNum,
    GetParentTD,
    //lytest
    InsertBlockVerify,
    InsertBlockRewards,
}

/// Database provider metrics
/// 记录不同数据库操作的持续时间分布
#[derive(Metrics)]
#[metrics(scope = "storage.providers.database")]
struct DatabaseProviderMetrics {
    /// Duration of insert storage hashing
    insert_storage_hashing: Histogram,
    /// Duration of insert account hashing
    insert_account_hashing: Histogram,
    /// Duration of insert merkle tree
    insert_merkle_tree: Histogram,
    /// Duration of insert block
    insert_block: Histogram,
    /// Duration of insert state
    insert_state: Histogram,
    /// Duration of insert hashes
    insert_hashes: Histogram,
    /// Duration of insert history indices
    insert_history_indices: Histogram,
    /// Duration of update pipeline stages
    update_pipeline_stages: Histogram,
    /// Duration of insert canonical headers
    insert_canonical_headers: Histogram,
    /// Duration of insert headers
    insert_headers: Histogram,
    /// Duration of insert header numbers
    insert_header_numbers: Histogram,
    /// Duration of insert header TD
    insert_header_td: Histogram,
    /// Duration of insert block ommers
    insert_block_ommers: Histogram,
    /// Duration of insert tx senders
    insert_tx_senders: Histogram,
    /// Duration of insert transactions
    insert_transactions: Histogram,
    /// Duration of insert transaction hash numbers
    insert_tx_hash_numbers: Histogram,
    /// Duration of insert block withdrawals
    insert_block_withdrawals: Histogram,
    /// Duration of insert block requests
    insert_block_requests: Histogram,
    /// Duration of insert block body indices
    insert_block_body_indices: Histogram,
    /// Duration of insert transaction blocks
    insert_tx_blocks: Histogram,
    /// Duration of get next tx num
    get_next_tx_num: Histogram,
    /// Duration of get parent TD
    get_parent_td: Histogram,
    /// lytest
    insert_block_verify:Histogram,
    /// lytest
    insert_block_rewards:Histogram,
}

impl DatabaseProviderMetrics {
    /// Records the duration for the given action.
    pub(crate) fn record_duration(&self, action: Action, duration: Duration) {
        match action {
            Action::InsertStorageHashing => self.insert_storage_hashing.record(duration),
            Action::InsertAccountHashing => self.insert_account_hashing.record(duration),
            Action::InsertMerkleTree => self.insert_merkle_tree.record(duration),
            Action::InsertBlock => self.insert_block.record(duration),
            Action::InsertState => self.insert_state.record(duration),
            Action::InsertHashes => self.insert_hashes.record(duration),
            Action::InsertHistoryIndices => self.insert_history_indices.record(duration),
            Action::UpdatePipelineStages => self.update_pipeline_stages.record(duration),
            Action::InsertCanonicalHeaders => self.insert_canonical_headers.record(duration),
            Action::InsertHeaders => self.insert_headers.record(duration),
            Action::InsertHeaderNumbers => self.insert_header_numbers.record(duration),
            Action::InsertHeaderTerminalDifficulties => self.insert_header_td.record(duration),
            Action::InsertBlockOmmers => self.insert_block_ommers.record(duration),
            Action::InsertTransactionSenders => self.insert_tx_senders.record(duration),
            Action::InsertTransactions => self.insert_transactions.record(duration),
            Action::InsertTransactionHashNumbers => self.insert_tx_hash_numbers.record(duration),
            Action::InsertBlockWithdrawals => self.insert_block_withdrawals.record(duration),
            Action::InsertBlockRequests => self.insert_block_requests.record(duration),
            Action::InsertBlockBodyIndices => self.insert_block_body_indices.record(duration),
            Action::InsertTransactionBlocks => self.insert_tx_blocks.record(duration),
            Action::GetNextTxNum => self.get_next_tx_num.record(duration),
            Action::GetParentTD => self.get_parent_td.record(duration),
            //lytest
            Action::InsertBlockVerify=>self.insert_block_verify.record(duration),
            Action::InsertBlockRewards=>self.insert_block_rewards.record(duration),
        }
    }
}
