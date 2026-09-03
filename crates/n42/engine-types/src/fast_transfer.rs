// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A plain value transfer applied without the interpreter.
//!
//! At the bench tier a block is 163,000 transfers between externally owned
//! accounts, and revm spends about 1.4 us on each: a journal, a frame, a
//! call into an account with no code, the journal's finalisation. The state
//! transition of such a transfer is three balance changes and a nonce, and
//! this module applies exactly that -- with revm's own arithmetic, in revm's
//! own order, producing the accounts revm's journal would hand back and the
//! result its handler would build -- and only when it can prove revm would
//! succeed and charge exactly the base cost. Anything else, and every
//! transaction on a fork this module has not been checked against, goes to
//! the interpreter unchanged. Every node executes every transaction either
//! way; nothing is skipped, and the post-state is the same to the byte.
//!
//! What qualifies: a call (legacy, EIP-2930 or EIP-1559) with no calldata, no
//! access list, no blob and no authorisation, from an account without code,
//! to an account without code that is not a precompile, with the nonce, the
//! balance and the fees revm's pre-execution checks demand, on Prague or
//! Osaka. The sender, the recipient and the block's beneficiary must be three
//! distinct accounts, the recipient must not be left empty (EIP-161) and the
//! beneficiary must already exist and not be empty, so that no account's
//! existence changes in a way this module would have to model.
//!
//! `N42_FAST_TRANSFER=1` turns it on; it is off by default so that a fleet
//! can measure it against the interpreter on the same binary.

use alloy_primitives::{Address, Bytes, U256};
use reth_evm::{
    eth::{EthEvmBuilder, EthEvmContext},
    precompiles::PrecompilesMap,
    Database, EthEvm, Evm, EvmEnv, EvmFactory,
};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::{
        result::{EVMError, ExecutionResult, HaltReason, Output, ResultAndState, ResultGas, SuccessReason},
        Block as _, Cfg as _, Transaction as _,
    },
    database_interface::DBErrorMarker,
    inspector::NoOpInspector,
    primitives::{hardfork::SpecId, HashMap, TxKind},
    state::{Account, EvmState, TransactionId},
    Inspector,
};

/// The gas of a call with no calldata: the whole cost of a qualifying transfer.
const TRANSFER_GAS: u64 = 21_000;

/// How many transfers have taken this path in this process.
static HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many transfers have taken this path in this process, so far.
pub fn hits() -> u64 {
    HITS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Why transfers were sent to the interpreter instead, by reason, so a
/// fleet that shows no hits says which check refused them.
static REJECTED: [std::sync::atomic::AtomicU64; 12] = [const { std::sync::atomic::AtomicU64::new(0) }; 12];

/// The refusals so far, by reason: shape, fork, configuration, limits, fees,
/// parties, sender, balance, recipient, beneficiary, arithmetic, inspecting.
pub fn rejected() -> [u64; 12] {
    std::array::from_fn(|i| REJECTED[i].load(std::sync::atomic::Ordering::Relaxed))
}

fn refused<T, E>(reason: usize) -> Result<Option<T>, E> {
    REJECTED[reason].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(None)
}

/// Whether `N42_FAST_TRANSFER=1` is set.
pub fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("N42_FAST_TRANSFER").map(|v| v == "1").unwrap_or(false))
}

/// [`EthEvmFactory`](reth_evm::EthEvmFactory) with the transfer path in front
/// of the interpreter.
#[derive(Debug, Clone, Copy, Default)]
pub struct N42EvmFactory {
    fast: bool,
}

impl N42EvmFactory {
    /// A factory whose EVMs take the transfer path when `N42_FAST_TRANSFER=1`.
    pub fn from_env() -> Self {
        Self { fast: enabled() }
    }

    /// A factory whose EVMs take (or never take) the transfer path.
    pub const fn with_fast_transfers(fast: bool) -> Self {
        Self { fast }
    }
}

impl EvmFactory for N42EvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> = N42Evm<DB, I>;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Tx = TxEnv;
    type Error<DBError: DBErrorMarker> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        N42Evm { inner: EthEvmBuilder::new(db, input).build(), inspecting: false, fast: self.fast }
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        N42Evm {
            inner: EthEvmBuilder::new(db, input).activate_inspector(inspector).build(),
            inspecting: true,
            fast: self.fast,
        }
    }
}

/// [`EthEvm`] with the transfer path in front of the interpreter.
pub struct N42Evm<DB: Database, I> {
    inner: EthEvm<DB, I, PrecompilesMap>,
    /// An inspector is watching: every transaction goes through the
    /// interpreter, which is what the inspector expects to see.
    inspecting: bool,
    fast: bool,
}

impl<DB: Database, I> std::fmt::Debug for N42Evm<DB, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("N42Evm").field("inspecting", &self.inspecting).field("fast", &self.fast).finish_non_exhaustive()
    }
}

impl<DB: Database, I: Inspector<EthEvmContext<DB>>> N42Evm<DB, I> {
    /// The transfer's result and post-state, if the transaction qualifies and
    /// revm would succeed on it; `None` sends it to the interpreter. A database
    /// error is the same error the interpreter would have hit loading the
    /// account.
    fn transfer(&mut self, tx: &TxEnv) -> Result<Option<ResultAndState>, DB::Error> {
        // The transaction's shape.
        let TxKind::Call(to) = tx.kind else { return refused(0) };
        if !tx.data.is_empty()
            || tx.tx_type > 2
            || !tx.access_list.0.is_empty()
            || !tx.authorization_list.is_empty()
            || !tx.blob_hashes.is_empty()
            || tx.gas_limit < TRANSFER_GAS
        {
            return refused(0);
        }
        let cfg = self.inner.cfg_env();
        let block = self.inner.block();
        // The forks this path is checked against: after EIP-7623 and EIP-7702
        // (Prague), before EIP-7708's transfer logs and EIP-8037's state gas
        // (Amsterdam).
        let spec = cfg.spec();
        if !spec.is_enabled_in(SpecId::PRAGUE) || spec.is_enabled_in(SpecId::AMSTERDAM) {
            return refused(1);
        }
        // Every check revm makes before executing, as revm makes it; a
        // configuration that relaxes any of them is not modelled here.
        if cfg.is_nonce_check_disabled()
            || cfg.is_balance_check_disabled()
            || cfg.is_eip3607_disabled()
            || cfg.is_fee_charge_disabled()
            || cfg.is_base_fee_check_disabled()
            || cfg.is_priority_fee_check_disabled()
            || cfg.is_block_gas_limit_disabled()
            || cfg.is_eip7623_disabled()
        {
            return refused(2);
        }
        if tx.chain_id.is_some_and(|id| id != cfg.chain_id())
            || tx.gas_limit > cfg.tx_gas_limit_cap()
            || tx.gas_limit > block.gas_limit()
        {
            return refused(3);
        }
        let basefee = block.basefee() as u128;
        if tx.gas_price < basefee || tx.gas_priority_fee.is_some_and(|tip| tip > tx.gas_price) {
            return refused(4);
        }
        let caller = tx.caller;
        let beneficiary = block.beneficiary();
        if to == caller || to == beneficiary || caller == beneficiary {
            return refused(5);
        }
        if self.inner.precompiles().get(&to).is_some() {
            return refused(5);
        }

        // The accounts, loaded the way the journal would load them: through
        // the same database, so its cache holds them as the pre-state.
        let value = tx.value;
        let db = self.inner.db_mut();
        let Some(sender) = db.basic(caller)? else { return refused(6) };
        if !sender.is_code_hash_empty_or_zero() || sender.nonce != tx.nonce || sender.nonce == u64::MAX {
            return refused(6);
        }
        let Ok(max_spending) = tx.max_balance_spending() else { return refused(7) };
        if max_spending > sender.balance {
            return refused(7);
        }
        let recipient = db.basic(to)?;
        match &recipient {
            Some(info) if !info.is_code_hash_empty_or_zero() => return refused(8),
            // An account that stays empty after being touched is deleted
            // (EIP-161); the interpreter models that, this does not.
            Some(info) if value.is_zero() && info.is_empty() => return refused(8),
            None if value.is_zero() => return refused(8),
            _ => {}
        }
        let Some(coinbase) = db.basic(beneficiary)? else { return refused(9) };
        if coinbase.is_empty() {
            return refused(9);
        }

        // revm's arithmetic: the caller pays gas_limit at the effective price
        // and the value, then gets the unused gas back at the same price; the
        // beneficiary receives the used gas at the price above the base fee.
        let effective_price = tx.effective_gas_price(basefee);
        let Some(gas_cost) = effective_price.checked_mul(TRANSFER_GAS as u128) else { return refused(10) };
        let Some(sender_balance) = sender.balance.checked_sub(value).and_then(|b| b.checked_sub(U256::from(gas_cost)))
        else {
            return refused(10);
        };
        let Some(recipient_balance) = recipient.as_ref().map_or(U256::ZERO, |r| r.balance).checked_add(value)
        else {
            return refused(10);
        };
        let tip = effective_price.saturating_sub(basefee);
        let Some(reward) = tip.checked_mul(TRANSFER_GAS as u128) else { return refused(10) };
        let Some(coinbase_balance) = coinbase.balance.checked_add(U256::from(reward)) else { return refused(10) };

        // The accounts as the journal would return them: touched, with the
        // pre-state kept as the original, and a recipient that did not exist
        // marked as loaded that way.
        let mut state: EvmState = HashMap::default();
        let mut sender_account = Account::from(sender);
        sender_account.info.balance = sender_balance;
        sender_account.info.nonce += 1;
        sender_account.mark_touch();
        state.insert(caller, sender_account);
        let mut recipient_account = match recipient {
            Some(info) => Account::from(info),
            None => Account::new_not_existing(TransactionId::ZERO),
        };
        recipient_account.info.balance = recipient_balance;
        recipient_account.mark_touch();
        state.insert(to, recipient_account);
        let mut coinbase_account = Account::from(coinbase);
        coinbase_account.info.balance = coinbase_balance;
        coinbase_account.mark_touch();
        state.insert(beneficiary, coinbase_account);

        // The result revm's handler builds for a call into an account without
        // code: it stops, spends the base cost, refunds nothing, and the
        // EIP-7623 floor for no calldata is the base cost too.
        let result = ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas: ResultGas::new_with_state_gas(TRANSFER_GAS, 0, TRANSFER_GAS, 0),
            logs: Vec::new(),
            output: Output::Call(Bytes::new()),
        };
        Ok(Some(ResultAndState::new(result, state)))
    }
}

impl<DB, I> Evm for N42Evm<DB, I>
where
    DB: Database,
    I: Inspector<EthEvmContext<DB>>,
{
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        self.inner.block()
    }

    fn cfg_env(&self) -> &CfgEnv<SpecId> {
        self.inner.cfg_env()
    }

    fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    fn transact_raw(&mut self, tx: TxEnv) -> Result<ResultAndState, Self::Error> {
        if self.fast && self.inspecting {
            REJECTED[11].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if self.fast && !self.inspecting {
            if let Some(done) = self.transfer(&tx).map_err(EVMError::Database)? {
                HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(done);
            }
        }
        self.inner.transact_raw(tx)
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState, Self::Error> {
        self.inner.transact_system_call(caller, contract, data)
    }

    fn finish(self) -> (DB, EvmEnv<SpecId, BlockEnv>) {
        self.inner.finish()
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspecting = enabled;
        self.inner.set_inspector_enabled(enabled);
    }

    fn components(&self) -> (&DB, &I, &PrecompilesMap) {
        self.inner.components()
    }

    fn components_mut(&mut self) -> (&mut DB, &mut I, &mut PrecompilesMap) {
        self.inner.components_mut()
    }
}

#[cfg(test)]
mod tests {
    //! The transfer path against the interpreter: same result, same accounts.
    use super::*;
    use alloy_primitives::{address, TxKind};
    use revm::{
        database::{CacheDB, EmptyDB},
        state::AccountInfo,
        Database as _, DatabaseCommit,
    };

    const SENDER: Address = address!("0x1000000000000000000000000000000000000001");
    const RECIPIENT: Address = address!("0x2000000000000000000000000000000000000002");
    const EXISTING: Address = address!("0x3000000000000000000000000000000000000003");
    const COINBASE: Address = address!("0x4000000000000000000000000000000000000004");
    const BASEFEE: u64 = 1_000;

    fn env() -> EvmEnv {
        let mut cfg = CfgEnv::new_with_spec(SpecId::OSAKA);
        cfg.chain_id = 1;
        let block = BlockEnv {
            beneficiary: COINBASE,
            basefee: BASEFEE,
            gas_limit: 30_000_000,
            ..Default::default()
        };
        EvmEnv::new(cfg, block)
    }

    fn db() -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(SENDER, AccountInfo { balance: U256::from(10u128.pow(20)), nonce: 7, ..Default::default() });
        db.insert_account_info(EXISTING, AccountInfo { balance: U256::from(5), nonce: 3, ..Default::default() });
        db.insert_account_info(COINBASE, AccountInfo { balance: U256::from(1), ..Default::default() });
        db
    }

    fn tx(to: Address, value: u128, tx_type: u8, gas_price: u128, tip: Option<u128>) -> TxEnv {
        TxEnv {
            tx_type,
            caller: SENDER,
            gas_limit: 50_000,
            gas_price,
            gas_priority_fee: tip,
            kind: TxKind::Call(to),
            value: U256::from(value),
            data: Bytes::new(),
            nonce: 7,
            chain_id: Some(1),
            ..Default::default()
        }
    }

    /// Runs `tx` on both paths from the same pre-state; returns (fast, slow),
    /// each as the result and the committed accounts of the three parties.
    fn both(tx: TxEnv) -> Vec<(ResultAndState, Vec<Option<AccountInfo>>)> {
        [true, false]
            .into_iter()
            .map(|fast| {
                let mut evm = N42EvmFactory::with_fast_transfers(fast).create_evm(db(), env());
                let out = evm.transact_raw(tx.clone()).expect("the transaction executes");
                let (mut db, _) = evm.finish();
                db.commit(out.state.clone());
                let infos = [SENDER, RECIPIENT, EXISTING, COINBASE]
                    .into_iter()
                    .map(|a| db.basic(a).expect("cache").map(|i| AccountInfo { code: None, ..i }))
                    .collect();
                (out, infos)
            })
            .collect()
    }

    fn assert_same(tx: TxEnv, expect_fast: bool) {
        let runs = both(tx.clone());
        let (fast, slow) = (&runs[0], &runs[1]);
        assert_eq!(fast.0.result, slow.0.result, "result");
        assert_eq!(fast.1, slow.1, "committed accounts");
        // The accounts the path hands back: only the touched ones, and for
        // those the same info and the same existence flag as the journal's.
        for (address, account) in &fast.0.state {
            let theirs = slow.0.state.get(address).expect("the interpreter loaded it too");
            assert_eq!(account.info, theirs.info, "info of {address}");
            assert_eq!(account.is_touched(), theirs.is_touched(), "touched {address}");
            assert_eq!(
                account.is_loaded_as_not_existing(),
                theirs.is_loaded_as_not_existing(),
                "not-existing flag {address}"
            );
        }
        let mut evm = N42EvmFactory::with_fast_transfers(true).create_evm(db(), env());
        assert_eq!(evm.transfer(&tx).expect("no database error").is_some(), expect_fast, "the path taken");
    }

    /// The two paths through revm's `State`, the layer the node persists
    /// from: the bundle (accounts, their statuses, the reverts) must be the
    /// same, or the block written to the database is not.
    fn bundles(tx: TxEnv) -> Vec<revm::database::BundleState> {
        use revm::database::{states::bundle_state::BundleRetention, State};
        [true, false]
            .into_iter()
            .map(|fast| {
                let mut state = State::builder().with_database(db()).with_bundle_update().build();
                {
                    let mut evm = N42EvmFactory::with_fast_transfers(fast).create_evm(&mut state, env());
                    let out = evm.transact_raw(tx.clone()).expect("the transaction executes");
                    evm.db_mut().commit(out.state);
                }
                state.merge_transitions(BundleRetention::Reverts);
                state.take_bundle()
            })
            .collect()
    }

    fn assert_same_bundle(tx: TxEnv) {
        let b = bundles(tx);
        let (fast, slow) = (&b[0], &b[1]);
        assert_eq!(fast.state.len(), slow.state.len(), "accounts in the bundle");
        for (address, account) in &slow.state {
            let ours = fast.state.get(address).expect("account in our bundle");
            assert_eq!(ours.info, account.info, "info {address}");
            assert_eq!(ours.original_info, account.original_info, "original info {address}");
            assert_eq!(ours.status, account.status, "status {address}");
            assert_eq!(ours.storage, account.storage, "storage {address}");
        }
        assert_eq!(fast.reverts, slow.reverts, "reverts");
        assert_eq!(fast.contracts.len(), slow.contracts.len(), "contracts");
    }

    #[test]
    fn bundle_of_a_transfer_to_a_new_account() {
        assert_same_bundle(tx(RECIPIENT, 12_345, 2, 5_000, Some(300)));
    }

    #[test]
    fn bundle_of_a_transfer_to_an_existing_account() {
        assert_same_bundle(tx(EXISTING, 1, 2, 5_000, Some(300)));
    }

    #[test]
    fn bundle_of_two_transfers_in_one_block() {
        use revm::database::{states::bundle_state::BundleRetention, State};
        let b: Vec<revm::database::BundleState> = [true, false]
            .into_iter()
            .map(|fast| {
                let mut state = State::builder().with_database(db()).with_bundle_update().build();
                {
                    let mut evm = N42EvmFactory::with_fast_transfers(fast).create_evm(&mut state, env());
                    for (nonce, to) in [(7u64, RECIPIENT), (8u64, RECIPIENT)] {
                        let mut t = tx(to, 5, 2, 5_000, Some(300));
                        t.nonce = nonce;
                        let out = evm.transact_raw(t).expect("executes");
                        evm.db_mut().commit(out.state);
                    }
                }
                state.merge_transitions(BundleRetention::Reverts);
                state.take_bundle()
            })
            .collect();
        assert_eq!(b[0].state.len(), b[1].state.len());
        for (address, account) in &b[1].state {
            let ours = &b[0].state[address];
            assert_eq!((&ours.info, &ours.original_info, ours.status), (&account.info, &account.original_info, account.status), "{address}");
        }
        assert_eq!(b[0].reverts, b[1].reverts, "reverts");
    }

    #[test]
    fn eip1559_transfer_to_a_new_account() {
        assert_same(tx(RECIPIENT, 12_345, 2, 5_000, Some(300)), true);
    }

    #[test]
    fn eip1559_transfer_to_an_existing_account() {
        assert_same(tx(EXISTING, 1, 2, 5_000, Some(300)), true);
    }

    #[test]
    fn tip_capped_by_the_max_fee() {
        assert_same(tx(EXISTING, 1, 2, 1_100, Some(300)), true);
    }

    #[test]
    fn legacy_transfer() {
        assert_same(tx(EXISTING, 99, 0, 2_000, None), true);
    }

    #[test]
    fn zero_value_to_a_new_account_goes_to_the_interpreter() {
        assert_same(tx(RECIPIENT, 0, 2, 5_000, Some(300)), false);
    }

    #[test]
    fn a_transfer_to_self_goes_to_the_interpreter() {
        assert_same(tx(SENDER, 1, 2, 5_000, Some(300)), false);
    }

    #[test]
    fn a_wrong_nonce_goes_to_the_interpreter() {
        let mut t = tx(EXISTING, 1, 2, 5_000, Some(300));
        t.nonce = 8;
        let mut evm = N42EvmFactory::with_fast_transfers(true).create_evm(db(), env());
        assert!(evm.transact_raw(t).is_err(), "the interpreter rejects it");
    }
}
