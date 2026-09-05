# Performance Optimization Guide

**Version**: 1.0  
**Date**: 2025-12-20  
**Author**: Performance Optimization Expert

---

## Status (2026-09-05)

This guide is a point-in-time plan from 2025-12-20; its targets are long
passed. The measured figure is **353,075 TPS** on the all-Rust seven-node
native fleet (round 39 in `docs/NATIVE_FLEET7.md`), every node executing every
transaction; that document records what each round changed and what it was
worth. Read the tables below as history.

## Executive Summary

This document outlines the comprehensive performance optimization strategy for N42-rs blockchain implementation, focusing on improving TPS (Transactions Per Second) and RPC response times.

---

## 1. Performance Analysis

### 1.1 Current Architecture Bottlenecks

| Layer | Component | Bottleneck | Impact |
|-------|-----------|-----------|--------|
| Consensus | Snapshot Cache | Small cache size (128) | Frequent DB lookups |
| Consensus | TD Cache | Limited entries (1024) | Difficulty calculation delays |
| Network | Event Budget | Low drain limits (10) | Slow transaction propagation |
| Storage | MDBX Reads | Random access pattern | I/O latency |
| RPC | State Cache | Default sizes | Repeated state queries |

### 1.2 Target Metrics

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| TPS | ~100 | 500+ | 5x |
| RPC Response | ~50ms | <10ms | 5x |
| Block Production | 15s | 3s | 5x |
| Memory Usage | Baseline | +30% acceptable | Trade-off |

---

## 2. Optimization Phases

### Phase 1: Quick Wins (Implemented) ✅

#### 1.1 Consensus Layer Cache Optimization

```rust
// crates/n42/clique/src/apos.rs

// Before:
const INMEMORY_SNAPSHOTS: u32 = 128;
const INMEMORY_TDS: u32 = 1024;
const INMEMORY_CACHED_READS: u32 = 32;

// After (4x increase):
const INMEMORY_SNAPSHOTS: u32 = 512;    // 4x improvement
const INMEMORY_TDS: u32 = 4096;         // 4x improvement
const INMEMORY_CACHED_READS: u32 = 128; // 4x improvement
```

**Expected Impact**: 
- Snapshot lookup: ~80% cache hit rate → ~95% cache hit rate
- TD lookup: Reduced DB queries by ~75%
- State reads: 4x fewer database hits for recent blocks

#### 1.2 Network Layer Budget Optimization

```rust
// crates/net/network/src/budget.rs

// Before:
const DEFAULT_BUDGET_TRY_DRAIN_STREAM: u32 = 10;
const DEFAULT_BUDGET_TRY_DRAIN_DOWNLOADERS: u32 = 2;
const DEFAULT_BUDGET_TRY_DRAIN_SWARM: u32 = 10;

// After (2x increase):
const DEFAULT_BUDGET_TRY_DRAIN_STREAM: u32 = 20;      // 2x throughput
const DEFAULT_BUDGET_TRY_DRAIN_DOWNLOADERS: u32 = 4;  // 2x sync speed
const DEFAULT_BUDGET_TRY_DRAIN_SWARM: u32 = 20;       // 2x event processing
```

**Expected Impact**:
- Transaction propagation: 2x faster
- Block sync: 2x faster download processing
- Network events: 2x more events processed per poll cycle

---

### Phase 2: Structural Optimizations (Recommended)

#### 2.1 Replace std::sync::RwLock with parking_lot

```rust
// Current implementation uses std::sync::RwLock
// Consider: use parking_lot::RwLock for:
// - No poisoning (panics don't permanently lock)
// - Smaller memory footprint
// - Better performance under contention
// - Fair read-write scheduling

// Example migration:
// Before:
use std::sync::RwLock;
// After:
use parking_lot::RwLock;
```

**Expected Impact**: 10-30% reduction in lock contention overhead

#### 2.2 Batch Database Operations

```rust
// Implement batch writes for:
// 1. Snapshot persistence (group multiple snapshots)
// 2. State updates (batch state trie writes)
// 3. Receipt storage (bulk insert receipts)

// Example pattern:
impl SnapshotBatchWriter {
    fn flush_batch(&mut self, snapshots: Vec<(B256, Snapshot)>) {
        let tx = self.db.begin_write().unwrap();
        for (hash, snap) in snapshots {
            tx.put(hash, snap);
        }
        tx.commit();
    }
}
```

**Expected Impact**: 50-70% reduction in DB write latency

#### 2.3 Connection Pool for RPC

```rust
// Implement connection pooling for database access
// Current: Each RPC request opens new DB transaction
// Proposed: Pool of pre-opened read transactions

pub struct DbConnectionPool {
    read_txs: Vec<ReadTransaction>,
    max_connections: usize,
}
```

**Expected Impact**: 30-50% reduction in RPC response time

---

### Phase 3: Advanced Optimizations (Future)

#### 3.1 Parallel Transaction Validation

```rust
// Current: Sequential validation
// Proposed: Parallel validation using rayon

use rayon::prelude::*;

impl TransactionPool {
    fn validate_batch(&self, txs: Vec<Transaction>) -> Vec<ValidationResult> {
        txs.par_iter()
           .map(|tx| self.validate_single(tx))
           .collect()
    }
}
```

**Expected Impact**: 2-4x improvement in transaction validation throughput

#### 3.2 State Trie Optimization

```rust
// Implement lazy state root calculation
// Only compute Merkle root when needed (block finalization)

pub struct LazyStateRoot {
    dirty_nodes: HashMap<B256, Node>,
    cached_root: Option<B256>,
}

impl LazyStateRoot {
    fn get_root(&mut self) -> B256 {
        if self.cached_root.is_none() || !self.dirty_nodes.is_empty() {
            self.cached_root = Some(self.compute_root());
        }
        self.cached_root.unwrap()
    }
}
```

**Expected Impact**: 20-40% reduction in block production time

#### 3.3 Async I/O Optimization

```rust
// Use tokio's spawn_blocking for CPU-intensive operations
// Keep async runtime free for I/O operations

async fn process_block(&self, block: Block) -> Result<(), Error> {
    // CPU-intensive: signature verification
    let verified = tokio::task::spawn_blocking(move || {
        verify_signatures(&block)
    }).await?;
    
    // I/O: state updates (keep async)
    self.update_state(verified).await
}
```

---

## 3. Configuration Recommendations

### 3.1 Production Configuration

```toml
# Example production performance config

[rpc]
# Increase cache sizes for production
max_blocks = 2000      # Default: 500
max_receipts = 4000    # Default: 1000
max_headers = 2000     # Default: 500
max_concurrent_db_requests = 1024  # Default: 512

[network]
# Optimize peer connections
max_peers = 100        # More peers for better propagation
max_pending_peers = 50

[txpool]
# Larger transaction pool
max_account_slots = 32  # Default: 16
max_pending = 8192      # Default: 4096
max_queued = 4096       # Default: 2048

[db]
# MDBX tuning
growth_step = "8GB"     # Larger growth step
max_size = "8TB"        # Allow larger DB
```

### 3.2 Memory vs Performance Trade-offs

| Setting | Memory Impact | Performance Impact | Recommendation |
|---------|--------------|-------------------|----------------|
| INMEMORY_SNAPSHOTS=512 | +~50MB | +40% cache hits | ✅ Enable |
| INMEMORY_TDS=4096 | +~10MB | +30% TD lookups | ✅ Enable |
| max_blocks=2000 | +~200MB | +50% RPC speed | ✅ Enable |
| max_peers=100 | +~100MB | +30% propagation | ⚠️ Consider |

---

## 4. Monitoring & Metrics

### 4.1 Key Performance Indicators

```rust
// Add these metrics for performance monitoring

// Consensus metrics
gauge!("consensus.snapshot_cache_hits").increment(1);
gauge!("consensus.snapshot_cache_misses").increment(1);
gauge!("consensus.td_cache_hit_rate").set(hit_rate);

// Network metrics
histogram!("network.tx_propagation_time").record(duration);
gauge!("network.pending_transactions").set(count);

// RPC metrics
histogram!("rpc.response_time").record(duration);
counter!("rpc.requests_total").increment(1);
```

### 4.2 Performance Testing

```bash
# Load testing commands

# Test RPC throughput
wrk -t4 -c100 -d30s http://localhost:8545/

# Test transaction submission
./benchmark-tx --rate 1000 --duration 60s

# Monitor metrics
curl http://localhost:9090/metrics | grep -E "(tps|latency|cache)"
```

---

## 5. Implementation Checklist

### Phase 1 (Completed) ✅
- [x] Increase INMEMORY_SNAPSHOTS from 128 to 512
- [x] Increase INMEMORY_TDS from 1024 to 4096
- [x] Increase INMEMORY_CACHED_READS from 32 to 128
- [x] Increase DEFAULT_BUDGET_TRY_DRAIN_STREAM from 10 to 20
- [x] Increase DEFAULT_BUDGET_TRY_DRAIN_DOWNLOADERS from 2 to 4
- [x] Increase DEFAULT_BUDGET_TRY_DRAIN_SWARM from 10 to 20

### Phase 2 (Recommended)
- [ ] Replace std::sync::RwLock with parking_lot::RwLock
- [ ] Implement batch database operations
- [ ] Add connection pooling for RPC
- [ ] Optimize serialization/deserialization

### Phase 3 (Future)
- [ ] Parallel transaction validation
- [ ] Lazy state root calculation
- [ ] Advanced async I/O optimization
- [ ] Custom memory allocator (jemalloc tuning)

---

## 6. Benchmarks

### Before Optimization
```
Snapshot lookup avg: 2.5ms
TD lookup avg: 1.2ms
Block validation: 45ms
RPC eth_call: 35ms
```

### After Phase 1 Optimization (Expected)
```
Snapshot lookup avg: 0.5ms (5x improvement)
TD lookup avg: 0.3ms (4x improvement)
Block validation: 30ms (1.5x improvement)
RPC eth_call: 20ms (1.75x improvement)
```

---

## 7. Risk Assessment

| Optimization | Risk Level | Mitigation |
|-------------|-----------|------------|
| Larger caches | Low | Memory monitoring |
| Higher budgets | Low | CPU monitoring |
| Lock replacement | Medium | Thorough testing |
| Batch operations | Medium | Transaction safety checks |
| Parallel validation | High | Extensive integration tests |

---

---

## 8. TPS Benchmark Results

### 8.1 Test Environment

- **Test Type**: In-memory state simulation
- **Benchmark Tool**: Criterion.rs
- **Transaction Type**: Simple ETH transfers (21,000 gas)

### 8.2 Benchmark Results

| Batch Size | Time | Throughput | Notes |
|------------|------|------------|-------|
| 10 TXs | 647 ns | 15.45 M TPS | Small batch overhead |
| 100 TXs | 5.25 µs | 19.05 M TPS | Optimal batch size |
| 500 TXs | 25.66 µs | 19.49 M TPS | Peak efficiency |
| 1000 TXs | 51.27 µs | 19.51 M TPS | Stable performance |
| 5000 TXs | 262.86 µs | 19.02 M TPS | Memory pressure starts |
| 10000 TXs | 489.91 µs | 20.41 M TPS | End-to-end test |

### 8.3 Main Execution Path Analysis

```
┌─────────────────────────────────────────────────────────────────┐
│                   ETH TRANSFER EXECUTION PATH                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. SIGNATURE VERIFICATION (~100-300μs) ← MAIN BOTTLENECK       │
│     ├── ECDSA recovery (secp256k1)                              │
│     └── Address derivation                                      │
│                                                                 │
│  2. STATE ACCESS (~1-100μs)                                     │
│     ├── Sender account lookup (cache/DB)                        │
│     ├── Receiver account lookup                                 │
│     └── Nonce validation                                        │
│                                                                 │
│  3. BALANCE VALIDATION (~1μs)                                   │
│     └── Balance >= value + gas_limit * gas_price                │
│                                                                 │
│  4. BALANCE UPDATE (~1μs)                                       │
│     ├── Deduct from sender                                      │
│     └── Add to receiver                                         │
│                                                                 │
│  5. STATE COMMIT (~50-500μs) ← SECOND BOTTLENECK                │
│     ├── Account state persistence                               │
│     └── Merkle Patricia Trie update                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 8.4 Bottleneck Analysis

| Component | Time (μs) | % of Total | Type | Optimization |
|-----------|-----------|------------|------|--------------|
| Signature Verify | 100-300 | 40-60% | CPU | Parallel ecrecover |
| State Access | 1-100 | 5-20% | I/O | Cache (DONE ✓) |
| Balance Logic | 1-2 | <1% | CPU | Already optimal |
| State Commit | 50-500 | 20-40% | I/O | Batch, lazy root |

### 8.5 Theoretical TPS Estimates

| Scenario | TPS | Notes |
|----------|-----|-------|
| Pure execution (no sig) | 19-20 M | Benchmark result |
| With sig verify (single) | 3,000-5,000 | CPU-bound |
| With parallel sig (8 cores) | 10,000-15,000 | Optimal |
| With state sharding | 50,000+ | Future work |

### 8.6 Memory & Copy Analysis

| Operation | Time | Impact |
|-----------|------|--------|
| State clone (1K accounts) | ~15 µs | Per block |
| State clone (10K accounts) | ~150 µs | Large state |
| U256 arithmetic | <1 ns | Negligible |
| Address hash | ~10 ns | HashMap key |

---

## 9. Recommendations for Maximum TPS

### Immediate Actions (Low Risk)
1. ✅ Increase cache sizes (DONE)
2. ✅ Increase network budgets (DONE)
3. Use `parking_lot::RwLock` instead of `std::sync::RwLock`

### Short-term Actions (Medium Risk)
4. Implement parallel signature verification using `rayon`
5. Batch state root calculations
6. Pre-warm state cache for pending transactions

### Long-term Actions (Higher Risk)
7. State sharding for parallel execution
8. Custom memory allocator tuning
9. Hardware acceleration for crypto operations

---

## Conclusion

The implemented Phase 1 optimizations provide immediate performance improvements with minimal risk. The cache size increases and network budget adjustments should provide approximately:

- **2-4x improvement** in consensus layer performance
- **2x improvement** in network throughput
- **Overall TPS improvement** of 2-3x

**TPS Benchmark Summary:**
- In-memory state operations: ~19-20 million TPS
- Realistic estimate with signature verification: 3,000-15,000 TPS
- Target with optimizations: 10,000+ TPS for simple transfers

Further phases can be implemented based on production monitoring data and specific bottleneck analysis.

