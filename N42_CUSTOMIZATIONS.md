# N42 定制修改清单

## 模块1: primitives-traits
### 定制文件:
- `crates/primitives-traits/src/header/clique_utils.rs` - **N42独有**, 提供 clique 签名恢复和 seal hash 计算
- `crates/primitives-traits/src/header/mod.rs` - 导出 `clique_utils` 模块

### 定制内容:
- `recover_address()` - 从区块头恢复签名者地址
- `seal_hash()` - 计算 clique 共识用的 seal hash
- `recover_address_generic()` - 泛型版本
- `seal_hash_generic()` - 泛型版本

## 模块2: consensus
### 定制文件:
- `crates/consensus/consensus/src/lib.rs` - 扩展 `Consensus` trait

### 定制内容:
- `prepare()` - APoS 准备区块头
- `seal()` - APoS 签名封装
- `snapshot()` - 获取快照
- `propose()` - 投票提案
- `discard()` - 撤销提案
- `proposals()` - 获取当前提案
- `total_difficulty()` - 获取总难度
- `wiggle()` - 计算 wiggle 时间
- `set_eth_signer_by_key()` - 设置签名者
- `get_eth_signer_address()` - 获取签名者地址
- 自定义错误类型: `SignHeaderError`, `SaveSnapshotError`, `NoSignerSet`, `AposErrorDetail`

## 模块3: storage
### 定制文件:
- `crates/storage/db-api/src/models/beacon.rs` - **N42独有**, beacon 数据模型
- `crates/storage/db-api/src/tables/mod.rs` - 添加 beacon 相关表

### 定制内容:
- `BeaconStateRecord` 表
- `BeaconBlockRecord` 表
- `BeaconNum2Hash` 表
- `PlainValidatorState` 表
- `ValidatorsHistory` 表
- `ValidatorChangeSets` 表

## 模块4: network
### 定制内容:
- 增加了网络预算参数 (budget.rs)
- N42 特定的导入/验证逻辑

## 模块5: ethereum/evm
### 定制内容:
- `evm_env()` 中使用 `recover_address()` 获取 beneficiary
- `blob_max_and_target_count_by_hardfork()` 方法

## 模块6: node/builder
### 定制文件:
- `crates/node/builder/src/launch/executed_inserts.rs`（N42 新增）
- `crates/node/builder/src/launch/engine.rs`（引擎循环多一个 select 分支）
- `crates/node/builder/src/lib.rs`（`pub use launch::executed_inserts`）
### 定制内容:
- 一条进入引擎循环的通道：节点把自己已经执行过的块（`BuiltPayloadExecutedBlock`）交给引擎，
  循环转成 `EngineApiRequest::InsertExecutedBlock` 并回执。reth 只对 payload 事件流里带执行结果的
  payload 走这条路，以太坊 payload 类型不带；N42 的共识在构建之后才封装块头、哈希会变，
  所以由节点自己配对（`bin/n42/src/payload_serve.rs`）。纯增量，默认对上游行为无影响。

## 其他 N42 独有模块:
- `crates/n42/clique/` - APoS 共识实现
- `crates/n42/primitives/` - beacon 链原语
- `crates/n42/engine-types/` - 引擎类型
- `crates/n42/engine-primitives/` - 引擎原语
- `crates/n42/consensus-client/` - 共识客户端
- `crates/n42/mobile-sdk/` - 移动端 SDK
- `crates/n42/merkle_db_rs/` - Merkle DB
- `crates/n42/pubsub-mem/` - 内存 pub/sub
- `crates/n42/alloy-rpc-types-engine/` - RPC 类型
- `crates/n42/alloy-rpc-types-beacon/` - Beacon RPC 类型
- `crates/ethereum/hardforks/` - N42 特定硬分叉
