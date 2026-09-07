# 研发排期：Ed25519 扩展交易类型，目标 1,000k TPS（2026-09-06）

依据 `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md`（算法基准、EIP 现状、批量协议、抗量子现状）
和 `docs/NATIVE_FLEET7.md`（fleet 的测量方法与现状）。本文只排工作，不重复论证。

## 0. 起点与目标

现状（round 39 / loop63，七节点，163k 笔/块，480M gas）：

| 项 | 数值 | 出处 |
| --- | ---: | --- |
| 记录 | 365,399 TPS（win1）| loop53Q300a |
| 供给上限（每节点 20 个恢复槽） | ~340–355k/s，槽 95% 忙 | loop54-55 |
| ecrecover 成本 | 空闲 36–43 µs，SMT 争用 48–63 µs | loop56-58 |
| 节点 CPU 中签名恢复占比 | 约 3/4（负载下） | commit d3326dd2b |
| 链周期（并行 follower） | 0.36–0.38 s → 容量 ~450k/s | loop54-55 |
| 本机 Ed25519 批量验证 | 单条 26 µs，批 64 为 13 µs，批 256 为 10 µs | sigbench |

目标：**Ed25519 高吞吐路径 1,000k TPS**，分三个里程碑：

- **M1（阶段 1）**：Ed25519 交易走批量验证。本机潜力：20 线程批 64 验证 **164 万签/s**
  （sigbench 实测 25,600 批/s × 64），是 ecrecover 同线程数 67.6 万/s 的 2.4 倍。签名之外的
  ingest 成本（解码、入队、缓存写入）今天约 16 µs/笔，在 20 槽下就是 125 万/s 的天花板，
  所以 M1 的验收定为**单节点 ingest ≥ 1,000k/s（20 槽）**，fleet 从"供给绑定"变为"链绑定"。
- **M2（阶段 2）**：链周期这一新瓶颈被推开：同一周期下每块笔数 ×1.5，或周期 ≤ 0.30 s；
  fleet win1 ≥ 550k（三轮 spread 内）。
- **M3（阶段 3）**：fleet win1 ≥ 1,000k。按 0.40 s 周期需要每块 400k 笔（gas 上限 ~1.18B，
  Ed25519 块体 ~56 MB）；按 0.33 s 周期需要每块 330k 笔。M3 的预算见第 4 节。

默认签名保持 secp256k1 不变；Ed25519 是并列的高吞吐路径，不替换任何现有类型。

## 0b. 进展（2026-09-07）

- M1 供给侧达成：ingest 每笔 54–56 µs → 26–31 µs，20 槽半数空闲，洪泛被 ingest 门（池高水位）限速而非签名恢复。
- round 41：`N42_ALTSIG_SENDER_CACHE=4194304` 后 follower 满块导入 336 → 222 ms，win1 **396,601 / 385,742**（每块全满，周期 0.41 s）。
  链成为瓶颈：163k 笔/块 × 0.41 s ≈ 397k/s，低于 450k 的估计，因为 0x50 块体 23 MB（141 B/笔）。
- 未达：M1 的"单节点 ingest ≥ 1,000k/s"没有直接量到（链先饱和）；win1 ≥ 420k 未达（链容量 397k）。
- 缺陷：7 条 ed25519 腿里 2 条在第 222 块停摆（下一任 leader 的执行层导入完成执行后全线程 futex 等待），已加阶段标记与看门狗，loop66 复现时定位。
- 下一步即阶段 2：loop66（pertx 10000、gas 上限 5.13B = 245k 笔/块、pacing 250）。

## 1. 总体排期

| 周 | 阶段 | 交付 | 验收 |
| --- | --- | --- | --- |
| W1 ✅ 2026-09-06 | 1A 规范 + 1B 原语 crate | `docs/spec/N42_TX_0x50.md`；`crates/n42/primitives-tx` 通过单测与 fixture | 编码/解码/哈希/地址推导与规范一致 |
| W2–W3 ✅ 2026-09-06（编译通过，未上 fleet） | 1C 节点贯通 | 节点接受、打包、执行、存储、RPC 返回 0x50 交易 | `n42 node` 单机跑通 `send_tx --alg ed25519`；`cargo check --workspace` 干净 |
| W4 ✅ 2026-09-07（round 40：供给成本减半、链成为瓶颈；见 NATIVE_FLEET7） | 1D 批量验证 + 1E 负载工具 + 1F 测量 | ingest 批验；`tx_flood --alg ed25519`；A-B-A 三轮 | **M1** |
| W5–W6 | 2A–2D 链周期 | 更大的块、follower sender 路径、body 传输、pacing 复测 | **M2** |
| W7 | 缓冲、文档、tag | `docs/NATIVE_FLEET7.md` 记录，打 tag | — |
| W8–W11 | 3A–3D 冲 1,000k | 并行出块、body 分片传输、ingest 非签名成本、写 IO | **M3** |

单人全职估计。W2–W3 是风险最大的一段（见 1C 的风险）。

## 2. 阶段 1：Ed25519 扩展交易类型

### 1A 规范（2 天）

```
type byte 0x50  N42AltSigTx
payload = rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
               to, value, data, access_list, alg_type, pubkey, signature])
alg_type  = 0x01 (Ed25519; pubkey 32 B, signature 64 B). 0x00 保留给 secp256k1，与 EIP-7932 对齐
signing hash = keccak256(0x50 || rlp([chain_id … access_list, alg_type, pubkey]))
sender    = keccak256(alg_type || pubkey)[12:]            // EIP-7932 的推导
tx hash   = keccak256(0x50 || payload)
gas       = 与 0x02 相同的 intrinsic gas（签名字节不额外计价；fleet 内部链）
mempool   = signature 必须 canonical（s < L，dalek verify_strict 的规则）；alg_type 未知即拒绝
```

已决定（2026-09-06）：第一阶段**只做 call**，`to == None`（create）的 0x50 交易在解码时拒绝；
回执与 RPC 里的 `type` 字段值为 0x50；gov5 不识别 0x50，混合 fleet 不能用，fleet7 全 Rust 不受影响。

### 1B 原语 crate `crates/n42/primitives-tx`（1 周）

- `TxAltSig` 结构、RLP 编解码、`Encodable2718/Decodable2718`、`Typed2718`、`SignableTransaction`
  的等价物（签名哈希）、`Transaction` trait（gas/nonce/to/value 等访问器）。
- `N42TxEnvelope = { Legacy, Eip2930, Eip1559, Eip4844, Eip7702, AltSig }`：以 reth 的
  `EthereumTxEnvelope` 为基础加一个变体（先例：op-reth 的 `OpTxEnvelope` 加 Deposit 0x7E）。
- `SignedTransaction` for `N42TxEnvelope`：`recover_signer` 对 AltSig 做单条 `verify_strict`
  并返回派生地址；`recover_signer_unchecked` 同样验签（Ed25519 没有"不检查"的恢复）。
- reth 存储需要的 `Compact` 编码（`reth-codecs`）：新类型走一个新的 type 标志位；
  静态文件与 MDBX/RocksDB 表都靠它。
- `serde`、`arbitrary`（测试）、`Hash/Eq`。
- 测试：round-trip、签名哈希 KAT（用 Python/独立脚本生成 3 组 fixture 存 `testdata/`）、
  地址推导、坏签名拒绝、s 非 canonical 拒绝。

### 1C 节点贯通（1.5 周）

把 `EthPrimitives` 换成 `N42Primitives`（`SignedTx = N42TxEnvelope`，Block/Receipt 随之），
需要动的点（按调用链）：

| 位置 | 改动 |
| --- | --- |
| `crates/n42/engine-types/src/node.rs` | `Primitives = N42Primitives` 约束；`N42Node` 的 `NodeTypes` |
| 交易池 | `EthPooledTransaction<N42TxEnvelope>` 或自定义 `N42PooledTransaction`；`PooledOf<P>` 解码接受 0x50；`try_recover_with_cache` 走新 envelope 的 `recover_signer` |
| EVM（`crates/n42/engine-types` 的 `N42EvmFactory` / `tx_env`） | AltSig → `TxEnv`：`caller` 用派生地址，`tx_type` 映射为 2（revm 不需要知道算法）；`fast_transfer.rs` 的 `tx.tx_type > 2` 放行 AltSig 映射后的值 |
| 出块（`payload.rs`、`assembler.rs`、`built_executions.rs`） | 泛型随 primitives 变；交易根用 `encode_2718` 已覆盖新类型 |
| 执行层通道（`h2-execution/raw_engine.rs`、`bin/n42/src/payload_serve.rs`） | `execution_data_from_raw_parts` 的交易字节按 2718 解码，接受 0x50；OWN_BLOCK 头路径不受影响 |
| follower（`bin/n42/src/follower_import.rs`、`parallel_transfer.rs`） | `Evm`/`Provider` 约束改到 `N42Primitives`；sender 缓存 miss 时走批量验证（1D） |
| h2 wire body（`h2-net/block_gossip.rs`、`h2-node/service.rs`） | RLP `[header, txs, verifiers, rewards]` 里 txs 用 2718 字节；✅ 已改为全程原始字节：出块者封装（`encode_block_rlp` → `into_block_raw`）、封印（`normalize_to_gov5_h2_with_header`）、执行层取块（`ChainBlock.transactions: Vec<Bytes>`，RPC 解析节点自己的交易类型）都不再解码成 alloy `TxEnvelope` |
| RPC（`crates/rpc/rpc-types-compat`，已 vendored） | AltSig → `alloy_rpc_types_eth::Transaction` 的映射（`type=0x50`，`r/s/v` 置空，新增 `pubkey/signature` 字段）；回执不变 |
| 存储（`crates/storage/*`，已 vendored） | 表的 value 类型跟随 `Compact`；`n42-init-snapshot`/`qmdb-export` 不涉及交易，不动 |

风险与对策：

- **级联编译**：所有 `Primitives = EthPrimitives` 的约束（node.rs 有 4 处、follower_import、payload_serve）
  与上游 `EthereumNode` 组件的耦合。对策：先在分支上做一次"只换类型不加变体"的 `N42TxEnvelope`
  （AltSig 变体先不加），把级联收敛，再加变体。这一步在 W2 前两天完成，是整个阶段的信号点。
- **`Compact` 与静态文件**：新类型字节要在 reth 的 tx 类型位域里有位置；测试从空 datadir 起链，
  不做旧数据迁移（fleet 每轮 `--fresh`）。
- **gov5 互操作**：0x50 只在 fleet7 链上启用（genesis `config` 加 `altSigTx: true`，
  不改 genesis hash）；`n42_devnet.json` 不开。

### 1D 批量验证（3 天）

- `crates/n42/tx-ingest/src/lib.rs` 的 `recover_decoded`：按类型分流，AltSig 攒到批
  （`N42_ED25519_BATCH`，默认 64，上限 256）调 `ed25519_dalek::verify_batch`；整批失败时逐条
  `verify_strict` 定位坏签名并丢弃；成功的写 `SenderRecoveryCache`（follower 导入靠它，同现有路径）。
- 批量验证的安全规则：dalek 的批量验证用随机权重（需要 `batch` feature 的 CSPRNG），
  不能用确定性权重；批内任何一条坏签名都必须导致回退逐条，不能"整批通过"。
- `follower_import.rs` 的缓存 miss 路径同样分批（正常情况下 miss 率应接近 0，因为每个节点都
  ingest 全部交易；记录 miss 计数以验证）。
- 恢复槽数保持 20 先测，再扫 16/20/24：Ed25519 批验的每槽吞吐是 ecrecover 的 2–3 倍，
  SMT 争用曲线可能不同。

### 1E 负载工具（2 天）

- `crates/n42/h2-node/examples/tx_flood.rs`：`--alg ed25519`。派生：`seed = keccak(offset,index)`
  的 32 B 作为 Ed25519 私钥；地址按 1A 推导；**funding 阶段用现有 secp 账户给这些地址转入**
  （fleet7 链 `everything at block 0`，无 EIP-8037 的创建成本问题）。
- `examples/send_tx` 同样加 `--alg`。
- 每笔字节：Ed25519 交易 ~141 B（比 0x02 的 ~110 B 多 31 B）；163k 笔的块体从 19 MB 涨到 ~23 MB，
  `publish -> receive` 预计从 74 ms 涨到 ~90 ms——这是阶段 2 要处理的一部分。

### 1F 测量（3 天）

1. 单节点 ingest 微基准（不起 fleet）：`N42_TX_INGEST_*` 现有计数器，比较 0x02 与 0x50 每槽 tx/s。
   验收：0x50 ≥ 2× 0x02。
2. fleet A-B-A：同一配置（record 配置，pacing 300），A = secp 洪泛，B = ed25519 洪泛，各三轮
   `scripts/fleet7-repeat.sh 3`，warm-up 腿作废。读 `fleet7-measure.py` 的 TPS + 占用 + full，
   `fleet7-phases.py` 的周期拆分。
   验收（M1）：单节点 ingest ≥ 1,000k/s（20 槽）；fleet 上 B 的块占用 ≥ 95%，周期上升到 0.40 s
   以上（链绑定的特征），win1 ≥ 420k（链容量 ~450k 减去 5% spread）。
   如果单节点 ingest 停在 1,000k 以下而签名验证已不是热点，热点就是解码 / 入队 / 缓存写入的
   16 µs，进 3C 处理。
3. 记录到 `docs/NATIVE_FLEET7.md`（round 40）。

## 3. 阶段 2：链周期 0.36 s

M1 之后供给 ~800k/s 而链只吃 ~450k/s。周期的组成（loop54-55，pacing 300）：门 327 ms
（300 + 27 固定）；follower 侧 publish→receive 74 ms、并行执行 87 ms（partition 29 / groups 29 /
merge 18）+ senders + QMDB root + 投票；leader 的 build-ahead 已在关键路径之外。

| 项 | 做法 | 预期 | 天 |
| --- | --- | --- | ---: |
| 2A 更大的块 | `--gasceil` 480M → 720M → 960M（245k / 326k 笔/块），`--pertx`/`F7_FLOOD_WINDOW` 配套；测 body 传输、并行执行、root 随块大小的斜率 | 固定成本（两轮 HotStuff 消息、门、投票收集）摊薄；单块 0.5 s 吃 326k 笔即 650k/s | 4 |
| 2B follower 的 sender 路径 | 1D 之后测 `senders_ms` 与缓存 miss；miss 走批验 | senders 从关键路径消失 | 1 |
| 2C body 传输 | 19→23→38 MB 的 body：direct push 分片并行发送；先测带宽是否是 74 ms 的成因（vs 序列化/解码） | publish→receive 不随块大小线性增长 | 4 |
| 2D pacing 复测 | follower 变快后 300 → 250 → 200 各三轮；`F7_VIEW_TIMEOUT_MS` 不动（更紧更差，已测） | 找到新的最优门 | 2 |
| 2E 执行与投票重叠（研究） | HotStuff-2 的两轮给了一个槽：R1 投票后、R2 决定前执行；先只做测量与设计，不实现 | 决定是否进阶段 3 | 2 |

验收（M2）：同一周期下每块笔数 ×1.5，或周期 ≤ 0.30 s；fleet win1 ≥ 550k，三轮 spread 内。
已知不要再碰的：更紧的 view timeout、vote log fsync、RocksDB nosync/direct-IO、BAL 并行执行器、
账户预取、pool gate 深度、24/28 槽、run length > 64、恢复线程 pin。

## 4. 阶段 3：1,000k TPS 的预算与工作项（W8–W11）

1,000k/s 在七节点、每节点执行全部交易的形状下，每个部件的预算（按 0.40 s 周期、400k 笔/块）：

| 部件 | 今天（163k 笔/块） | 1,000k 需要 | 差距与工作项 |
| --- | ---: | ---: | --- |
| 每节点 ingest（20 槽） | ~350k/s | ≥ 1,000k/s | 签名：M1 解决（潜力 1.64M/s）；非签名 16 µs/笔 → ≤ 7 µs（**3C**） |
| 出块者执行（build-ahead 内） | 194–207 ms | ≤ ~350 ms / 400k 笔 | 线性外推 480–510 ms，超出周期：出块者也走 `parallel_transfer` 的分组并行（**3A**） |
| follower 并行执行 | 87 ms | ≤ ~200 ms | 线性外推 213 ms，边界上；分组数与 worker 数随块放大复测（2A 的斜率） |
| body 传输 publish→receive | 74 ms / 19 MB | ≤ ~120 ms / 56 MB | 线性外推 ~220 ms：direct push 分片并行、接收端并行解码（**3B**，接 2C） |
| QMDB root + 状态写 | 在 receive→vote 内 | 随账户数线性 | 2A 测斜率；必要时 root 计算分片 |
| 磁盘写 | ~1 GB/s（七节点合计） | ~2.7 GB/s | 静态文件与 tx-hash 索引的写放大（**3D**）；长窗口才暴露 |
| 内存 | EL 每块 +~19 MB 已知增长 | 块体 ×3 | 先找到持有 payload 字节的 reth 组件（loop60 未解） |

工作项：

| 项 | 做法 | 天 |
| --- | --- | ---: |
| 3A 并行出块 | 出块者的 fast-transfer 构建改为分组并行（复用 `parallel_transfer::Groups`），bundle 直接写入；与 build-ahead 配合 | 6 |
| 3B body 分片传输 | direct push 按 N 片并行发送与解码，接收端边收边解；测 56 MB 块体的 publish→receive | 5 |
| 3C ingest 非签名成本 | 解码零拷贝（frame 已是 `Bytes`）、入队批量化到 256、缓存写入合并；目标 ≤ 7 µs/笔 | 4 |
| 3D 写 IO | 更大的写缓冲、tx-hash 索引迁出或延后、静态文件段大小；90 s 以上窗口验证 | 4 |
| 3E 测量 | 三轮 A-B-A，`fleet7-phases.py` 拆周期；`docs/NATIVE_FLEET7.md` round 41 | 3 |

验收（M3）：fleet win1 ≥ 1,000k，三轮 spread 内；占用 ≥ 90%。

## 4b. 排期外（按收益排序）

1. **0x51 批量转账类型**（同一发送者一签多转，调研 3.3 节）：k=8 时每笔恢复 3.7 µs，
   对 secp 账户也有效；`fast_transfer` 循环 items。估 2 周。若 M3 卡在供给上，它先于 3C。
2. **`alg_type = 0x02` Falcon-512**：CPU 与 ecrecover 持平，字节 +1.5 KB/笔；需要公钥注册表
   （gov5 `PQKeyRegistry` 的思路）与 AVX-512 验签实现的许可评估（eprint 2026/1539 是 CC BY-NC-ND）。
   先做设计，不排实现。
3. **gov5 的 Falcon 验签可伪造**（调研 4.3 节有复现代码）：gov5 侧已知晓并在其排期中处理（2026-09-06），
   本排期不涉及。

## 5. 规则

- 每个数字都要 A-B-A、三轮、看 win1 与整轮总量；warm-up 腿作废；box claim 协议
  （`/data/blockchain/wr-logs/BOX-CLAIM-PROTOCOL.md`）。
- 新代码在 `crates/n42/*`；vendored reth crate 只做增量改动；`[lints] workspace = true`；
  consensus 路径不引入 `unwrap`。
- 每个里程碑打 tag（`n42-v0.10.0` = M1，`n42-v0.11.0` = M2，`n42-v1.0.0` = M3）。
