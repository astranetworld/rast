# 签名算法、批量交易类型与抗量子支持：调研对比（2026-09-06）

本文回答三个问题：(1) 在本机（AMD EPYC 9B45，AVX-512）上哪种签名 / 恢复算法既高效又安全，
以及如何通过扩展交易类型（EIP-2718 类型字节）引入；(2) 业界有哪些"一批交易一起签名、验证、
传输、执行、改状态"的协议，以及对 N42 管线意味着什么；(3) 当下是否存在通过扩展交易类型的
抗量子（Falcon 等）签名 / 验签，gov5 支持到什么程度。

所有数字来自 `docs/sigbench/`（独立 crate，`cargo run --release`），原始输出在
`docs/sigbench/results-2026-09-06-epyc-9b45.txt`。测量时机器 load 4.5，单线程数字取 5 次
中最好的一次；"20 线程"一行是 20 个线程同时跑 0.8 s 的实际吞吐（和 fleet 每节点 20 个恢复槽
一致）。fleet 里实测的 ecrecover 是空闲 36–43 µs、SMT 争用下 48–63 µs，比这里的 29 µs 慢，
差额是缓存 / SMT 争用，各算法同样会受到。

## 1. 本机基准

| 算法（实现） | 单线程 µs/次 | 20 线程 次/s | 签名 B | 公钥 B | 备注 |
| --- | ---: | ---: | ---: | ---: | --- |
| keccak256（110 B 交易） | 0.26 | – | – | – | 基线 |
| **secp256k1 ECDSA 恢复（libsecp256k1，节点现用）** | **29.4** | **676k** | 65 | 0（恢复） | 我们现在的成本 |
| secp256k1 ECDSA 验证（给定公钥） | 25.3 | – | 64 | 33 | 恢复只贵 15% |
| secp256k1 ECDSA 恢复（k256 纯 Rust） | 135.6 | – | 65 | 0 | 4.6× 慢，绝不能退到这条路径 |
| secp256k1 Schnorr BIP-340（k256） | 56.7 | – | 64 | 32 | libsecp 的 schnorrsig 应接近 25 µs，未测 |
| P-256 ECDSA（p256 纯 Rust，revm 的 RIP-7212 用的就是它） | 163.6 | – | 64 | 33 | passkey 场景，性能最差 |
| **Ed25519 单条（dalek）** | 26.3 | 759k | 64 | 32 | 与 ecrecover 同级 |
| **Ed25519 批量 64 / 256** | **13.0 / 10.2** | **1,638k**（批 64） | 64 | 32 | 批量验证 2–3× |
| BLS12-381 单条（blst） | 667 | 30k | 96 | 48 | 单条极贵 |
| **BLS12-381 聚合验证，每签（n=64 / 256，不同消息）** | **20.6 / 8.4** | – | 96 / 批 | 48 | 需要有人先聚合 |
| BLS12-381 fast_aggregate_verify（512 签名同一消息） | 835（整批） | – | 96 | – | 委员会投票的成本 |
| ML-DSA-44（fips204 纯 Rust） | 60.7 | 330k | 2,420 | 1,312 | FIPS 204 |
| ML-DSA-65 | 97.7 | – | 3,309 | 1,952 | |
| **Falcon-512（PQClean C，AVX2）** | **31.3** | **639k** | 656 | 897 | **与 ecrecover 同价** |
| Falcon-1024 | 60.9 | – | 1,275 | 1,793 | |
| Falcon-512 签名 | 150 | – | | | 仅供参考 |
| SLH-DSA-SHAKE-128f（fips205） | 3,448 | – | 17,088 | 32 | 不可用 |

换算成 fleet 的形状——一块 163k 笔、每节点 20 个线程验签：

| 方案 | 每块验签墙钟 | 每块签名 + 公钥字节 |
| --- | ---: | ---: |
| secp256k1 ecrecover（现状） | 241 ms | 10.6 MB |
| Ed25519 单条 | 215 ms | 15.6 MB |
| Ed25519 批量 64 / 256 | 100 / 83 ms | 15.6 MB |
| BLS 聚合（n=256 一组） | 68 ms（+ 出块者聚合） | 7.8 MB 公钥 + 每组 96 B |
| Falcon-512（AVX2） | 255 ms | **253 MB** |
| Falcon-512（AVX-512 优化实现，论文 3.6 µs） | ~29 ms | 253 MB（有注册表则 112 MB） |
| ML-DSA-44 | 494 ms | 608 MB |

现在每块 payload 约 19 MB（110 B/笔）。抗量子方案在 CPU 上已经不贵（Falcon-512 与 ecrecover 持平，
AVX-512 版本能快 8 倍），**贵在字节**：每块 253 MB 意味着每个 follower 每 0.4 s 收 253 MB，
这是 gossip 带宽和存储的问题，不是验签的问题。这一点决定了第 3 节的结论。

## 2. 选择：什么算法、怎么通过扩展交易类型引入

### 2.1 结论

1. **保留 secp256k1 ECDSA 作为默认**（钱包生态、EIP-7702、所有工具链）。恢复比验证只贵 15%，
   "把公钥放进交易省掉恢复"不值得做。
2. **新增一条 Ed25519 交易类型作为高吞吐路径**。理由：单条与 ecrecover 同价，批量验证在本机
   每签 10–13 µs（2.3–2.9×），实现成熟（dalek，常量时间、`verify_strict` 拒绝可延展签名），
   密钥 32 B、签名 64 B，Solana / Sui / Aptos / Cosmos 的默认方案。安全性上 Ed25519（Curve25519，
   ~128-bit）与 secp256k1 等价，且没有 ECDSA 的 nonce 依赖。
3. **BLS 聚合只用于"有人替一批交易聚合"的场景**（ERC-4337/ERC-7766 式的 bundler，或出块者
   聚合），每签 8.4 µs 是所有经典方案里最低的，但要求公钥可查（不可恢复）、需要 PoP（防
   rogue-key）、单条验证 667 µs 意味着 mempool 逐条准入不可行。不建议做成通用交易类型。
4. **Schnorr / P-256 不推荐**：Schnorr 在本机没有性能优势（批量验证 libsecp 主线也没有），
   P-256 只有 passkey 需要，用预编译（RIP-7212 / EIP-7951，revm 已带 `P256VERIFY` 0x100）
   在合约层解决即可。
5. **抗量子**：Falcon-512 是唯一 CPU 成本与现状持平的方案，但 1.5 KB/笔的字节成本在 16 万笔/块
   下不可承受；ML-DSA-44 CPU 翻倍、字节 3.7 KB。见第 4 节。

### 2.2 那个 EIP：EIP-7932 及其现状

- **EIP-7932 "Secondary Signature Algorithms"**（Draft）。2025-04 提出时是"算法交易封装"
  （一个新 2718 类型包裹另一笔交易并前置签名数据），2025-08 与 EF 讨论后**改为注册表 +
  `SIGRECOVER` 预编译（地址 0x12，基础 3,000 gas，输入 `alg_type || signature || signing_data`，
  输出 20 字节地址）**，不再定义交易类型。每种算法要一个独立 EIP 登记 `ALG_TYPE`（< 127，
  0x00 = secp256k1，0x7F 保留）、`SIZE`、`gas_cost()`、`verify()`。
  发送者地址 = `keccak(alg_id || pubkey)[12:]`（63 字节公钥有防碰撞特判）。
- **EIP-7980 "Ed25519 transaction support"**：7932 的第一个算法登记（`ALG_TYPE` 为 Ed25519），
  **已 Withdrawn**。
- 交易层的承载现在被寄托在 **EIP-8141 "Frame Transaction"**（类型 0x06，VERIFY 帧 + EXECUTE 帧，
  Hegotá 的 CFI，2026 下半年），签名灵活性走账户抽象：验证逻辑在 VERIFY 帧里调用 7932 的
  `SIGRECOVER` 或 8051/8052 的 PQ 预编译。7932 讨论串 2026-08 的帖子正是在谈 8141 用哨兵值走
  非 ECDSA 路径。
- 相关预编译 EIP：EIP-2537（BLS12-381，Pectra 已上线，revm 有）、RIP-7212 / EIP-7951
  （P-256，revm 有 `secp256r1.rs`）、EIP-665（Ed25519 预编译，旧提案，Stagnant）。
- **reth 2.5.1 / alloy 2.3 / revm 42 里没有 7932、7980、8051、8052、8141 的任何实现**
  （在 cargo registry 源码里 grep 无命中；revm 预编译目录只有 secp256k1、secp256r1、bls12_381、
  bn254、kzg、modexp、blake2、hash）。

同一模式在别的链早已是生产形态：Sui 的签名是 `flag || sig || pubkey`（0x00 Ed25519、0x01
secp256k1、0x02 secp256r1、0x03 多签、0x05 zkLogin、0x06 passkey），地址 = `blake2b(flag ||
pubkey)`——和 7932 的地址推导完全同构；Aptos、Solana 也是同样的"算法标识 + 公钥随交易携带"。

### 2.3 对 N42 的实现建议（扩展交易类型）

以太坊主网路径（7932 + 8141）今年不会落地，我们不必等。建议自定义一个 2718 类型字节，
但**沿用 7932 的地址推导和 `alg_type` 编号**，将来若 7932 上线可以无缝对齐：

```
0x50  N42AltSigTx = rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data,
                         access_list, alg_type, pubkey, signature])
      sender = keccak256(alg_type || pubkey)[12:]
      alg_type: 0x01 = Ed25519 (pubkey 32 B, signature 64 B)   // 7932 未分配的号段，将来跟随其登记
      signing hash = keccak256(0x50 || rlp([... 到 access_list, alg_type, pubkey]))
```

- 恢复槽（`crates/n42/tx-ingest`）看到 0x50 就不做 ecrecover，攒成 64–256 条一批调
  `ed25519_dalek::verify_batch`，失败时退化为逐条以定位坏签名；批量验证需要独立随机数
  （dalek 用 CSPRNG 加权，防止批内抵消攻击）。
- 出块与 follower 校验同样按批验（`bin/n42/src/follower_import.rs` 的并行导入路径可以直接换验签函数）。
- 与 revm 的接口：`TxEnv.caller` 已经是恢复后的地址，执行层不需要知道算法；
  `fast_transfer.rs` 对 `tx_type > 2` 的拒绝要放行 0x50。
- 不动 `y_parity/r/s` 的语义、不改 legacy 类型，是纯增量。

预期收益（按第 1 节）：每节点 20 槽的供给上限从 ~350k/s 提到 ~800k+/s（批 64），
链本身的 0.36 s 周期（约 450k/s）会成为新的瓶颈。

## 3. 批量交易：业界协议与对 N42 的启示

### 3.1 协议盘点

| 协议 | 状态 | 一个签名覆盖什么 | 与我们相关的点 |
| --- | --- | --- | --- |
| EIP-2711 Sponsored, expiring and batch transactions | Draft / Stagnant（2020） | 一笔交易内多个 call，有赞助者 | 最接近"原生批量交易类型"的 EIP，被拆解后放弃 |
| EIP-3074 AUTH/AUTHCALL | Withdrawn | invoker 合约代发 | 安全模型依赖 invoker，被 7702 取代 |
| **EIP-7702 Set Code**（Pectra，已上线） | Final | EOA 委托代码后一笔交易做多个 call | 批量 call 有了，但每笔仍是一次 ecrecover + authorization 的 ecrecover |
| ERC-4337 bundle + **ERC-7766 Signature Aggregation** | 标准 / Draft | bundler 把多个 UserOp 的签名聚合成一个（BLS 参考实现） | 唯一把"跨发送者一次验签"做成标准接口的方案：`aggregateSignatures` / `validateSignatures` |
| **EIP-8141 Frame Transaction**（类型 0x06） | Hegotá CFI | VERIFY 帧 + 多个 EXECUTE 帧，原生 AA | 以太坊自己给出的"批量 + 任意签名算法"最终形态 |
| Algorand atomic group | 生产 | 最多 16 笔，组 id = 各笔哈希，全成或全败 | 每笔仍各自签名，节省的是原子性不是验签 |
| Sui Programmable Transaction Block | 生产 | 一个签名、最多 1,024 条命令 | 同一发送者"一签多做"的极致形态 |
| Cosmos SDK multi-msg tx | 生产 | 一个签名、多个 msg | 同上 |
| Solana | 生产 | 一笔交易多条 instruction、多签名者；sigverify 按 128 个包一批做 Ed25519 批量验证（CPU/GPU） | 传输、验签都天然按批 |

### 3.2 哪种"批"真的省 CPU

在我们的管线里每笔的 CPU 大头是 ecrecover（29–63 µs），解码 + keccak 约 1 µs，快速转账执行
1–2 µs，状态更新按账户数计。传输已经是批的（ingest 的 frame、gossip 的 block body）。
所以只有两种批能改变数字：

1. **同一发送者一签多转（签名摊销）**——Sui/Cosmos 模式。一个签名覆盖 k 个 `(to, value)`，
   恢复成本 /k，字节 65/k + 每项约 30 B。k=8 时每笔恢复 3.7 µs，供给上限直接越过链的 450k/s。
   这是对 N42 收益最大、实现最小的一项，且和现有 `fast_transfer` 路径正交。
2. **跨发送者批量验证**——Ed25519 批量（2.3–2.9×）或 BLS 聚合（3.5×，但需要聚合者与公钥注册）。
   这是第 2 节的交易类型。

原子组（Algorand）和 7702 式批量 call 不减少验签次数，对 TPS 目标没有帮助。

### 3.3 建议的批量类型

```
0x51  N42BatchTransferTx = rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit,
                                items: [[to, value], ...] (1..=256),
                                alg_type, pubkey_or_empty, signature])
```

- `alg_type = 0x00` 时 `signature` 是 65 B 的 secp256k1 可恢复签名、`pubkey` 为空，
  与现有钱包密钥兼容；`0x01` 走 Ed25519。两种类型共用一套 `alg_type` 解释。
- 一个 nonce、一次 gas 结算、一张回执（回执里按 item 记 log 或 status 位图），
  执行在 `fast_transfer` 里循环 items，状态写 1 + k 个账户。
- 出块者按 item 数计 gas 与占用；mempool 按整笔准入；`tx_flood` 增加 `--batch k` 生成这种交易
  即可测量。
- 这就是 EIP-2711 的 batch 部分去掉赞助 / 过期后的最小子集，也和 8141 的 EXECUTE 帧语义相容。

## 4. 抗量子签名：当下支持情况

### 4.1 以太坊与业界

- **没有任何已上线的"抗量子签名交易类型"**。以太坊路线图明确走账户抽象（EIP-8141）+ 预编译：
  - **EIP-8051 ML-DSA-44 预编译**（Draft）：`VERIFY_MLDSA` 0x12、`VERIFY_MLDSA_ETH` 0x13，
    4,500 gas，输入 32 B 消息 + 2,420 B 签名 + 20,512 B 展开公钥；带 7932 兼容的 `signature_info` 容器。
  - **EIP-8052 Falcon 预编译**（Draft，2025-10；三个预编译，含 SHAKE256 与 Keccak-PRNG 两种
    hash-to-point，各 1,000 gas）；更早的 **EIP-7619 Falcon512 通用验证器**（0x65，1,465 gas + 6/字）。
  - 注意 8051 的 0x12 与 7932 的 `SIGRECOVER` 0x12 撞地址，两者都是 Draft，说明这一块远未定稿。
  - Solana 有 Falcon 验签 syscall 的提案（SIMD-0461，PR 阶段）。
- 性能上 Falcon 已经不是障碍：本机 PQClean AVX2 31 µs；2026 年的 AVX-512 实现在 Zen5 上 3.6 µs
  （eprint 2026/1539，代码开源但 CC BY-NC-ND）。障碍是尺寸：签名 656 B + 公钥 897 B。
  gov5 的 `PQKeyRegistry`（注册后交易只带 32 B 公钥哈希）是正确方向，但公钥要从状态里读一次。

### 4.2 n42-rs

无。`crates/`、`bin/`、`docs/` 里没有 falcon / dilithium / ML-DSA / SLH-DSA 的任何代码，
交易类型只有 reth 自带的 0x00–0x04（fast_transfer 只放行 ≤ 2）。依赖链（reth 2.5.1、alloy 2.3、
revm 42）也没有。要做只能自己加（`pqcrypto-falcon` / `fips204` 都能直接用，本文基准就是用它们跑的）。

### 4.3 gov5（`../N42-gov5`）

**有实现，但不是交易类型，并且 Falcon 部分不安全。**

- 代码：`crypto/falcon`（Falcon-512）、`crypto/dilithium`（mode2/3/5 及 AES 变体，circl 模板生成）、
  `crypto/kyber`、`crypto/kem/{kyber,frodo}`、`crypto/pke/kyber`、`crypto/csidh`。
- 预编译 `internal/vm/pq_contracts.go`：0x14 Falcon-512、0x15 Dilithium2、0x16 Dilithium3、
  0x17 SQIsign（返回 `errPQNotImplemented`）；gas 3,500 / 4,000 / 5,000 / 8,000；
  由 `ChainRules.IsPQPrecompiles`（`pqPrecompilesTime`）门控，**只有 devnet 配置置 0 开启**，
  链 94/95 的配置里没有。zkprover 的 guest 也带了这个开关。
- `contracts/pqregistry/PQKeyRegistry.sol`：PQ 公钥注册表，交易引用 32 B 哈希。
- `internal/p2p/discover/v5wire/pq_handshake.go`：discv5 握手用 Kyber KEM（这是密钥交换，不是签名）。
- **交易类型只有 Legacy / AccessList / DynamicFee（0、1、2）**：没有 PQ 扩展交易类型，
  PQ 签名只能由合约（智能账户）调预编译验证，与以太坊的 8141 思路一致。
- **`crypto/falcon` 不是 Falcon**。`internal.go` 的 `verifySignature` 不做任何格运算
  （没有 NTT、没有 `s1 = c − s2·h mod q`、没有范数检查），只解出 `s2` 的前 64 个系数当作
  `commitment || tag`，检查 `tag == SHAKE256(commitment || pk.h || msg)`。这个标签任何人
  拿公钥就能算。我用一个临时测试（构造 commitment、算 tag、经 `encodeSignature` 编码）
  证实：**仅凭公钥伪造的 553 字节签名被 `falcon.Verify` 接受**（`forged signature accepted
  without private key: true`），测试文件已删除、仓库无改动。因此 0x14 预编译在当前实现下
  等价于"永远通过"，`PQKeyRegistry` 里登记 Falcon 公钥的账户对任何人开放。
  Dilithium 是 circl 模板生成的完整实现（有 NTT/Decompose/UseHint），但没有 KAT 测试文件，
  本机没有 circl 模块缓存，未逐字比对。
- 探针代码（放到 `crypto/falcon/` 下的 `_test.go` 即可复现）：

```go
pk, _, _ := GenerateKey(nil)
var s2 [N]int16
commitment := make([]byte, 32)
for i := range commitment { commitment[i] = byte(i * 7); s2[i] = int16(int8(commitment[i])) }
sh := sha3.NewShake256(); sh.Write(commitment)
for i := 0; i < N; i++ { sh.Write([]byte{byte(pk.h[i]), byte(pk.h[i] >> 8)}) }
sh.Write(msg); var tag [32]byte; sh.Read(tag[:])
for i := 0; i < 32; i++ { s2[32+i] = int16(int8(tag[i])) }
sig := make([]byte, SignatureSize); n := encodeSignature(sig, make([]byte, 40), s2[:])
Verify(pk, msg, sig[:n]) // == true
```

### 4.4 结论

- "通过扩展交易类型的抗量子签名 / 验签"：**以太坊没有，reth/alloy/revm 没有，n42-rs 没有，
  gov5 也没有**（gov5 只有预编译 + 注册表合约，且 Falcon 实现是占位）。
- 如果 N42 要做，路径清楚：第 2.3 节的 0x50 类型加 `alg_type = 0x02 Falcon-512`，验签用
  PQClean（后续换 AVX-512 实现），公钥走注册表；CPU 与现状持平，真正要解决的是每笔多出的
  ~700 B 在 gossip 和存储上的代价。在 16 万笔/块的目标下这意味着块体从 19 MB 涨到 ~130 MB。

## 来源

- EIP-7932 <https://eips.ethereum.org/EIPS/eip-7932>，讨论串 <https://ethereum-magicians.org/t/eip-7932-secondary-signature-algorithms/23514>
- EIP-7980 <https://eips.ethereum.org/EIPS/eip-7980>（Withdrawn）
- EIP-8141 <https://eips.ethereum.org/EIPS/eip-8141>
- EIP-8051 <https://eips.ethereum.org/EIPS/eip-8051>，EIP-8052 <https://eips.ethereum.org/EIPS/eip-8052>，EIP-7619 <https://eips.ethereum.org/EIPS/eip-7619>
- EIP-2711 <https://eips.ethereum.org/EIPS/eip-2711>，ERC-7766 <https://eips.ethereum.org/EIPS/eip-7766>
- 以太坊抗量子路线图 <https://ethereum.org/roadmap/security/quantum-resistance/>
- Falcon Verify on AVX-512 <https://eprint.iacr.org/2026/1539>
- Sui 签名格式 <https://docs.sui.io/concepts/cryptography/transaction-auth/signatures>，PTB <https://docs.sui.io/concepts/transactions/prog-txn-blocks>
- Algorand atomic transfers <https://developer.algorand.org/docs/get-details/atomic_transfers/>
- Solana sigverify <https://github.com/solana-labs/solana/blob/cd6f931223181d5a1d47cba64e857785a175a760/core/src/sigverify.rs>，SIMD-0461 <https://github.com/solana-foundation/solana-improvement-documents/pull/461>
