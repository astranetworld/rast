# How many accounts do 163,000 consecutive transactions touch? Ethereum, BNB, Polygon, Tron against the fleet7 bench (2026-09-07)

## Why this was measured

Round 43 of the native fleet (`docs/NATIVE_FLEET7.md`) found that the load
generator's ingest path had every worker's senders paying the same
recipients, so a "full" block of 163,000 transfers touched about 13,000
accounts, and every throughput number through round 42 had been measured on
that shape. With the generator fixed a full block touches ~147,000 accounts
(`created=14,196 updated=132,803`), and the fleet reads 163-168k TPS at a
0.97-1.0 s cycle instead of 396k. The question this note answers: is 147,000
accounts per 163,000 transactions a realistic shape, or another artefact?

## Method

`scripts/chainmix.py <evm|tron> <rpc url> 163000` walks back from a chain's
head until it has seen 163,000 consecutive transactions and counts, per
transaction:

- the sender,
- the `to` address (the contract, for a call),
- for an ERC-20/TRC-20 `transfer(address,uint256)` (selector `a9059cbb`) or
  `transferFrom(address,address,uint256)` (`23b872dd`) the recipient (and
  `transferFrom`'s source) decoded from the calldata.

"All distinct accounts" is the union of the three. What a contract does
inside a call -- pool reserves, other token balances, fee accounts, any
storage slot -- is invisible without traces, so every count below is a
**lower bound on the state a transaction touches**, and the bound is loose
exactly where contract calls dominate.

Endpoints: `https://ethereum-rpc.publicnode.com`, `https://bsc-rpc.publicnode.com`,
`https://polygon-bor-rpc.publicnode.com` (JSON-RPC, `eth_getBlockByNumber`
with full transactions), `https://api.trongrid.io/wallet/getblockbynum`
(TronGrid). Polygon's public endpoint rate-limited the walk at 50,000
transactions; its row is that sample and an extrapolation.

## Result

| chain | txs | blocks | plain transfers | token transfers | other calls | distinct senders | distinct `to` | distinct token recipients | all distinct accounts | per tx |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Ethereum (head 25,927,865) | 165,865 | 624 | 51,458 | 55,214 | 59,019 | 62,475 | 33,515 | 25,804 | **87,628** | 0.53 |
| BNB Chain (head 120,558,382) | 163,502 | 2,700 | 23,984 | 19,299 | 120,173 | 32,815 | 11,595 | 12,115 | **46,269** | 0.28 |
| Polygon (head 93,405,250, 50k sample) | 50,022 | 780 | 3,386 | 3,908 | 42,714 | 7,817 | 2,936 | 2,056 | 10,821 (~25k at 163k) | 0.22 |
| Tron (head 86,047,040) | 163,419 | 472 | 100,824 | 24,541 | 38,052 | 103,057 | 74,066 | 15,436 | **173,368** | 1.06 |
| N42 fleet7 bench, generator fixed | 163,000 | 1 | 163,000 | -- | -- | ~380 | ~141,000 | -- | **147,000** written | 0.90 |
| N42 fleet7 bench, generator before the fix (rounds through 42) | 163,000 | 1 | 163,000 | -- | -- | ~380 | ~13,000 | -- | ~13,400 written | 0.08 |

The fleet's rows count accounts *written* by the block's execution
(`created + updated` in the builder's log), which for plain transfers is the
same set the survey counts for the other chains (sender and recipient).

## Reading it

- **Tron** is the chain whose traffic is closest to the bench (62% plain
  TRX/TRC-10 transfers, most of the rest USDT). Its last 163,000 transactions
  touch *more* distinct accounts than there are transactions -- 173,368 --
  because most senders and most recipients appear once in the window. The
  bench's 147,000 is below that.
- **Ethereum** touches 87,628 distinct addresses by this count, but 69% of
  its transactions are contract calls whose state effects the count cannot
  see. A swap writes the pool's reserves, two token balances and a fee
  account; an ERC-20 transfer writes two storage slots plus the sender's
  nonce and balance. In state entries written, Ethereum's 163,000
  transactions are well above 147,000.
- **BNB Chain and Polygon** are dominated by bots and aggregators: few
  senders, a great many calls to the same contracts (73% and 85% "other
  calls"). By address count they are lighter than the bench's shape; by
  storage slots written they are not.

## Conclusion

147,000 state entries per 163,000 transactions is a reasonable, if anything
conservative, shape for a payments chain: Tron's real traffic is heavier in
accounts, Ethereum's is heavier in state entries, and only the bot-heavy EVM
chains are lighter by the address count. The 13,000-account shape the bench
ran on before round 43 is one no chain has, and the numbers measured on it
(365k, 396k TPS) are not comparable with anything measured after the fix.

Two things the survey does not settle: how many *new* accounts a real
block creates (the bench creates ~14,000 per block, ~9%; Tron's share of
first-seen recipients is likely higher, Ethereum's lower), and the storage
footprint of contract calls, which needs traces (`debug_traceBlock` with the
prestate tracer) rather than block bodies. Both would only raise the other
chains' numbers.

## Reproducing

```bash
python3 scripts/chainmix.py evm  https://ethereum-rpc.publicnode.com 163000
python3 scripts/chainmix.py evm  https://bsc-rpc.publicnode.com 163000
python3 scripts/chainmix.py tron https://api.trongrid.io/wallet/getblockbynum 163000
```

The bench keeps the pre-round-43 shape as a knob for comparison:
`F7_FLOOD_LEGACY_RECIPIENTS=1` (`tx_flood --legacy-recipients`) indexes the
ingest path's recipients by the worker-local sender index again, so a full
block touches ~13,000 accounts instead of ~147,000; `F7_RECIPIENTS=<n>`
sets the spread the fixed flood draws recipients from (1 = a single sink
account, 20,000, 100,000, ... 2,000,000).

The script prints checkpoints at 10k, 25k, 50k, 100k and 163k transactions,
so a rate-limited endpoint still yields a partial row. Ethereum and BNB take
15-80 s; TronGrid without an API key takes about 15 minutes.
