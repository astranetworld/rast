#!/usr/bin/env python3
"""Distinct accounts touched by the most recent N consecutive transactions of a chain.

EVM chains via JSON-RPC (eth_getBlockByNumber, full transactions), Tron via TronGrid
(/wallet/getblockbynum). Counted per transaction: the sender, the `to` address, and for
ERC-20/TRC-20 transfer(address,uint256) / transferFrom calls the token recipient (and
transferFrom's source). Contract-internal effects (other storage, internal calls) are
not visible without traces, so the count is a lower bound on state touched.
"""
import json, sys, time, urllib.request, concurrent.futures as cf

kind, url, target = sys.argv[1], sys.argv[2], int(sys.argv[3])
checkpoints = [10_000, 25_000, 50_000, 100_000, 163_000]

def post(body, tries=6):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"content-type": "application/json", "user-agent": "n42-chainmix/1"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except Exception as e:
            time.sleep(1.5 * (i + 1))
    raise RuntimeError("rpc failed")

def evm_block(n):
    r = post({"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber", "params": [hex(n), True]})
    return r["result"]

def tron_block(n):
    return post({"num": n})

def erc20_targets(data):
    """Recipient (and source for transferFrom) of a token transfer calldata, hex without 0x."""
    if not data or len(data) < 8:
        return []
    sel = data[:8]
    if sel == "a9059cbb" and len(data) >= 8 + 64:            # transfer(to, amount)
        return [data[8 + 24:8 + 64]]
    if sel == "23b872dd" and len(data) >= 8 + 128:           # transferFrom(from, to, amount)
        return [data[8 + 24:8 + 64], data[72 + 24:72 + 64]]
    return []

senders, recipients, token_to, all_acc = set(), set(), set(), set()
n_tx = n_plain = n_token = n_call = n_create = 0
next_cp = 0
t0 = time.time()

def report(label):
    print(f"{label}: txs={n_tx} plain_transfers={n_plain} token_transfers={n_token} other_calls={n_call} creates={n_create} "
          f"distinct: senders={len(senders)} recipients(to)={len(recipients)} token_recipients={len(token_to)} "
          f"all_accounts={len(all_acc)} ratio={len(all_acc)/max(n_tx,1):.3f} elapsed={time.time()-t0:.0f}s", flush=True)

if kind == "evm":
    head = int(post({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []})["result"], 16)
    n = head - 2
    blocks = 0
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        while n_tx < target:
            nums = list(range(n, n - 12, -1))
            n -= 12
            for b in ex.map(evm_block, nums):
                if b is None:
                    continue
                blocks += 1
                for tx in b["transactions"]:
                    n_tx += 1
                    f = tx["from"].lower(); senders.add(f); all_acc.add(f)
                    to = tx.get("to")
                    data = (tx.get("input") or "0x")[2:]
                    if to is None:
                        n_create += 1; continue
                    to = to.lower(); recipients.add(to); all_acc.add(to)
                    if data == "":
                        n_plain += 1
                    else:
                        tg = erc20_targets(data)
                        if tg:
                            n_token += 1
                            for a in tg:
                                a = "0x" + a; token_to.add(a); all_acc.add(a)
                        else:
                            n_call += 1
            while next_cp < len(checkpoints) and n_tx >= checkpoints[next_cp]:
                report(f"checkpoint {checkpoints[next_cp]} (blocks {blocks}, head {head})"); next_cp += 1
    report(f"final (blocks {blocks}, from {head} back to {n})")
else:
    head = tron_block_num = post({})["block_header"]["raw_data"]["number"] if False else None
    now = post({}) if False else None
    # TronGrid: getnowblock via a different path
    req = urllib.request.Request(url.replace("getblockbynum", "getnowblock"), data=b"{}", headers={"content-type": "application/json"})
    head = json.load(urllib.request.urlopen(req, timeout=60))["block_header"]["raw_data"]["number"]
    n = head - 2
    blocks = 0
    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        while n_tx < target:
            nums = list(range(n, n - 8, -1))
            n -= 8
            for b in ex.map(tron_block, nums):
                blocks += 1
                for tx in b.get("transactions", []):
                    c = tx["raw_data"]["contract"][0]
                    v = c["parameter"]["value"]; typ = c["type"]
                    n_tx += 1
                    f = v.get("owner_address", "").lower(); senders.add(f); all_acc.add(f)
                    if typ == "TransferContract" or typ == "TransferAssetContract":
                        to = v.get("to_address", "").lower(); recipients.add(to); all_acc.add(to); n_plain += 1
                    elif typ == "TriggerSmartContract":
                        to = v.get("contract_address", "").lower(); recipients.add(to); all_acc.add(to)
                        tg = erc20_targets(v.get("data", ""))
                        if tg:
                            n_token += 1
                            for a in tg:
                                a = "41" + a; token_to.add(a); all_acc.add(a)
                        else:
                            n_call += 1
                    elif typ == "CreateSmartContract":
                        n_create += 1
                    else:
                        n_call += 1
            while next_cp < len(checkpoints) and n_tx >= checkpoints[next_cp]:
                report(f"checkpoint {checkpoints[next_cp]} (blocks {blocks}, head {head})"); next_cp += 1
    report(f"final (blocks {blocks}, from {head} back to {n})")
