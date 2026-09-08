#!/usr/bin/env python3
"""The shape of the fleet's latest full block, for round.txt: how many senders and
distinct recipients 163,000 transfers touch, and how long each sender's run is.
Round 43 found the flood paying 13,000 recipients a block for 42 rounds before
anyone looked; every round records this line now.

usage: fleet7-shape.py <http rpc base port> [label]
"""
import json, sys, urllib.request

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8700
label = sys.argv[2] if len(sys.argv) > 2 else "shape"
url = f"http://127.0.0.1:{port}"

def rpc(m, p):
    req = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(), headers={"content-type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=120))["result"]

try:
    head = int(rpc("eth_blockNumber", []), 16)
    best = None
    for num in range(head - 1, max(head - 8, 0), -1):
        b = rpc("eth_getBlockByNumber", [hex(num), True])
        if b and len(b["transactions"]) > (len(best["transactions"]) if best else 0):
            best = b
        if best and len(best["transactions"]) >= 100_000:
            break
    if not best:
        print(f"{label:<13}: no block with transactions near {head}")
        sys.exit(0)
    txs = best["transactions"]
    froms = [t["from"] for t in txs]
    tos = [t.get("to") for t in txs]
    runs = []; cur = None; n = 0
    for f in froms:
        if f == cur:
            n += 1
        else:
            if cur is not None:
                runs.append(n)
            cur = f; n = 1
    runs.append(n); runs.sort()
    print(f"{label:<13}: block {int(best['number'],16)} txs={len(txs)} senders={len(set(froms))} distinct_recipients={len(set(tos))} "
          f"runs={len(runs)} run_median={runs[len(runs)//2]} run_max={runs[-1]} gasUsed={int(best['gasUsed'],16)}")
except Exception as e:  # a round must not die on its shape line
    print(f"{label:<13}: unavailable ({e})")
