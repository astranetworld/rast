// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sends signed value transfers to a node's JSON-RPC, for watching them
//! travel a mixed fleet: submitted to one client, sealed by the other.
//!
//!   send_tx --rpc http://127.0.0.1:18545 --key <hex> --to <address> --count 3 [--chain-id 1143]
//!
//! Prints each transaction's hash; `eth_getTransactionReceipt` on any member
//! then says which block, and whose, sealed it.
//!
//! `--rate <tx/s>` paces the sending instead of bursting, and `--seconds <n>`
//! runs for a duration rather than a count — a fleet measured only on empty
//! blocks says nothing about the costs that scale with transactions, which on
//! gov5's fleet is where the dominant one was found.
//!
//! One key is one nonce sequence, so one process is one sender. Load comes from
//! running several against different funded accounts; two processes sharing a
//! key race its nonce and most of what they send is rejected.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde_json::{json, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rpc = "http://127.0.0.1:18545".to_string();
    let mut key = None;
    let mut to = None;
    let mut count = 1u64;
    let mut chain_id = 1143u64;
    let mut rate: Option<f64> = None;
    let mut seconds: Option<u64> = None;
    let mut quiet = false;
    let mut alg = "secp256k1".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rpc" => rpc = args.next().ok_or("--rpc needs a URL")?,
            "--key" => key = Some(args.next().ok_or("--key needs hex")?),
            "--to" => to = Some(args.next().ok_or("--to needs an address")?),
            "--count" => count = args.next().ok_or("--count needs a number")?.parse()?,
            "--chain-id" => chain_id = args.next().ok_or("--chain-id needs a number")?.parse()?,
            "--rate" => rate = Some(args.next().ok_or("--rate needs a number")?.parse()?),
            "--seconds" => seconds = Some(args.next().ok_or("--seconds needs a number")?.parse()?),
            // A sustained run prints one line per transaction otherwise, which
            // at any useful rate is its own kind of load.
            "--quiet" => quiet = true,
            "--alg" => alg = args.next().ok_or("--alg needs secp256k1 or ed25519")?,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    let key = key.ok_or("--key is required")?;
    // `--alg ed25519`: the 32-byte hex key is an Ed25519 seed, the account is
    // keccak256(0x01 || pubkey)[12..], and the transfers are 0x50 transactions.
    let ed25519 = match alg.as_str() {
        "secp256k1" => None,
        "ed25519" => {
            let seed: [u8; 32] = alloy_primitives::hex::decode(key.trim_start_matches("0x"))?
                .try_into()
                .map_err(|_| "--key for ed25519 must be 32 bytes")?;
            Some(ed25519_dalek::SigningKey::from_bytes(&seed))
        }
        other => return Err(format!("--alg {other}: secp256k1 or ed25519").into()),
    };
    let signer: PrivateKeySigner = match &ed25519 {
        None => key.parse()?,
        // Unused when signing with Ed25519; any key gives the type.
        Some(_) => PrivateKeySigner::from_bytes(&alloy_primitives::B256::repeat_byte(1))?,
    };
    let pubkey = ed25519.as_ref().map(|k| alloy_primitives::Bytes::copy_from_slice(k.verifying_key().as_bytes()));
    let from = match &pubkey {
        Some(pk) => n42_tx_types::alt_sig::sender_of(n42_tx_types::ALG_ED25519, pk),
        None => signer.address(),
    };
    let to: Address = to.ok_or("--to is required")?.parse()?;
    let client = reqwest::blocking::Client::new();
    let call = |method: &str, params: Vec<Value>| -> Result<Value, Box<dyn std::error::Error>> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let response: Value = client.post(&rpc).json(&body).send()?.json()?;
        if let Some(error) = response.get("error") {
            return Err(format!("{method}: {error}").into());
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    };
    let nonce_hex = call("eth_getTransactionCount", vec![json!(from), json!("pending")])?;
    let mut nonce = u64::from_str_radix(nonce_hex.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;

    let started = std::time::Instant::now();
    let deadline = seconds.map(|s| started + std::time::Duration::from_secs(s));
    let gap = rate.filter(|r| *r > 0.0).map(|r| std::time::Duration::from_secs_f64(1.0 / r));
    // `--seconds` runs until the clock says stop; without it, `--count` does.
    let limit = if deadline.is_some() { u64::MAX } else { count };

    let mut sent = 0u64;
    let mut rejected = 0u64;
    for index in 0..limit {
        if deadline.is_some_and(|at| std::time::Instant::now() >= at) {
            break;
        }
        if let Some(gap) = gap {
            // Paced from the start, not from the last send, so a slow node
            // does not let the sender drift and then catch up in a burst.
            let due = started + gap * u32::try_from(index).unwrap_or(u32::MAX);
            if let Some(wait) = due.checked_duration_since(std::time::Instant::now()) {
                std::thread::sleep(wait);
            }
        }
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 5_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(to),
            value: U256::from(1_000_000_000_000_000u64),
            ..Default::default()
        };
        let raw = match (&ed25519, &pubkey) {
            (Some(ed), Some(pk)) => {
                let alt = n42_tx_types::TxAltSig {
                    chain_id: tx.chain_id,
                    nonce: tx.nonce,
                    max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
                    max_fee_per_gas: tx.max_fee_per_gas,
                    gas_limit: tx.gas_limit,
                    to,
                    value: tx.value,
                    input: Default::default(),
                    access_list: Default::default(),
                    alg_type: n42_tx_types::ALG_ED25519,
                    pubkey: pk.clone(),
                };
                alloy_primitives::hex::encode_prefixed(alt.sign_ed25519(ed).encoded_2718())
            }
            _ => {
                let signature = signer.sign_hash_sync(&tx.signature_hash())?;
                let envelope: TxEnvelope = tx.into_signed(signature).into();
                alloy_primitives::hex::encode_prefixed(envelope.encoded_2718())
            }
        };
        match call("eth_sendRawTransaction", vec![json!(raw)]) {
            Ok(hash) => {
                if !quiet {
                    println!("{} nonce {nonce}", hash.as_str().unwrap_or("?"));
                }
                sent += 1;
                nonce += 1;
            }
            // A sustained sender outlives the pool's patience: once it is full
            // the node refuses, and the right answer is to keep the nonce and
            // try again rather than to stop and leave a gap nothing can fill.
            Err(err) if deadline.is_some() => {
                rejected += 1;
                if rejected % 100 == 1 {
                    eprintln!("rejected: {err}");
                }
            }
            Err(err) => return Err(err),
        }
    }
    if deadline.is_some() {
        let elapsed = started.elapsed().as_secs_f64();
        println!("sent {sent} in {elapsed:.1}s ({:.1}/s), {rejected} rejected", sent as f64 / elapsed);
    }
    Ok(())
}
