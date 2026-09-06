// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: Apache-2.0

//! Signature verification / recovery micro-benchmark for the fleet7 host.
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

const SAMPLES: usize = 2048; // distinct (key, msg, sig) tuples cycled through
const PAR_THREADS: usize = 20; // the fleet's recovery slots per node

fn time_one<F: FnMut(usize)>(name: &str, sig_bytes: usize, pk_bytes: usize, mut f: F) -> f64 {
    // warm
    for i in 0..256 { f(i % SAMPLES); }
    let mut best = f64::MAX;
    for _ in 0..5 {
        let n = 2000;
        let t = Instant::now();
        for i in 0..n { f(i % SAMPLES); }
        let us = t.elapsed().as_secs_f64() * 1e6 / n as f64;
        if us < best { best = us; }
    }
    println!("{:<44} {:>9.2} us/op  {:>10.0} op/s/thread   sig {:>5} B  pk {:>5} B", name, best, 1e6 / best, sig_bytes, pk_bytes);
    best
}

fn time_par<F: Fn(usize) + Sync>(name: &str, f: F) {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(PAR_THREADS).build().unwrap();
    let total = std::sync::atomic::AtomicU64::new(0);
    let dur = Duration::from_millis(800);
    pool.scope(|s| {
        for t in 0..PAR_THREADS {
            let total = &total; let f = &f;
            s.spawn(move |_| {
                let start = Instant::now(); let mut n = 0u64; let mut i = t * 97;
                while start.elapsed() < dur { for _ in 0..64 { f(i % SAMPLES); i += 1; } n += 64; }
                total.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    let ops = total.load(std::sync::atomic::Ordering::Relaxed) as f64 / dur.as_secs_f64();
    println!("{:<44} {:>10.0} op/s on {} threads ({:.1} us/op effective per thread)", name, ops, PAR_THREADS, PAR_THREADS as f64 * 1e6 / ops);
}

fn digests(rng: &mut StdRng) -> Vec<[u8; 32]> {
    (0..SAMPLES).map(|_| { let mut d = [0u8; 32]; rng.fill_bytes(&mut d); d }).collect()
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    let msgs = digests(&mut rng);
    println!("threads for parallel rows: {PAR_THREADS}; samples per scheme: {SAMPLES}\n");

    // ---------- baselines ----------
    {
        use sha3::{Digest, Keccak256};
        let bufs: Vec<Vec<u8>> = (0..SAMPLES).map(|_| { let mut b = vec![0u8; 110]; rng.fill_bytes(&mut b); b }).collect();
        time_one("keccak256 of a 110 B transaction", 0, 0, |i| { std::hint::black_box(Keccak256::digest(&bufs[i])); });
    }

    // ---------- secp256k1 ECDSA via libsecp256k1 (what reth uses) ----------
    {
        use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SecretKey, PublicKey};
        let secp = Secp256k1::new();
        let keys: Vec<(SecretKey, PublicKey)> = (0..SAMPLES).map(|_| { let sk = SecretKey::new(&mut rng); (sk, PublicKey::from_secret_key(&secp, &sk)) }).collect();
        let sigs: Vec<RecoverableSignature> = (0..SAMPLES).map(|i| secp.sign_ecdsa_recoverable(&Message::from_digest(msgs[i]), &keys[i].0)).collect();
        let std_sigs: Vec<secp256k1::ecdsa::Signature> = sigs.iter().map(|s| s.to_standard()).collect();
        time_one("secp256k1 ECDSA recover (libsecp256k1)", 65, 0, |i| { std::hint::black_box(secp.recover_ecdsa(&Message::from_digest(msgs[i]), &sigs[i]).unwrap()); });
        time_one("secp256k1 ECDSA verify, pk given (libsecp256k1)", 64, 33, |i| { secp.verify_ecdsa(&Message::from_digest(msgs[i]), &std_sigs[i], &keys[i].1).unwrap(); });
        time_par("secp256k1 ECDSA recover (libsecp256k1) parallel", |i| { std::hint::black_box(secp.recover_ecdsa(&Message::from_digest(msgs[i]), &sigs[i]).unwrap()); });
    }

    // ---------- secp256k1 ECDSA via k256 (pure Rust) ----------
    {
        use k256::ecdsa::{SigningKey, VerifyingKey, Signature, RecoveryId};
        let keys: Vec<SigningKey> = (0..SAMPLES).map(|_| SigningKey::random(&mut rng)).collect();
        let sigs: Vec<(Signature, RecoveryId)> = (0..SAMPLES).map(|i| keys[i].sign_prehash_recoverable(&msgs[i]).unwrap()).collect();
        time_one("secp256k1 ECDSA recover (k256 pure Rust)", 65, 0, |i| { std::hint::black_box(VerifyingKey::recover_from_prehash(&msgs[i], &sigs[i].0, sigs[i].1).unwrap()); });
    }

    // ---------- secp256k1 Schnorr BIP-340 (k256) ----------
    {
        use k256::schnorr::{SigningKey, VerifyingKey, Signature};
        let keys: Vec<SigningKey> = (0..SAMPLES).map(|_| SigningKey::random(&mut rng)).collect();
        let vks: Vec<VerifyingKey> = keys.iter().map(|k| *k.verifying_key()).collect();
        let sigs: Vec<Signature> = (0..SAMPLES).map(|i| keys[i].sign_raw(&msgs[i], &[0u8; 32]).unwrap()).collect();
        time_one("secp256k1 Schnorr BIP-340 verify (k256)", 64, 32, |i| { vks[i].verify_raw(&msgs[i], &sigs[i]).unwrap(); });
    }

    // ---------- P-256 ECDSA (RIP-7212 precompile curve) ----------
    {
        use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::hazmat::{PrehashSigner, PrehashVerifier}};
        let keys: Vec<SigningKey> = (0..SAMPLES).map(|_| SigningKey::random(&mut rng)).collect();
        let vks: Vec<VerifyingKey> = keys.iter().map(|k| *k.verifying_key()).collect();
        let sigs: Vec<Signature> = (0..SAMPLES).map(|i| keys[i].sign_prehash(&msgs[i]).unwrap()).collect();
        time_one("P-256 ECDSA verify (p256 pure Rust)", 64, 33, |i| { vks[i].verify_prehash(&msgs[i], &sigs[i]).unwrap(); });
    }

    // ---------- Ed25519 ----------
    {
        use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
        let keys: Vec<SigningKey> = (0..SAMPLES).map(|_| SigningKey::generate(&mut rng)).collect();
        let vks: Vec<VerifyingKey> = keys.iter().map(|k| k.verifying_key()).collect();
        let sigs: Vec<Signature> = (0..SAMPLES).map(|i| keys[i].sign(&msgs[i])).collect();
        let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| &m[..]).collect();
        time_one("Ed25519 verify (dalek)", 64, 32, |i| { vks[i].verify(&msgs[i], &sigs[i]).unwrap(); });
        time_one("Ed25519 verify_strict (dalek)", 64, 32, |i| { vks[i].verify_strict(&msgs[i], &sigs[i]).unwrap(); });
        for &b in &[16usize, 64, 256] {
            let name = format!("Ed25519 batch verify, per sig (batch {b})");
            let mut best = f64::MAX;
            for _ in 0..5 {
                let t = Instant::now(); let rounds = 2048 / b;
                for r in 0..rounds { let s = r * b; ed25519_dalek::verify_batch(&msg_refs[s..s + b], &sigs[s..s + b], &vks[s..s + b]).unwrap(); }
                let us = t.elapsed().as_secs_f64() * 1e6 / (rounds * b) as f64; if us < best { best = us; }
            }
            println!("{:<44} {:>9.2} us/op  {:>10.0} op/s/thread", name, best, 1e6 / best);
        }
        time_par("Ed25519 verify (dalek) parallel", |i| { vks[i].verify(&msgs[i], &sigs[i]).unwrap(); });
        time_par("Ed25519 batch-64 verify parallel (per sig)", |i| { let s = (i / 64) * 64; let s = s.min(SAMPLES - 64); ed25519_dalek::verify_batch(&msg_refs[s..s + 64], &sigs[s..s + 64], &vks[s..s + 64]).unwrap(); });
        println!("   (the parallel batch row above counts 1 op = 64 signatures; multiply op/s by 64)");
    }

    // ---------- BLS12-381 (blst, min_pk: 48 B pk, 96 B sig) ----------
    {
        use blst::min_pk::{SecretKey, PublicKey, Signature, AggregateSignature};
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let keys: Vec<SecretKey> = (0..SAMPLES).map(|_| { let mut ikm = [0u8; 32]; rng.fill_bytes(&mut ikm); SecretKey::key_gen(&ikm, &[]).unwrap() }).collect();
        let pks: Vec<PublicKey> = keys.iter().map(|k| k.sk_to_pk()).collect();
        let sigs: Vec<Signature> = (0..SAMPLES).map(|i| keys[i].sign(&msgs[i], dst, &[])).collect();
        time_one("BLS12-381 single verify (blst)", 96, 48, |i| { assert_eq!(sigs[i].verify(true, &msgs[i], dst, &[], &pks[i], true), blst::BLST_ERROR::BLST_SUCCESS); });
        for &b in &[64usize, 256] {
            let s = 0; let agg = AggregateSignature::aggregate(&sigs[s..s + b].iter().collect::<Vec<_>>(), true).unwrap().to_signature();
            let pk_refs: Vec<&PublicKey> = pks[s..s + b].iter().collect(); let m_refs: Vec<&[u8]> = msgs[s..s + b].iter().map(|m| &m[..]).collect();
            let mut best = f64::MAX;
            for _ in 0..5 { let t = Instant::now(); for _ in 0..8 { assert_eq!(agg.aggregate_verify(true, &m_refs, dst, &pk_refs, true), blst::BLST_ERROR::BLST_SUCCESS); } let us = t.elapsed().as_secs_f64() * 1e6 / (8 * b) as f64; if us < best { best = us; } }
            println!("{:<44} {:>9.2} us/op  {:>10.0} op/s/thread   (distinct messages, aggregate sig 96 B)", format!("BLS12-381 aggregate verify per sig (n={b})"), best, 1e6 / best);
        }
        // same message (committee-style) fast aggregate verify
        let same = msgs[0]; let same_sigs: Vec<Signature> = keys[..512].iter().map(|k| k.sign(&same, dst, &[])).collect();
        let agg = AggregateSignature::aggregate(&same_sigs.iter().collect::<Vec<_>>(), true).unwrap().to_signature();
        let pk_refs: Vec<&PublicKey> = pks[..512].iter().collect();
        let mut best = f64::MAX;
        for _ in 0..5 { let t = Instant::now(); for _ in 0..16 { assert_eq!(agg.fast_aggregate_verify(true, &same, dst, &pk_refs), blst::BLST_ERROR::BLST_SUCCESS); } let us = t.elapsed().as_secs_f64() * 1e6 / 16.0; if us < best { best = us; } }
        println!("{:<44} {:>9.2} us total for 512 signers (one message)", "BLS12-381 fast_aggregate_verify (n=512)", best);
        time_par("BLS12-381 single verify (blst) parallel", |i| { assert_eq!(sigs[i].verify(true, &msgs[i], dst, &[], &pks[i], true), blst::BLST_ERROR::BLST_SUCCESS); });
    }

    // ---------- ML-DSA (FIPS 204) ----------
    {
        use fips204::traits::{Signer, Verifier, SerDes};
        {
            use fips204::ml_dsa_44 as m;
            let kp: Vec<(m::PublicKey, m::PrivateKey)> = (0..256).map(|_| m::try_keygen().unwrap()).collect();
            let sigs: Vec<_> = (0..256).map(|i| kp[i].1.try_sign(&msgs[i], &[]).unwrap()).collect();
            let (pkl, sl) = (kp[0].0.clone().into_bytes().len(), sigs[0].len());
            time_one("ML-DSA-44 verify (fips204 pure Rust)", sl, pkl, |i| { let i = i % 256; assert!(kp[i].0.verify(&msgs[i], &sigs[i], &[])); });
            time_par("ML-DSA-44 verify parallel", |i| { let i = i % 256; assert!(kp[i].0.verify(&msgs[i], &sigs[i], &[])); });
        }
        {
            use fips204::ml_dsa_65 as m;
            let kp: Vec<(m::PublicKey, m::PrivateKey)> = (0..256).map(|_| m::try_keygen().unwrap()).collect();
            let sigs: Vec<_> = (0..256).map(|i| kp[i].1.try_sign(&msgs[i], &[]).unwrap()).collect();
            let (pkl, sl) = (kp[0].0.clone().into_bytes().len(), sigs[0].len());
            time_one("ML-DSA-65 verify (fips204 pure Rust)", sl, pkl, |i| { let i = i % 256; assert!(kp[i].0.verify(&msgs[i], &sigs[i], &[])); });
        }
    }

    // ---------- Falcon (FN-DSA) via PQClean C ----------
    {
        use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};
        {
            use pqcrypto_falcon::falcon512 as f;
            let kp: Vec<(f::PublicKey, f::SecretKey)> = (0..256).map(|_| f::keypair()).collect();
            let sigs: Vec<f::DetachedSignature> = (0..256).map(|i| f::detached_sign(&msgs[i], &kp[i].1)).collect();
            let (pkl, sl) = (kp[0].0.as_bytes().len(), sigs[0].as_bytes().len());
            time_one("Falcon-512 verify (PQClean C, AVX2)", sl, pkl, |i| { let i = i % 256; f::verify_detached_signature(&sigs[i], &msgs[i], &kp[i].0).unwrap(); });
            time_par("Falcon-512 verify parallel", |i| { let i = i % 256; f::verify_detached_signature(&sigs[i], &msgs[i], &kp[i].0).unwrap(); });
            let t = Instant::now(); for i in 0..64 { std::hint::black_box(f::detached_sign(&msgs[i], &kp[i].1)); }
            println!("{:<44} {:>9.2} us/op  (signing, for reference)", "Falcon-512 sign", t.elapsed().as_secs_f64() * 1e6 / 64.0);
        }
        {
            use pqcrypto_falcon::falcon1024 as f;
            let kp: Vec<(f::PublicKey, f::SecretKey)> = (0..64).map(|_| f::keypair()).collect();
            let sigs: Vec<f::DetachedSignature> = (0..64).map(|i| f::detached_sign(&msgs[i], &kp[i].1)).collect();
            let (pkl, sl) = (kp[0].0.as_bytes().len(), sigs[0].as_bytes().len());
            time_one("Falcon-1024 verify (PQClean C, AVX2)", sl, pkl, |i| { let i = i % 64; f::verify_detached_signature(&sigs[i], &msgs[i], &kp[i].0).unwrap(); });
        }
    }

    // ---------- SLH-DSA (FIPS 205), hash-based ----------
    {
        use fips205::traits::{Signer, Verifier, SerDes};
        use fips205::slh_dsa_shake_128f as s;
        let kp: Vec<(s::PublicKey, s::PrivateKey)> = (0..16).map(|_| s::try_keygen().unwrap()).collect();
        let sigs: Vec<_> = (0..16).map(|i| kp[i].1.try_sign(&msgs[i], &[], true).unwrap()).collect();
        let (pkl, sl) = (kp[0].0.clone().into_bytes().len(), sigs[0].len());
        time_one("SLH-DSA-SHAKE-128f verify (fips205)", sl, pkl, |i| { let i = i % 16; assert!(kp[i].0.verify(&msgs[i], &sigs[i], &[])); });
    }
}
