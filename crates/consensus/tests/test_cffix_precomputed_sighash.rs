//! cffix-rustoshi-precomputed-sighash: the BIP-143 / BIP-341 whole-tx digests
//! are hashed once per transaction, not once per signature.
//!
//! Core builds one `PrecomputedTransactionData` per transaction
//! (`src/script/interpreter.cpp`, `PrecomputedTransactionData::Init`) and every
//! `SignatureHash` / `SignatureHashSchnorr` reads `hashPrevouts`,
//! `hashSequence`, `hashOutputs` and the BIP-341 `sha_*` digests from it.
//! Without that cache, every signature re-serializes and re-hashes every input
//! and output of its transaction, so an N-input transaction costs O(N^2)
//! hashing in block connect and in mempool accept.
//!
//! Instrument: a counting global allocator. Every whole-tx digest builds its
//! serialization in a heap buffer (36 bytes per input for prevouts, 4 for
//! sequences, 8 + script for amounts / scriptPubKeys), so the bytes allocated
//! while validating one N-input transaction grow like N^2 without the cache
//! and like N with it. The test validates the same shape of transaction at N
//! and 2N inputs through the production block-connect entry point
//! (`validate_scripts_parallel_with_n_workers`) and asserts the ratio is
//! linear (about 2), not quadratic (about 4).
//!
//! The sighash bytes are consensus, so this file also checks Core's
//! `bip341_wallet_vectors.json` byte for byte (sigMsg and sigHash for every
//! key-path input) and validates its fully signed transaction, which mixes
//! P2TR key-path inputs of every hash type with a P2WPKH (BIP-143) input and a
//! legacy P2PKH input, through the block path; and a corrupted signature in
//! that transaction must still be rejected.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use rustoshi_consensus::{validate_scripts_parallel_with_n_workers, CoinEntry, ScriptFlags};
use rustoshi_crypto::taproot::{build_sig_msg, compute_taproot_sighash, TaprootPrevouts};
use rustoshi_primitives::{
    Block, BlockHeader, Decodable, Encodable, Hash256, OutPoint, Transaction, TxIn, TxOut,
};
use secp256k1::{Keypair, Message, Scalar, Secp256k1, SecretKey};

// ---------------------------------------------------------------------------
// Counting allocator
// ---------------------------------------------------------------------------

struct Counting;

static ALLOCATED: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            ALLOCATED.fetch_add((new_size - layout.size()) as u64, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// The allocator counter is process-wide; tests in this file take this lock
/// so a measurement never overlaps another test's allocations.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn flags() -> ScriptFlags {
    ScriptFlags {
        verify_p2sh: true,
        verify_dersig: true,
        verify_checklocktimeverify: true,
        verify_checksequenceverify: true,
        verify_witness: true,
        verify_nulldummy: true,
        verify_taproot: true,
        ..Default::default()
    }
}

fn block_of(spend: Transaction) -> Block {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x03, 0x01, 0x00, 0x00],
            sequence: 0xFFFF_FFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 5_000_000_000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    Block {
        header: BlockHeader {
            version: 0x20000000,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: 1_700_000_000,
            bits: 0x207fffff,
            nonce: 0,
        },
        transactions: vec![coinbase, spend],
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    P2wpkh,
    P2tr,
}

/// An `n`-input transaction spending `kind` outputs of one key, every input
/// signed SIGHASH_ALL (P2WPKH) / SIGHASH_DEFAULT (P2TR), plus its coins.
///
/// Signed with the code under test, so it only measures scaling; the
/// Core-signed vector tests below are the sighash correctness guard.
fn signed_spend(kind: Kind, n: usize) -> (Block, Vec<Vec<CoinEntry>>) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let pk = sk.public_key(&secp);
    let pk_bytes = pk.serialize();
    let pkh = rustoshi_crypto::hash160(&pk_bytes);

    // P2TR key-path: output key = internal key tweaked with TapTweak(P).
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (internal, _) = keypair.x_only_public_key();
    let tweak = rustoshi_crypto::tagged_hash("TapTweak", &internal.serialize());
    let tweaked = keypair
        .add_xonly_tweak(&secp, &Scalar::from_be_bytes(tweak).unwrap())
        .unwrap();
    let (output_key, _) = tweaked.x_only_public_key();

    let spk: Vec<u8> = match kind {
        Kind::P2wpkh => {
            let mut s = vec![0x00, 0x14];
            s.extend_from_slice(&pkh.0);
            s
        }
        Kind::P2tr => {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&output_key.serialize());
            s
        }
    };
    let value = 10_000u64;

    let mut tx = Transaction {
        version: 2,
        inputs: (0..n)
            .map(|i| {
                let mut txid = [0x5au8; 32];
                txid[0] = (i & 0xff) as u8;
                txid[1] = (i >> 8) as u8;
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256(txid),
                        vout: i as u32,
                    },
                    script_sig: vec![],
                    sequence: 0xFFFF_FFFD,
                    witness: vec![],
                }
            })
            .collect(),
        outputs: vec![TxOut {
            value: 1000,
            script_pubkey: vec![
                0x00, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            ],
        }],
        lock_time: 0,
    };

    let amounts = vec![value; n];
    let scripts: Vec<Vec<u8>> = vec![spk.clone(); n];
    let script_refs: Vec<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();
    let mut witnesses = Vec::with_capacity(n);
    for i in 0..n {
        let w = match kind {
            Kind::P2wpkh => {
                let code = rustoshi_crypto::p2wpkh_script_code(&pkh.0);
                let h = rustoshi_crypto::segwit_v0_sighash(&tx, i, &code, value, 0x01);
                let sig = secp.sign_ecdsa(&Message::from_digest(h.0), &sk);
                let mut der = sig.serialize_der().to_vec();
                der.push(0x01);
                vec![der, pk_bytes.to_vec()]
            }
            Kind::P2tr => {
                let prev = TaprootPrevouts {
                    amounts: &amounts,
                    scripts: &script_refs,
                };
                let h = compute_taproot_sighash(&tx, i, prev, 0x00, None, None).unwrap();
                let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(h), &tweaked);
                vec![sig.as_ref().to_vec()]
            }
        };
        witnesses.push(w);
    }
    for (inp, w) in tx.inputs.iter_mut().zip(witnesses) {
        inp.witness = w;
    }

    let coins = vec![(0..n)
        .map(|_| CoinEntry {
            height: 1,
            is_coinbase: false,
            value,
            script_pubkey: spk.clone(),
        })
        .collect::<Vec<_>>()];
    (block_of(tx), coins)
}

/// Bytes allocated while the block path validates `block` (1 worker).
fn bytes_to_validate(block: &Block, coins: &[Vec<CoinEntry>]) -> u64 {
    let before = ALLOCATED.load(Ordering::SeqCst);
    let r = validate_scripts_parallel_with_n_workers(1, block, coins, &flags(), None);
    let after = ALLOCATED.load(Ordering::SeqCst);
    assert!(r.is_ok(), "validly signed spend must validate: {r:?}");
    after - before
}

// ---------------------------------------------------------------------------
// The finding
// ---------------------------------------------------------------------------

/// Doubling the inputs of a transaction must about double the sighash work,
/// for BIP-143 (P2WPKH) and for BIP-341 (P2TR key-path) alike.
#[test]
fn sighash_midstate_computed_once_per_tx() {
    let _g = serial();
    const N: usize = 300;
    for kind in [Kind::P2wpkh, Kind::P2tr] {
        let (b1, c1) = signed_spend(kind, N);
        let (b2, c2) = signed_spend(kind, 2 * N);
        // Warm the script-check machinery once so one-time setup is not
        // charged to the first measurement.
        let _ = bytes_to_validate(&b1, &c1);
        let a1 = bytes_to_validate(&b1, &c1);
        let a2 = bytes_to_validate(&b2, &c2);
        let ratio = a2 as f64 / a1 as f64;
        eprintln!(
            "{kind:?}: {N} inputs -> {a1} B ({} B/input), {} inputs -> {a2} B ({} B/input), ratio {ratio:.2}",
            a1 / N as u64,
            2 * N,
            a2 / (2 * N) as u64
        );
        assert!(
            ratio < 2.5,
            "{kind:?}: validating {} inputs allocated {ratio:.2}x the bytes of {N} inputs \
             (linear = 2, quadratic = 4): the whole-tx sighash digests are being rebuilt \
             per signature instead of once per transaction (Core PrecomputedTransactionData)",
            2 * N
        );
    }
}

// ---------------------------------------------------------------------------
// Consensus bytes: Core's BIP-341 wallet vectors
// ---------------------------------------------------------------------------

fn vectors() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/bip341_wallet_vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// sigMsg and sigHash for every keyPathSpending input, byte for byte.
#[test]
fn bip341_wallet_vectors_sighash_byte_identical() {
    let _g = serial();
    let v = vectors();
    let mut checked = 0;
    for case in v["keyPathSpending"].as_array().unwrap() {
        let given = &case["given"];
        let raw = hex::decode(given["rawUnsignedTx"].as_str().unwrap()).unwrap();
        let tx = Transaction::decode(&mut raw.as_slice()).unwrap();
        let utxos = given["utxosSpent"].as_array().unwrap();
        let amounts: Vec<u64> = utxos
            .iter()
            .map(|u| u["amountSats"].as_u64().unwrap())
            .collect();
        let scripts: Vec<Vec<u8>> = utxos
            .iter()
            .map(|u| hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap())
            .collect();
        let refs: Vec<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();
        for inp in case["inputSpending"].as_array().unwrap() {
            let idx = inp["given"]["txinIndex"].as_u64().unwrap() as usize;
            let ht = inp["given"]["hashType"].as_u64().unwrap() as u8;
            let prev = || TaprootPrevouts {
                amounts: &amounts,
                scripts: &refs,
            };
            let msg = build_sig_msg(&tx, idx, prev(), ht, None, None).unwrap();
            let h = compute_taproot_sighash(&tx, idx, prev(), ht, None, None).unwrap();
            assert_eq!(
                hex::encode(&msg),
                inp["intermediary"]["sigMsg"].as_str().unwrap(),
                "sigMsg input {idx} hashType {ht:#x}"
            );
            assert_eq!(
                hex::encode(h),
                inp["intermediary"]["sigHash"].as_str().unwrap(),
                "sigHash input {idx} hashType {ht:#x}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 7, "all 7 keyPathSpending inputs checked");
}

fn vector_signed_block() -> (Block, Vec<Vec<CoinEntry>>) {
    let v = vectors();
    let case = &v["keyPathSpending"][0];
    let raw = hex::decode(case["auxiliary"]["fullySignedTx"].as_str().unwrap()).unwrap();
    let tx = Transaction::decode(&mut raw.as_slice()).unwrap();
    let mut reser = Vec::new();
    tx.encode(&mut reser).unwrap();
    assert_eq!(reser, raw, "fullySignedTx round-trips");
    let coins = case["given"]["utxosSpent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| CoinEntry {
            height: 1,
            is_coinbase: false,
            value: u["amountSats"].as_u64().unwrap(),
            script_pubkey: hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap(),
        })
        .collect::<Vec<_>>();
    assert_eq!(coins.len(), tx.inputs.len());
    (block_of(tx), vec![coins])
}

/// Core's fully signed 9-input transaction (P2TR key-path with DEFAULT, ALL,
/// NONE, SINGLE and ANYONECANPAY variants, plus P2WPKH and P2PKH inputs)
/// validates through the block path, which shares one sighash cache across
/// all its inputs.
#[test]
fn bip341_fully_signed_tx_validates_through_shared_cache() {
    let _g = serial();
    let (block, coins) = vector_signed_block();
    let has_wpkh = coins[0]
        .iter()
        .any(|c| c.script_pubkey.len() == 22 && c.script_pubkey[0] == 0);
    let has_pkh = coins[0]
        .iter()
        .any(|c| c.script_pubkey.len() == 25 && c.script_pubkey[0] == 0x76);
    assert!(
        has_wpkh && has_pkh,
        "vector covers BIP-143 and legacy inputs too"
    );
    for workers in [1, 4] {
        let r = validate_scripts_parallel_with_n_workers(workers, &block, &coins, &flags(), None);
        assert!(r.is_ok(), "{workers} workers: {r:?}");
    }
}

/// Negative control: the same transaction with one byte of one signature
/// flipped is rejected, at every input kind (P2TR, P2WPKH, P2PKH). Shows the
/// test above can see a bad signature.
#[test]
fn bip341_fully_signed_tx_corrupted_sig_rejected() {
    let _g = serial();
    let (block, coins) = vector_signed_block();
    let mut rejected = 0;
    for i in 0..block.transactions[1].inputs.len() {
        let mut b = block.clone();
        let inp = &mut b.transactions[1].inputs[i];
        if let Some(sig) = inp.witness.first_mut().filter(|s| !s.is_empty()) {
            sig[10] ^= 0x01;
        } else if inp.script_sig.len() > 12 {
            inp.script_sig[12] ^= 0x01;
        } else {
            continue;
        }
        let r = validate_scripts_parallel_with_n_workers(1, &b, &coins, &flags(), None);
        assert!(r.is_err(), "input {i}: corrupted signature accepted");
        rejected += 1;
    }
    assert!(rejected >= 8, "corrupted {rejected} inputs");
}

// ---------------------------------------------------------------------------
// Consensus bytes: BIP-143 under every hash type
// ---------------------------------------------------------------------------

/// BIP-143's P2SH-P2WSH 6-of-6 example as Core ships it in
/// `src/test/data/tx_valid.json` ("BIP143 example: P2SH-P2WSH 6-of-6 multisig
/// signed with 6 different SIGHASH types"): ALL, NONE, SINGLE, ALL|ACP,
/// NONE|ACP, SINGLE|ACP, each signature over a different BIP-143 sighash.
const BIP143_6OF6_TX: &str = "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000";

fn bip143_6of6_block() -> (Block, Vec<Vec<CoinEntry>>) {
    let raw = hex::decode(BIP143_6OF6_TX).unwrap();
    let tx = Transaction::decode(&mut raw.as_slice()).unwrap();
    // prevout: HASH160 0x14 0x9993a429037b5d912407a71c252019287b8d27a5 EQUAL, 987654321 sat
    let spk = hex::decode("a9149993a429037b5d912407a71c252019287b8d27a587").unwrap();
    let coins = vec![vec![CoinEntry {
        height: 1,
        is_coinbase: false,
        value: 987_654_321,
        script_pubkey: spk,
    }]];
    (block_of(tx), coins)
}

/// The six Core-made signatures, one per BIP-143 hash type, all verify
/// through the shared cache; flipping one byte of any one of them rejects.
#[test]
fn bip143_six_hash_types_through_shared_cache() {
    let _g = serial();
    let (block, coins) = bip143_6of6_block();
    let r = validate_scripts_parallel_with_n_workers(1, &block, &coins, &flags(), None);
    assert!(r.is_ok(), "Core-signed 6-of-6 must validate: {r:?}");

    let hash_types: Vec<u8> = block.transactions[1].inputs[0].witness[1..7]
        .iter()
        .map(|s| *s.last().unwrap())
        .collect();
    assert_eq!(hash_types, vec![0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

    for k in 1..=6 {
        let mut b = block.clone();
        b.transactions[1].inputs[0].witness[k][10] ^= 0x01;
        let r = validate_scripts_parallel_with_n_workers(1, &b, &coins, &flags(), None);
        assert!(
            r.is_err(),
            "signature {k} (hash type {:#x}) corrupted but accepted",
            hash_types[k - 1]
        );
    }
}
