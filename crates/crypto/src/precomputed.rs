//! Per-transaction sighash midstates (Core's `PrecomputedTransactionData`).
//!
//! BIP-143 (`hashPrevouts`, `hashSequence`, `hashOutputs`) and BIP-341
//! (`sha_prevouts`, `sha_amounts`, `sha_scriptpubkeys`, `sha_sequences`,
//! `sha_outputs`) digest every input or every output of the transaction.
//! They are the same for every signature in that transaction, so hashing
//! them once per signature makes sighash work O(sigs x tx size). Core
//! computes them once per transaction in
//! `PrecomputedTransactionData::Init` (`src/script/interpreter.cpp`) and
//! every `SignatureHash` call reads the cache.
//!
//! This type does the same. Each group is computed lazily on first use
//! (a legacy-only transaction never pays for it) and at most once, via
//! `OnceLock`, so one instance can be shared by the parallel script-check
//! workers that verify the inputs of one transaction.
//!
//! As in Core, the BIP-143 double hashes are derived from the BIP-341
//! single hashes: `hashPrevouts = SHA256(sha_prevouts)` because
//! `sha256d(x) = SHA256(SHA256(x))` and both BIPs serialize outpoints,
//! sequences and outputs identically.
//!
//! The sighash bytes are consensus. The free functions
//! [`crate::segwit_v0_sighash`] and [`crate::taproot::build_sig_msg`] are
//! thin wrappers that build a fresh instance, so there is exactly one
//! preimage builder for each sighash version.

use std::cell::Cell;
use std::sync::OnceLock;

use crate::hashes::sha256;
use crate::taproot::write_compact_size;
use rustoshi_primitives::{Hash256, Transaction};

thread_local! {
    static MIDSTATE_COMPUTATIONS: Cell<u64> = const { Cell::new(0) };
}

/// Number of per-transaction midstate groups computed on this thread so far.
///
/// Incremented once each time the shared group (prevouts, sequences,
/// outputs) or the BIP-341 spent-output group (amounts, scriptPubKeys) is
/// hashed. Test hook: with the cache in place this grows with the number
/// of transactions, not with the number of signatures.
pub fn midstate_computations() -> u64 {
    MIDSTATE_COMPUTATIONS.with(|c| c.get())
}

fn bump_midstate_counter() {
    MIDSTATE_COMPUTATIONS.with(|c| c.set(c.get() + 1));
}

/// Single-SHA256 digests over all inputs / all outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedMidstates {
    /// SHA256 of every outpoint (txid || vout LE).
    pub sha_prevouts: [u8; 32],
    /// SHA256 of every nSequence (u32 LE).
    pub sha_sequences: [u8; 32],
    /// SHA256 of every output (value LE || compact_size || script).
    pub sha_outputs: [u8; 32],
}

/// BIP-143 digests (double SHA256), derived from [`SharedMidstates`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bip143Hashes {
    pub hash_prevouts: Hash256,
    pub hash_sequence: Hash256,
    pub hash_outputs: Hash256,
}

/// BIP-341 digests over the spent outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpentOutputMidstates {
    /// SHA256 of every spent amount (u64 LE).
    pub sha_amounts: [u8; 32],
    /// SHA256 of every spent scriptPubKey (compact_size || script).
    pub sha_scriptpubkeys: [u8; 32],
}

/// Cached sighash midstates for one transaction.
///
/// `spent_amounts` / `spent_scripts` are the outputs spent by every input
/// (in input order). They are needed only for BIP-341; pass empty slices
/// when they are unknown, and [`Self::spent_outputs_ready`] is then false,
/// like Core's `m_spent_outputs_ready`.
pub struct PrecomputedTransactionData<'a> {
    tx: &'a Transaction,
    spent_amounts: &'a [u64],
    spent_scripts: SpentScripts<'a>,
    shared: OnceLock<SharedMidstates>,
    bip143: OnceLock<Bip143Hashes>,
    spent: OnceLock<SpentOutputMidstates>,
}

/// The spent scriptPubKeys, in either of the two shapes callers hold.
#[derive(Clone, Copy)]
enum SpentScripts<'a> {
    Owned(&'a [Vec<u8>]),
    Refs(&'a [&'a [u8]]),
}

impl<'a> SpentScripts<'a> {
    fn len(&self) -> usize {
        match self {
            SpentScripts::Owned(s) => s.len(),
            SpentScripts::Refs(s) => s.len(),
        }
    }

    fn get(&self, i: usize) -> &'a [u8] {
        match *self {
            SpentScripts::Owned(s) => s[i].as_slice(),
            SpentScripts::Refs(s) => s[i],
        }
    }
}

impl<'a> PrecomputedTransactionData<'a> {
    /// Cache for `tx`, spending `spent_amounts[i]` / `spent_scripts[i]` at input `i`.
    pub fn new(
        tx: &'a Transaction,
        spent_amounts: &'a [u64],
        spent_scripts: &'a [Vec<u8>],
    ) -> Self {
        Self::with_scripts(tx, spent_amounts, SpentScripts::Owned(spent_scripts))
    }

    /// Same as [`Self::new`] for callers holding the scripts as `&[&[u8]]`.
    pub fn from_script_refs(
        tx: &'a Transaction,
        spent_amounts: &'a [u64],
        spent_scripts: &'a [&'a [u8]],
    ) -> Self {
        Self::with_scripts(tx, spent_amounts, SpentScripts::Refs(spent_scripts))
    }

    fn with_scripts(
        tx: &'a Transaction,
        spent_amounts: &'a [u64],
        spent_scripts: SpentScripts<'a>,
    ) -> Self {
        Self {
            tx,
            spent_amounts,
            spent_scripts,
            shared: OnceLock::new(),
            bip143: OnceLock::new(),
            spent: OnceLock::new(),
        }
    }

    /// The transaction this cache belongs to.
    pub fn tx(&self) -> &'a Transaction {
        self.tx
    }

    /// The spent amounts this cache was built with.
    pub fn spent_amounts(&self) -> &'a [u64] {
        self.spent_amounts
    }

    /// The spent scriptPubKey of input `i`.
    ///
    /// Panics if `i` is out of range; check [`Self::spent_outputs_ready`] first.
    pub fn spent_script(&self, i: usize) -> &'a [u8] {
        self.spent_scripts.get(i)
    }

    /// True when a spent output is known for every input (BIP-341 usable).
    pub fn spent_outputs_ready(&self) -> bool {
        self.spent_amounts.len() == self.tx.inputs.len()
            && self.spent_scripts.len() == self.tx.inputs.len()
    }

    /// Prevouts / sequences / outputs single hashes, computed once.
    pub fn shared(&self) -> &SharedMidstates {
        self.shared.get_or_init(|| {
            bump_midstate_counter();
            let tx = self.tx;
            let mut buf = Vec::with_capacity(36 * tx.inputs.len());
            for inp in &tx.inputs {
                buf.extend_from_slice(&inp.previous_output.txid.0);
                buf.extend_from_slice(&inp.previous_output.vout.to_le_bytes());
            }
            let sha_prevouts = sha256(&buf);

            buf.clear();
            for inp in &tx.inputs {
                buf.extend_from_slice(&inp.sequence.to_le_bytes());
            }
            let sha_sequences = sha256(&buf);

            buf.clear();
            for o in &tx.outputs {
                encode_txout(&mut buf, o);
            }
            let sha_outputs = sha256(&buf);

            SharedMidstates {
                sha_prevouts,
                sha_sequences,
                sha_outputs,
            }
        })
    }

    /// BIP-143 `hashPrevouts` / `hashSequence` / `hashOutputs`, computed once.
    pub fn bip143(&self) -> &Bip143Hashes {
        self.bip143.get_or_init(|| {
            let s = self.shared();
            Bip143Hashes {
                hash_prevouts: Hash256(sha256(&s.sha_prevouts)),
                hash_sequence: Hash256(sha256(&s.sha_sequences)),
                hash_outputs: Hash256(sha256(&s.sha_outputs)),
            }
        })
    }

    /// BIP-341 `sha_amounts` / `sha_scriptpubkeys`, computed once.
    ///
    /// Returns `None` when the spent outputs are not known for every input.
    pub fn spent_outputs(&self) -> Option<&SpentOutputMidstates> {
        if !self.spent_outputs_ready() {
            return None;
        }
        Some(self.spent.get_or_init(|| {
            bump_midstate_counter();
            let mut buf = Vec::with_capacity(8 * self.spent_amounts.len());
            for amt in self.spent_amounts {
                buf.extend_from_slice(&amt.to_le_bytes());
            }
            let sha_amounts = sha256(&buf);

            buf.clear();
            for i in 0..self.spent_scripts.len() {
                let script = self.spent_scripts.get(i);
                write_compact_size(&mut buf, script.len() as u64);
                buf.extend_from_slice(script);
            }
            let sha_scriptpubkeys = sha256(&buf);

            SpentOutputMidstates {
                sha_amounts,
                sha_scriptpubkeys,
            }
        }))
    }
}

/// Encode a TxOut as `value (8 LE) || compact_size(script_len) || script`.
pub(crate) fn encode_txout(out: &mut Vec<u8>, txout: &rustoshi_primitives::TxOut) {
    out.extend_from_slice(&txout.value.to_le_bytes());
    write_compact_size(out, txout.script_pubkey.len() as u64);
    out.extend_from_slice(&txout.script_pubkey);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::sha256d;
    use rustoshi_primitives::{Decodable, Encodable, OutPoint, TxIn, TxOut};

    fn tx_with_inputs(n: usize) -> Transaction {
        Transaction {
            version: 2,
            inputs: (0..n)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Hash256([(i % 251) as u8; 32]),
                        vout: i as u32,
                    },
                    script_sig: vec![],
                    sequence: 0xFFFF_FFF0 - i as u32,
                    witness: vec![],
                })
                .collect(),
            outputs: vec![
                TxOut {
                    value: 1234,
                    script_pubkey: vec![0x51],
                },
                TxOut {
                    value: 99,
                    script_pubkey: vec![0x6a; 300],
                },
            ],
            lock_time: 7,
        }
    }

    /// The BIP-143 doubles derived from the singles equal a direct sha256d
    /// over the BIP-143 serialization (the `Encodable` path the old code used).
    #[test]
    fn bip143_doubles_match_direct_sha256d() {
        let tx = tx_with_inputs(5);
        let pre = PrecomputedTransactionData::new(&tx, &[], &[]);
        let mut prevouts = Vec::new();
        let mut seqs = Vec::new();
        for inp in &tx.inputs {
            inp.previous_output.encode(&mut prevouts).unwrap();
            seqs.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        let mut outs = Vec::new();
        for o in &tx.outputs {
            o.encode(&mut outs).unwrap();
        }
        let h = pre.bip143();
        assert_eq!(h.hash_prevouts, sha256d(&prevouts));
        assert_eq!(h.hash_sequence, sha256d(&seqs));
        assert_eq!(h.hash_outputs, sha256d(&outs));
        assert!(!pre.spent_outputs_ready());
        assert!(pre.spent_outputs().is_none());
    }

    /// Each midstate group is hashed once per transaction, however many
    /// times it is read.
    #[test]
    fn midstate_groups_computed_once() {
        let tx = tx_with_inputs(8);
        let amounts = vec![1000u64; 8];
        let scripts = vec![vec![0x51u8, 0x20]; 8];
        let pre = PrecomputedTransactionData::new(&tx, &amounts, &scripts);
        let before = midstate_computations();
        for _ in 0..50 {
            let _ = pre.bip143();
            let _ = pre.shared();
            let _ = pre.spent_outputs().unwrap();
        }
        assert_eq!(midstate_computations() - before, 2);
    }

    fn vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../consensus/testdata/bip341_wallet_vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// The tx-level intermediary hashes in Core's bip341_wallet_vectors.json.
    #[test]
    fn bip341_wallet_vector_midstates() {
        let v = vectors();
        for case in v["keyPathSpending"].as_array().unwrap() {
            let raw = hex::decode(case["given"]["rawUnsignedTx"].as_str().unwrap()).unwrap();
            let tx = Transaction::decode(&mut raw.as_slice()).unwrap();
            let utxos = case["given"]["utxosSpent"].as_array().unwrap();
            let amounts: Vec<u64> = utxos
                .iter()
                .map(|u| u["amountSats"].as_u64().unwrap())
                .collect();
            let scripts: Vec<Vec<u8>> = utxos
                .iter()
                .map(|u| hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap())
                .collect();
            let pre = PrecomputedTransactionData::new(&tx, &amounts, &scripts);
            let im = &case["intermediary"];
            let hx = |b: &[u8; 32]| hex::encode(b);
            let s = pre.shared();
            let sp = pre.spent_outputs().unwrap();
            assert_eq!(hx(&s.sha_prevouts), im["hashPrevouts"].as_str().unwrap());
            assert_eq!(hx(&s.sha_sequences), im["hashSequences"].as_str().unwrap());
            assert_eq!(hx(&s.sha_outputs), im["hashOutputs"].as_str().unwrap());
            assert_eq!(hx(&sp.sha_amounts), im["hashAmounts"].as_str().unwrap());
            assert_eq!(
                hx(&sp.sha_scriptpubkeys),
                im["hashScriptPubkeys"].as_str().unwrap()
            );
        }
    }
}
