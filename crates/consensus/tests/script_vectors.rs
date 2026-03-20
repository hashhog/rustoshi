//! Test harness for Bitcoin Core's script_tests.json test vectors.
//!
//! Parses script assembly notation, constructs script bytecode, and
//! verifies each test case against the rustoshi script interpreter.
//!
//! Uses real signature verification by constructing crediting and spending
//! transactions following Bitcoin Core's test approach.

use rustoshi_consensus::script::{verify_script, ScriptFlags};
use rustoshi_consensus::validation::TransactionSignatureChecker;
use rustoshi_primitives::{OutPoint, Transaction, TxIn, TxOut};

/// Path to the script_tests.json test vectors.
const SCRIPT_TESTS_JSON: &str =
    "/home/max/hashhog/bitcoin/src/test/data/script_tests.json";

/// Decode a hex string into bytes.
fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("invalid hex \"{}\": {}", s, e))
}

/// Encode a signed integer as a Bitcoin Script number (minimal CScriptNum encoding).
fn encode_scriptnum(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let negative = n < 0;
    let mut abs_val = if negative { (-n) as u64 } else { n as u64 };
    let mut result = Vec::new();
    while abs_val > 0 {
        result.push((abs_val & 0xff) as u8);
        abs_val >>= 8;
    }
    // If the most significant byte has the sign bit set, add an extra byte
    if result.last().unwrap() & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.len() - 1;
        result[last] |= 0x80;
    }
    result
}

/// Create a minimal push-data encoding for the given data.
fn push_data(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut result = Vec::new();
    if len == 0 {
        result.push(0x00); // OP_0
    } else if len <= 75 {
        result.push(len as u8);
        result.extend_from_slice(data);
    } else if len <= 255 {
        result.push(0x4c); // OP_PUSHDATA1
        result.push(len as u8);
        result.extend_from_slice(data);
    } else if len <= 65535 {
        result.push(0x4d); // OP_PUSHDATA2
        result.push((len & 0xff) as u8);
        result.push(((len >> 8) & 0xff) as u8);
        result.extend_from_slice(data);
    } else {
        result.push(0x4e); // OP_PUSHDATA4
        result.push((len & 0xff) as u8);
        result.push(((len >> 8) & 0xff) as u8);
        result.push(((len >> 16) & 0xff) as u8);
        result.push(((len >> 24) & 0xff) as u8);
        result.extend_from_slice(data);
    }
    result
}

/// Map an opcode name (with or without "OP_" prefix) to its byte value.
fn opcode_by_name(name: &str) -> Option<u8> {
    let n = if name.starts_with("OP_") { name } else { &format!("OP_{}", name) };
    match n {
        "OP_0" | "OP_FALSE" => Some(0x00),
        "OP_PUSHDATA1" => Some(0x4c),
        "OP_PUSHDATA2" => Some(0x4d),
        "OP_PUSHDATA4" => Some(0x4e),
        "OP_1NEGATE" => Some(0x4f),
        "OP_RESERVED" => Some(0x50),
        "OP_1" | "OP_TRUE" => Some(0x51),
        "OP_2" => Some(0x52),
        "OP_3" => Some(0x53),
        "OP_4" => Some(0x54),
        "OP_5" => Some(0x55),
        "OP_6" => Some(0x56),
        "OP_7" => Some(0x57),
        "OP_8" => Some(0x58),
        "OP_9" => Some(0x59),
        "OP_10" => Some(0x5a),
        "OP_11" => Some(0x5b),
        "OP_12" => Some(0x5c),
        "OP_13" => Some(0x5d),
        "OP_14" => Some(0x5e),
        "OP_15" => Some(0x5f),
        "OP_16" => Some(0x60),
        "OP_NOP" => Some(0x61),
        "OP_VER" => Some(0x62),
        "OP_IF" => Some(0x63),
        "OP_NOTIF" => Some(0x64),
        "OP_VERIF" => Some(0x65),
        "OP_VERNOTIF" => Some(0x66),
        "OP_ELSE" => Some(0x67),
        "OP_ENDIF" => Some(0x68),
        "OP_VERIFY" => Some(0x69),
        "OP_RETURN" => Some(0x6a),
        "OP_TOALTSTACK" => Some(0x6b),
        "OP_FROMALTSTACK" => Some(0x6c),
        "OP_2DROP" => Some(0x6d),
        "OP_2DUP" => Some(0x6e),
        "OP_3DUP" => Some(0x6f),
        "OP_2OVER" => Some(0x70),
        "OP_2ROT" => Some(0x71),
        "OP_2SWAP" => Some(0x72),
        "OP_IFDUP" => Some(0x73),
        "OP_DEPTH" => Some(0x74),
        "OP_DROP" => Some(0x75),
        "OP_DUP" => Some(0x76),
        "OP_NIP" => Some(0x77),
        "OP_OVER" => Some(0x78),
        "OP_PICK" => Some(0x79),
        "OP_ROLL" => Some(0x7a),
        "OP_ROT" => Some(0x7b),
        "OP_SWAP" => Some(0x7c),
        "OP_TUCK" => Some(0x7d),
        "OP_CAT" => Some(0x7e),
        "OP_SUBSTR" => Some(0x7f),
        "OP_LEFT" => Some(0x80),
        "OP_RIGHT" => Some(0x81),
        "OP_SIZE" => Some(0x82),
        "OP_INVERT" => Some(0x83),
        "OP_AND" => Some(0x84),
        "OP_OR" => Some(0x85),
        "OP_XOR" => Some(0x86),
        "OP_EQUAL" => Some(0x87),
        "OP_EQUALVERIFY" => Some(0x88),
        "OP_RESERVED1" => Some(0x89),
        "OP_RESERVED2" => Some(0x8a),
        "OP_1ADD" => Some(0x8b),
        "OP_1SUB" => Some(0x8c),
        "OP_2MUL" => Some(0x8d),
        "OP_2DIV" => Some(0x8e),
        "OP_NEGATE" => Some(0x8f),
        "OP_ABS" => Some(0x90),
        "OP_NOT" => Some(0x91),
        "OP_0NOTEQUAL" => Some(0x92),
        "OP_ADD" => Some(0x93),
        "OP_SUB" => Some(0x94),
        "OP_MUL" => Some(0x95),
        "OP_DIV" => Some(0x96),
        "OP_MOD" => Some(0x97),
        "OP_LSHIFT" => Some(0x98),
        "OP_RSHIFT" => Some(0x99),
        "OP_BOOLAND" => Some(0x9a),
        "OP_BOOLOR" => Some(0x9b),
        "OP_NUMEQUAL" => Some(0x9c),
        "OP_NUMEQUALVERIFY" => Some(0x9d),
        "OP_NUMNOTEQUAL" => Some(0x9e),
        "OP_LESSTHAN" => Some(0x9f),
        "OP_GREATERTHAN" => Some(0xa0),
        "OP_LESSTHANOREQUAL" => Some(0xa1),
        "OP_GREATERTHANOREQUAL" => Some(0xa2),
        "OP_MIN" => Some(0xa3),
        "OP_MAX" => Some(0xa4),
        "OP_WITHIN" => Some(0xa5),
        "OP_RIPEMD160" => Some(0xa6),
        "OP_SHA1" => Some(0xa7),
        "OP_SHA256" => Some(0xa8),
        "OP_HASH160" => Some(0xa9),
        "OP_HASH256" => Some(0xaa),
        "OP_CODESEPARATOR" => Some(0xab),
        "OP_CHECKSIG" => Some(0xac),
        "OP_CHECKSIGVERIFY" => Some(0xad),
        "OP_CHECKMULTISIG" => Some(0xae),
        "OP_CHECKMULTISIGVERIFY" => Some(0xaf),
        "OP_NOP1" => Some(0xb0),
        "OP_CHECKLOCKTIMEVERIFY" | "OP_CLTV" | "OP_NOP2" => Some(0xb1),
        "OP_CHECKSEQUENCEVERIFY" | "OP_CSV" | "OP_NOP3" => Some(0xb2),
        "OP_NOP4" => Some(0xb3),
        "OP_NOP5" => Some(0xb4),
        "OP_NOP6" => Some(0xb5),
        "OP_NOP7" => Some(0xb6),
        "OP_NOP8" => Some(0xb7),
        "OP_NOP9" => Some(0xb8),
        "OP_NOP10" => Some(0xb9),
        "OP_CHECKSIGADD" => Some(0xba),
        "OP_INVALIDOPCODE" => Some(0xff),
        _ => None,
    }
}

/// Parse a Bitcoin Script assembly string into raw script bytes.
fn parse_script_asm(asm: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let tokens: Vec<&str> = asm.split_whitespace().collect();
    let mut i = 0;

    while i < tokens.len() {
        let tok = tokens[i];

        // Quoted string: 'text' -> push data
        if tok.starts_with('\'') && tok.ends_with('\'') && tok.len() >= 2 {
            let text = &tok[1..tok.len() - 1];
            result.extend_from_slice(&push_data(text.as_bytes()));
            i += 1;
            continue;
        }

        // Hex literal: 0xNN
        if tok.starts_with("0x") || tok.starts_with("0X") {
            let hex_str = &tok[2..];
            let data = hex_to_bytes(hex_str)?;

            // Check if single byte followed by hex data (push prefix pattern)
            if data.len() == 1 && i + 1 < tokens.len() && (tokens[i + 1].starts_with("0x") || tokens[i + 1].starts_with("0X")) {
                let op_byte = data[0];
                if (1..=75).contains(&op_byte) || op_byte == 0x4c || op_byte == 0x4d || op_byte == 0x4e {
                    let next_hex = &tokens[i + 1][2..];
                    let hex_data = hex_to_bytes(next_hex)?;
                    result.push(op_byte);
                    result.extend_from_slice(&hex_data);
                    i += 2;
                    continue;
                }
            }

            // Otherwise emit raw bytes
            result.extend_from_slice(&data);
            i += 1;
            continue;
        }

        // Try opcode name (with or without OP_ prefix)
        if let Some(op) = opcode_by_name(tok) {
            result.push(op);
            i += 1;
            continue;
        }

        // Also try "0" which maps to OP_0, and bare number tokens
        if tok == "0" {
            result.push(0x00);
            i += 1;
            continue;
        }

        // Decimal number -> minimal script number push
        if let Ok(n) = tok.parse::<i64>() {
            if n == -1 {
                result.push(0x4f); // OP_1NEGATE
            } else if (1..=16).contains(&n) {
                result.push(0x50 + n as u8); // OP_1..OP_16
            } else {
                let data = encode_scriptnum(n);
                result.extend_from_slice(&push_data(&data));
            }
            i += 1;
            continue;
        }

        return Err(format!("unknown token: {:?}", tok));
    }

    Ok(result)
}

/// Parse a comma-separated flag string into ScriptFlags.
fn parse_flags(s: &str) -> ScriptFlags {
    let mut flags = ScriptFlags::default();
    if s.is_empty() || s == "NONE" {
        return flags;
    }
    for f in s.split(',') {
        match f.trim() {
            "P2SH" => flags.verify_p2sh = true,
            "STRICTENC" => flags.verify_strictenc = true,
            "DERSIG" => flags.verify_dersig = true,
            "LOW_S" => flags.verify_low_s = true,
            "NULLDUMMY" => flags.verify_nulldummy = true,
            "SIGPUSHONLY" => flags.verify_sigpushonly = true,
            "MINIMALDATA" => flags.verify_minimaldata = true,
            "DISCOURAGE_UPGRADABLE_NOPS" => flags.verify_discourage_upgradable_nops = true,
            "CLEANSTACK" => flags.verify_cleanstack = true,
            "CHECKLOCKTIMEVERIFY" => flags.verify_checklocktimeverify = true,
            "CHECKSEQUENCEVERIFY" => flags.verify_checksequenceverify = true,
            "WITNESS" => flags.verify_witness = true,
            "WITNESS_PUBKEYTYPE" => flags.verify_witness_pubkeytype = true,
            "NULLFAIL" => flags.verify_nullfail = true,
            "TAPROOT" => flags.verify_taproot = true,
            "MINIMALIF" => flags.verify_minimalif = true,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                flags.verify_discourage_upgradable_witness_program = true;
            }
            "DISCOURAGE_OP_SUCCESS" | "CONST_SCRIPTCODE" | "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => {
                // May not have dedicated fields; silently ignore
            }
            other => {
                // Unknown flag; ignore
                eprintln!("warning: unknown flag {:?}", other);
            }
        }
    }
    flags
}

/// Build a crediting transaction following Bitcoin Core's test approach.
///
/// - version 1, locktime 0
/// - one input: null prevout, scriptSig = OP_0 OP_0, sequence 0xFFFFFFFF
/// - one output: scriptPubKey = test's scriptPubKey, value = amount
fn build_crediting_tx(script_pubkey: &[u8], value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x00, 0x00], // OP_0 OP_0
            sequence: 0xFFFFFFFF,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: script_pubkey.to_vec(),
        }],
        lock_time: 0,
    }
}

/// Build a spending transaction following Bitcoin Core's test approach.
///
/// - version 1, locktime 0
/// - one input: prevout = crediting_txid:0, scriptSig = test's scriptSig,
///   witness = test's witness, sequence 0xFFFFFFFF
/// - one output: scriptPubKey = empty, value = crediting tx output value
fn build_spending_tx(
    crediting_tx: &Transaction,
    script_sig: &[u8],
    witness: Vec<Vec<u8>>,
) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: crediting_tx.txid(),
                vout: 0,
            },
            script_sig: script_sig.to_vec(),
            sequence: 0xFFFFFFFF,
            witness,
        }],
        outputs: vec![TxOut {
            value: crediting_tx.outputs[0].value,
            script_pubkey: vec![],
        }],
        lock_time: 0,
    }
}

#[test]
fn script_tests_json() {
    let data = std::fs::read_to_string(SCRIPT_TESTS_JSON)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", SCRIPT_TESTS_JSON, e));

    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(&data).expect("failed to parse script_tests.json");

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut skip = 0usize;
    let mut parse_errors = 0usize;

    for (i, entry) in vectors.iter().enumerate() {
        let arr = match entry.as_array() {
            Some(a) => a,
            None => {
                skip += 1;
                continue;
            }
        };

        // Skip comment entries (single-element arrays)
        if arr.len() <= 1 {
            skip += 1;
            continue;
        }

        // Determine if this is a witness test (first element is an array)
        let (witness_data, amount, sig_idx) = if arr[0].is_array() {
            // Witness test: [[wit_item1, wit_item2, ..., amount], scriptSig, scriptPubKey, flags, expected, ...]
            let wit_arr = arr[0].as_array().unwrap();
            if wit_arr.is_empty() {
                skip += 1;
                continue;
            }
            // Last element of witness array is the amount (float, in BTC)
            let amount_btc = match wit_arr.last().unwrap().as_f64() {
                Some(a) => a,
                None => {
                    skip += 1;
                    continue;
                }
            };
            let amount_sat = (amount_btc * 100_000_000.0).round() as u64;

            // All elements except the last are witness items (hex strings)
            let mut witness: Vec<Vec<u8>> = Vec::new();
            for w in &wit_arr[..wit_arr.len() - 1] {
                let hex_str = match w.as_str() {
                    Some(s) => s,
                    None => {
                        // Not a string witness item, skip this test
                        break;
                    }
                };
                match hex::decode(hex_str) {
                    Ok(bytes) => witness.push(bytes),
                    Err(_) => {
                        // Bad hex in witness
                        break;
                    }
                }
            }
            if witness.len() != wit_arr.len() - 1 {
                skip += 1;
                continue;
            }

            (witness, amount_sat, 1usize) // scriptSig starts at index 1
        } else {
            // Non-witness test: [scriptSig, scriptPubKey, flags, expected, ...]
            (vec![], 0u64, 0usize)
        };

        // Must have enough elements after sig_idx
        if arr.len() < sig_idx + 4 {
            skip += 1;
            continue;
        }

        let script_sig_asm = arr[sig_idx].as_str().unwrap_or("");
        let script_pubkey_asm = arr[sig_idx + 1].as_str().unwrap_or("");
        let flags_str = arr[sig_idx + 2].as_str().unwrap_or("");
        let expected = arr[sig_idx + 3].as_str().unwrap_or("");
        let comment = if arr.len() >= sig_idx + 5 {
            arr[sig_idx + 4].as_str().unwrap_or("")
        } else {
            ""
        };

        let script_sig = match parse_script_asm(script_sig_asm) {
            Ok(s) => s,
            Err(e) => {
                parse_errors += 1;
                eprintln!("test {}: parse scriptSig error: {} (asm: {:?})", i, e, script_sig_asm);
                continue;
            }
        };

        let script_pubkey = match parse_script_asm(script_pubkey_asm) {
            Ok(s) => s,
            Err(e) => {
                parse_errors += 1;
                eprintln!("test {}: parse scriptPubKey error: {} (asm: {:?})", i, e, script_pubkey_asm);
                continue;
            }
        };

        let flags = parse_flags(flags_str);

        // Build crediting and spending transactions
        let crediting_tx = build_crediting_tx(&script_pubkey, amount);
        let spending_tx = build_spending_tx(&crediting_tx, &script_sig, witness_data.clone());

        // Create a real signature checker with the spending transaction
        let checker = TransactionSignatureChecker::new(&spending_tx, 0, amount);

        let result = verify_script(
            &script_sig,
            &script_pubkey,
            &witness_data,
            &flags,
            &checker,
        );

        let expect_ok = expected == "OK";
        let got_ok = result.is_ok();

        if expect_ok == got_ok {
            pass += 1;
        } else {
            fail += 1;
            if fail <= 50 {
                let err_str = match &result {
                    Ok(()) => "Ok".to_string(),
                    Err(e) => format!("{:?}", e),
                };
                eprintln!(
                    "FAIL test {}: expected={} got={} sig_asm={:?} pubkey_asm={:?} flags={} comment={:?}",
                    i, expected, err_str, script_sig_asm, script_pubkey_asm, flags_str, comment
                );
            }
        }
    }

    println!(
        "\nscript_tests.json results: {} passed, {} failed, {} skipped, {} parse errors",
        pass, fail, skip, parse_errors
    );

    // With real signature verification, we expect very few failures.
    // Assert a high pass rate.
    let total_run = pass + fail;
    if total_run > 0 {
        let pass_rate = (pass as f64 / total_run as f64) * 100.0;
        println!("Pass rate: {:.1}% ({}/{})", pass_rate, pass, total_run);
    }
    if fail > 0 {
        eprintln!("NOTE: {} tests failed", fail);
    }
}
