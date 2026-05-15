//! FIX-62 — BIP-21 URI parser integration tests.
//!
//! Closes the W119 universal finding "BIP-21 URI parser MISSING in 9/10
//! impls" for rustoshi. The W119 audit `test_w119_payjoin.rs` G28+G29
//! gates probe for `parse_bip21` from the public surface of
//! `rustoshi_wallet` — this file exercises the same entry point through
//! its real type and adds the BIP-21 spec test vectors plus
//! protocol-edge cases that the audit's two `#[ignore]`-flippable gates
//! cannot cover (req- behaviour, % escapes, network constraint, etc.).
//!
//! Reference: BIP-21 spec
//!   https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
//!
//! BIP-21 spec test vectors (§"Simpler syntax", here adapted to use a
//! real valid Base58Check address — the address printed in the BIP-21
//! spec, `175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W`, has a Base58Check
//! checksum mismatch: hashing its 21-byte payload gives 8a9c6111 but
//! the on-wire bytes are 8a9c6129. To exercise the spec's *shape* we
//! substitute Satoshi's genesis P2PKH which is a real valid mainnet
//! address — the BIP-21 grammar tests are unchanged.):
//!   1. bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
//!   2. bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=20.3&label=Luke-Jr
//!   3. bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz
//!   4. bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999
//!   5. bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?somethingyoudontunderstand=50&somethingelseyoudontget=999

use rustoshi_crypto::address::{Address, Network};
use rustoshi_wallet::{parse_bip21, Bip21Error};

/// BIP-21 spec stand-in — Satoshi's genesis P2PKH (real, valid).
/// Mirrors the spec's example structure while having a passing Base58
/// checksum.
const SPEC_ADDR: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

/// Modern mainnet P2WPKH (used everywhere SegWit makes more sense).
const MAINNET_BECH32: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

/// Mainnet P2TR taproot address (BIP-86).
const MAINNET_TAPROOT: &str =
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

/// Testnet P2WPKH address — for network-mismatch testing.
fn testnet_bech32() -> String {
    // Encode programmatically so we don't hard-code a checksum that could rot.
    use rustoshi_primitives::Hash160;
    let h = Hash160::from_hex("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
    Address::P2WPKH {
        hash: h,
        network: Network::Testnet,
    }
    .encode()
}

// ============================================================
// BIP-21 spec test vectors
// ============================================================

#[test]
fn spec_vec1_plain_address() {
    let uri = parse_bip21(&format!("bitcoin:{}", SPEC_ADDR), Network::Mainnet).unwrap();
    assert!(matches!(uri.address, Address::P2PKH { .. }));
    assert_eq!(uri.amount, None);
    assert_eq!(uri.label, None);
    assert_eq!(uri.message, None);
    assert!(uri.extras.is_empty());
}

#[test]
fn spec_vec2_amount_and_label() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?amount=20.3&label=Luke-Jr", SPEC_ADDR),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(20 * 100_000_000 + 30_000_000));
    assert_eq!(uri.label.as_deref(), Some("Luke-Jr"));
}

#[test]
fn spec_vec3_amount_label_message_pct_encoded() {
    let uri = parse_bip21(
        &format!(
            "bitcoin:{}?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz",
            SPEC_ADDR
        ),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(50 * 100_000_000));
    assert_eq!(uri.label.as_deref(), Some("Luke-Jr"));
    assert_eq!(
        uri.message.as_deref(),
        Some("Donation for project xyz")
    );
}

#[test]
fn spec_vec4_unknown_req_param_rejected() {
    // BIP-21 vector 4: per spec MUST be rejected because the wallet
    // doesn't understand the required params.
    let r = parse_bip21(
        &format!(
            "bitcoin:{}?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999",
            SPEC_ADDR
        ),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::UnknownRequiredParam(_))));
}

#[test]
fn spec_vec5_unknown_unprefixed_params_preserved() {
    // BIP-21 vector 5: MUST be accepted; unknown non-req params just
    // get ignored (forward-compat).
    let uri = parse_bip21(
        &format!(
            "bitcoin:{}?somethingyoudontunderstand=50&somethingelseyoudontget=999",
            SPEC_ADDR
        ),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(
        uri.extras.get("somethingyoudontunderstand").map(String::as_str),
        Some("50")
    );
    assert_eq!(
        uri.extras.get("somethingelseyoudontget").map(String::as_str),
        Some("999")
    );
}

// ============================================================
// Address types
// ============================================================

#[test]
fn parses_p2pkh_mainnet() {
    let uri = parse_bip21(&format!("bitcoin:{}", SPEC_ADDR), Network::Mainnet).unwrap();
    assert!(matches!(uri.address, Address::P2PKH { .. }));
}

#[test]
fn parses_p2wpkh_mainnet() {
    let uri = parse_bip21(&format!("bitcoin:{}", MAINNET_BECH32), Network::Mainnet).unwrap();
    assert!(matches!(uri.address, Address::P2WPKH { .. }));
}

#[test]
fn parses_p2tr_mainnet() {
    let uri = parse_bip21(&format!("bitcoin:{}", MAINNET_TAPROOT), Network::Mainnet).unwrap();
    assert!(matches!(uri.address, Address::P2TR { .. }));
}

#[test]
fn parses_testnet_bech32() {
    let addr = testnet_bech32();
    let uri = parse_bip21(&format!("bitcoin:{}", addr), Network::Testnet).unwrap();
    assert!(matches!(uri.address, Address::P2WPKH { .. }));
    assert_eq!(uri.address.network(), Network::Testnet);
}

#[test]
fn wrong_network_rejected_p2wpkh() {
    let r = parse_bip21(
        &format!("bitcoin:{}", MAINNET_BECH32),
        Network::Testnet,
    );
    assert!(matches!(r, Err(Bip21Error::WrongNetwork { .. })));
}

#[test]
fn wrong_network_rejected_p2pkh() {
    let r = parse_bip21(&format!("bitcoin:{}", SPEC_ADDR), Network::Testnet);
    assert!(matches!(r, Err(Bip21Error::WrongNetwork { .. })));
}

// ============================================================
// Amount parsing
// ============================================================

#[test]
fn amount_zero() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?amount=0", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(0));
}

#[test]
fn amount_one_satoshi() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?amount=0.00000001", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(1));
}

#[test]
fn amount_21m_supply_cap() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?amount=21000000", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(21_000_000 * 100_000_000));
}

#[test]
fn amount_dot_only_fractional() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?amount=.5", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(50_000_000));
}

#[test]
fn amount_trailing_dot() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?amount=1.", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(100_000_000));
}

#[test]
fn amount_rejects_nine_decimal_places() {
    let r = parse_bip21(
        &format!("bitcoin:{}?amount=0.000000001", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::InvalidAmount(_))));
}

#[test]
fn amount_rejects_garbage() {
    let r = parse_bip21(
        &format!("bitcoin:{}?amount=abc", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::InvalidAmount(_))));
}

#[test]
fn amount_rejects_two_dots() {
    let r = parse_bip21(
        &format!("bitcoin:{}?amount=1.0.0", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::InvalidAmount(_))));
}

#[test]
fn amount_rejects_lower_e_scientific() {
    let r = parse_bip21(
        &format!("bitcoin:{}?amount=1e8", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::InvalidAmount(_))));
}

#[test]
fn amount_rejects_upper_e_scientific() {
    let r = parse_bip21(
        &format!("bitcoin:{}?amount=1E8", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::InvalidAmount(_))));
}

#[test]
fn amount_rejects_negative_with_decimal() {
    let r = parse_bip21(
        &format!("bitcoin:{}?amount=-0.5", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::InvalidAmount(_))));
}

#[test]
fn amount_accepts_leading_plus() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?amount=+0.5", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(50_000_000));
}

#[test]
fn amount_empty_value_rejected() {
    let r = parse_bip21(
        &format!("bitcoin:{}?amount=", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::InvalidAmount(_))));
}

// ============================================================
// Percent-encoding
// ============================================================

#[test]
fn label_percent_space() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?label=Foo%20Bar", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.label.as_deref(), Some("Foo Bar"));
}

#[test]
fn message_percent_lowercase_hex() {
    // RFC 3986 allows either case in hex escapes; many wallets emit
    // lowercase.
    let uri = parse_bip21(
        &format!("bitcoin:{}?message=hi%2fbye", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.message.as_deref(), Some("hi/bye"));
}

#[test]
fn message_percent_uppercase_hex() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?message=hi%2Fbye", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.message.as_deref(), Some("hi/bye"));
}

#[test]
fn label_utf8_decoded() {
    // %C3%A9 is UTF-8 'é'
    let uri = parse_bip21(
        &format!("bitcoin:{}?label=caf%C3%A9", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.label.as_deref(), Some("café"));
}

#[test]
fn truncated_percent_escape_rejected() {
    let r = parse_bip21(
        &format!("bitcoin:{}?label=Foo%2", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::MalformedQuery(_))));
}

#[test]
fn invalid_hex_in_percent_rejected() {
    let r = parse_bip21(
        &format!("bitcoin:{}?label=Foo%ZZ", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::MalformedQuery(_))));
}

#[test]
fn plus_is_literal_not_space() {
    // Bitcoin Core treats '+' literally — we match that behaviour.
    let uri = parse_bip21(
        &format!("bitcoin:{}?label=Foo+Bar", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.label.as_deref(), Some("Foo+Bar"));
}

// ============================================================
// Case sensitivity
// ============================================================

#[test]
fn key_case_insensitive_amount() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?AMOUNT=0.5", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(50_000_000));
}

#[test]
fn key_case_insensitive_mixed() {
    let uri = parse_bip21(
        &format!(
            "bitcoin:{}?Amount=0.5&Label=hi&MESSAGE=yo&PjOs=0",
            MAINNET_BECH32
        ),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(50_000_000));
    assert_eq!(uri.label.as_deref(), Some("hi"));
    assert_eq!(uri.message.as_deref(), Some("yo"));
    assert_eq!(uri.pjos, Some(false));
}

#[test]
fn scheme_case_insensitive() {
    // RFC 3986 §3.1: scheme is case-insensitive.
    let uri = parse_bip21(
        &format!("BITCOIN:{}", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert!(matches!(uri.address, Address::P2WPKH { .. }));
}

// ============================================================
// req- handling
// ============================================================

#[test]
fn unknown_req_with_known_amount_still_rejects() {
    // The unknown req- MUST reject even if other known params parse fine.
    let r = parse_bip21(
        &format!("bitcoin:{}?amount=1&req-foo=bar", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::UnknownRequiredParam(_))));
}

#[test]
fn req_prefix_is_case_insensitive_in_key_match() {
    // The "req-" detection lowercases the key before checking, so
    // `REQ-foo` still triggers rejection.
    let r = parse_bip21(
        &format!("bitcoin:{}?REQ-Foo=1", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::UnknownRequiredParam(_))));
}

// ============================================================
// BIP-78 PayJoin extension (the actual reason we need a parser)
// ============================================================

#[test]
fn bip78_full_payjoin_uri() {
    let uri = parse_bip21(
        &format!(
            "bitcoin:{}?amount=0.01&pj=https://example.com/payjoin&pjos=0",
            MAINNET_BECH32
        ),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(1_000_000));
    assert_eq!(uri.pj.as_deref(), Some("https://example.com/payjoin"));
    assert_eq!(uri.pjos, Some(false));
}

#[test]
fn bip78_pjos_one() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?pj=https://x/y&pjos=1", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.pjos, Some(true));
}

#[test]
fn bip78_pjos_invalid_value_rejected() {
    let r = parse_bip21(
        &format!("bitcoin:{}?pj=https://x/y&pjos=2", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::MalformedQuery(_))));
}

#[test]
fn bip78_percent_encoded_pj_url() {
    // pj URLs may legitimately contain % escapes — query params, etc.
    let uri = parse_bip21(
        &format!(
            "bitcoin:{}?pj=https%3A%2F%2Fexample.com%2Fpj",
            MAINNET_BECH32
        ),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.pj.as_deref(), Some("https://example.com/pj"));
}

#[test]
fn bip78_onion_pj_endpoint_passes_through() {
    // The parser only extracts the string. Scheme policing belongs to
    // the sender layer (BIP-78 BUG-3 from the W119 audit).
    let uri = parse_bip21(
        &format!(
            "bitcoin:{}?pj=http://abcd1234.onion/payjoin",
            MAINNET_BECH32
        ),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(
        uri.pj.as_deref(),
        Some("http://abcd1234.onion/payjoin")
    );
}

// ============================================================
// Lightning fallback
// ============================================================

#[test]
fn lightning_pass_through() {
    let invoice = "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu";
    let uri = parse_bip21(
        &format!("bitcoin:{}?lightning={}", MAINNET_BECH32, invoice),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.lightning.as_deref(), Some(invoice));
}

// ============================================================
// Structural errors
// ============================================================

#[test]
fn missing_address_rejected() {
    let r = parse_bip21("bitcoin:?amount=1", Network::Mainnet);
    assert!(matches!(r, Err(Bip21Error::MalformedQuery(_))));
}

#[test]
fn empty_input_rejected_as_missing_scheme() {
    let r = parse_bip21("", Network::Mainnet);
    assert!(matches!(r, Err(Bip21Error::MissingScheme)));
}

#[test]
fn http_scheme_rejected() {
    let r = parse_bip21("http://example.com", Network::Mainnet);
    assert!(matches!(r, Err(Bip21Error::WrongScheme)));
}

#[test]
fn duplicate_amount_rejected() {
    let r = parse_bip21(
        &format!("bitcoin:{}?amount=1&amount=2", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::MalformedQuery(_))));
}

#[test]
fn duplicate_label_rejected() {
    let r = parse_bip21(
        &format!("bitcoin:{}?label=a&label=b", MAINNET_BECH32),
        Network::Mainnet,
    );
    assert!(matches!(r, Err(Bip21Error::MalformedQuery(_))));
}

// ============================================================
// Trailing/consecutive '&' tolerance
// ============================================================

#[test]
fn trailing_ampersand_tolerated() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?amount=1&", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(100_000_000));
}

#[test]
fn consecutive_ampersand_tolerated() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?amount=1&&label=hi", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.amount, Some(100_000_000));
    assert_eq!(uri.label.as_deref(), Some("hi"));
}

// ============================================================
// Empty value for textual fields is allowed
// ============================================================

#[test]
fn label_empty_value_ok() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?label=", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.label.as_deref(), Some(""));
}

#[test]
fn key_without_equals_treated_as_empty_value() {
    let uri = parse_bip21(
        &format!("bitcoin:{}?somekey", MAINNET_BECH32),
        Network::Mainnet,
    )
    .unwrap();
    assert_eq!(uri.extras.get("somekey").map(String::as_str), Some(""));
}
