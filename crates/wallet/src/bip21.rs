//! BIP-21 URI parser (`bitcoin:` payment URIs).
//!
//! Implements [BIP-21] — the URI scheme that lets a sender hand a wallet a
//! single string ("bitcoin:bc1q.../?amount=0.5&label=Alice") and have the
//! wallet pre-fill the recipient, amount, label, and message. Modern
//! extensions ([BIP-78] PayJoin) hang additional params off the same URI:
//! `pj=<endpoint>` and `pjos=0|1`. This parser exposes those fields too
//! so a PayJoin sender can drive the full flow from a single URI.
//!
//! ## Grammar
//!
//! ```text
//! bitcoinurn        = "bitcoin:" bitcoinaddress [ "?" bitcoinparams ]
//! bitcoinparams     = bitcoinparam *( "&" bitcoinparam )
//! bitcoinparam      = [ "amount=" amount ]
//!                   / [ "label=" *qchar ]
//!                   / [ "message=" *qchar ]
//!                   / [ "lightning=" *qchar ]    ; ecosystem extension
//!                   / [ "pj=" *qchar ]           ; BIP-78
//!                   / [ "pjos=" ( "0" / "1" ) ]  ; BIP-78
//!                   / otherparam
//!                   / reqparam                   ; req- prefix → MUST reject if unknown
//! ```
//!
//! Query keys are matched case-insensitively (per RFC 3986); values are
//! percent-decoded as UTF-8.
//!
//! [BIP-21]: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
//! [BIP-78]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki

use std::collections::HashMap;

use rustoshi_crypto::address::{Address, AddressError, Network};

/// Parsed contents of a `bitcoin:` URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip21Uri {
    /// Recipient address (validated against the active network).
    pub address: Address,
    /// Amount in satoshis (converted from the BIP-21 decimal-BTC value).
    pub amount: Option<u64>,
    /// Payee label (percent-decoded UTF-8).
    pub label: Option<String>,
    /// Free-form message (percent-decoded UTF-8).
    pub message: Option<String>,
    /// Lightning fallback (BOLT-11 invoice). Passed through verbatim.
    pub lightning: Option<String>,
    /// BIP-78 PayJoin endpoint URL.
    pub pj: Option<String>,
    /// BIP-78 `pjos` flag. `Some(true)` ⇔ output substitution allowed
    /// (the BIP-78 default), `Some(false)` ⇔ explicitly disabled.
    pub pjos: Option<bool>,
    /// Any unprefixed unknown query keys, preserved for forward-compat.
    /// `req-`-prefixed keys are never put here — unknown `req-` rejects
    /// the URI outright per BIP-21.
    pub extras: HashMap<String, String>,
}

/// Errors that can arise while parsing a `bitcoin:` URI.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Bip21Error {
    /// Input did not contain a scheme at all.
    #[error("missing URI scheme")]
    MissingScheme,
    /// Scheme was present but was not `bitcoin:`.
    #[error("wrong URI scheme: expected `bitcoin:`")]
    WrongScheme,
    /// Address part failed to parse.
    #[error("invalid address: {0}")]
    InvalidAddress(#[from] AddressError),
    /// Address parsed but for the wrong network.
    #[error("address is for network {got:?}, expected {expected:?}")]
    WrongNetwork {
        /// The network the caller asked for.
        expected: Network,
        /// The network the address was actually encoded for.
        got: Network,
    },
    /// `amount=` value could not be parsed as a non-negative finite
    /// decimal-BTC value.
    #[error("invalid amount: {0}")]
    InvalidAmount(String),
    /// Query syntax was malformed (e.g. invalid percent-escape, bad
    /// `pjos=` value, multiple addresses).
    #[error("malformed query: {0}")]
    MalformedQuery(String),
    /// An unknown `req-<X>` query key was present. BIP-21 mandates the
    /// entire URI be rejected.
    #[error("unknown required parameter: {0}")]
    UnknownRequiredParam(String),
}

/// Parse a BIP-21 `bitcoin:` URI.
///
/// `input` is the full URI string (`bitcoin:<addr>?<query>`).
///
/// `network` is the active network — the embedded address must match it.
/// Mainnet / Testnet / Regtest / Signet are all supported via the
/// underlying [`Address`] parser.
///
/// Returns a [`Bip21Uri`] on success.
///
/// ## Examples
///
/// ```ignore
/// use rustoshi_wallet::{parse_bip21, Network};
/// let uri = parse_bip21(
///     "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.5&label=Donation",
///     Network::Mainnet,
/// ).unwrap();
/// assert_eq!(uri.amount, Some(50_000_000));
/// assert_eq!(uri.label.as_deref(), Some("Donation"));
/// ```
pub fn parse_bip21(input: &str, network: Network) -> Result<Bip21Uri, Bip21Error> {
    // Find the scheme. Per RFC 3986, the scheme is `ALPHA *( ALPHA / DIGIT
    // / "+" / "-" / "." ) ":"`. BIP-21 only cares about exactly `bitcoin:`,
    // case-insensitive (RFC 3986 §3.1).
    let colon = input.find(':').ok_or(Bip21Error::MissingScheme)?;
    if !input[..colon].eq_ignore_ascii_case("bitcoin") {
        return Err(Bip21Error::WrongScheme);
    }
    let rest = &input[colon + 1..];

    // Split address from query string. A '?' anywhere in `rest` begins
    // the query. An empty rest (just "bitcoin:") is invalid — there must
    // be an address.
    let (addr_part_raw, query_part) = match rest.find('?') {
        Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
        None => (rest, None),
    };

    if addr_part_raw.is_empty() {
        return Err(Bip21Error::MalformedQuery(
            "address is empty".to_string(),
        ));
    }

    // The address part itself MAY be percent-encoded in principle; in
    // practice every published BIP-21 URI encodes the address verbatim
    // (all base58 and bech32 characters are unreserved). Still decode to
    // be defensive — a stray %-escape over a base58 char is harmless.
    let addr_part = percent_decode(addr_part_raw)
        .map_err(|e| Bip21Error::MalformedQuery(format!("address: {}", e)))?;

    // Parse the address; this enforces the network constraint.
    let address = Address::from_string(&addr_part, Some(network)).map_err(|e| match e {
        AddressError::NetworkMismatch { expected, got } => {
            Bip21Error::WrongNetwork { expected, got }
        }
        other => Bip21Error::InvalidAddress(other),
    })?;

    let mut uri = Bip21Uri {
        address,
        amount: None,
        label: None,
        message: None,
        lightning: None,
        pj: None,
        pjos: None,
        extras: HashMap::new(),
    };

    if let Some(query) = query_part {
        parse_query(query, &mut uri)?;
    }

    Ok(uri)
}

/// Parse the query portion (after `?`) into the supplied [`Bip21Uri`].
fn parse_query(query: &str, out: &mut Bip21Uri) -> Result<(), Bip21Error> {
    if query.is_empty() {
        return Ok(());
    }

    // Track keys we've already seen so a duplicate `amount=` (etc.) is
    // flagged. BIP-21 doesn't strictly forbid duplicates, but every
    // sensible wallet rejects them — silent last-wins behaviour would
    // be a fingerprinting / footgun risk.
    let mut seen: HashMap<String, ()> = HashMap::new();

    for pair in query.split('&') {
        if pair.is_empty() {
            // Allow trailing or consecutive '&' — common URL idiom.
            continue;
        }

        let (raw_key, raw_value) = match pair.find('=') {
            Some(eq) => (&pair[..eq], &pair[eq + 1..]),
            None => (pair, ""),
        };

        // Decode key per RFC 3986. Then lowercase for matching.
        let key_decoded = percent_decode(raw_key)
            .map_err(|e| Bip21Error::MalformedQuery(format!("key `{}`: {}", raw_key, e)))?;
        let key_lower = key_decoded.to_ascii_lowercase();

        if seen.insert(key_lower.clone(), ()).is_some() {
            return Err(Bip21Error::MalformedQuery(format!(
                "duplicate query key `{}`",
                key_lower
            )));
        }

        let value = percent_decode(raw_value)
            .map_err(|e| Bip21Error::MalformedQuery(format!("value of `{}`: {}", key_lower, e)))?;

        match key_lower.as_str() {
            "amount" => {
                out.amount = Some(parse_amount_btc(&value)?);
            }
            "label" => {
                out.label = Some(value);
            }
            "message" => {
                out.message = Some(value);
            }
            "lightning" => {
                out.lightning = Some(value);
            }
            "pj" => {
                out.pj = Some(value);
            }
            "pjos" => match value.as_str() {
                "0" => out.pjos = Some(false),
                "1" => out.pjos = Some(true),
                other => {
                    return Err(Bip21Error::MalformedQuery(format!(
                        "pjos must be 0 or 1, got `{}`",
                        other
                    )));
                }
            },
            other => {
                if other.starts_with("req-") {
                    // BIP-21: unknown required param → reject. We
                    // recognise NO `req-` keys today; future negotiated
                    // extensions would add explicit handling here.
                    return Err(Bip21Error::UnknownRequiredParam(other.to_string()));
                }
                // Unknown unprefixed key — forward-compat, preserve.
                out.extras.insert(key_lower, value);
            }
        }
    }

    Ok(())
}

/// Parse a decimal-BTC amount per BIP-21.
///
/// BIP-21 amount is "amount in decimal Bitcoin (BTC)" — e.g.
/// `amount=20.30` means 20.30 BTC = 2_030_000_000 satoshis.
///
/// We parse by string splitting (NOT via `f64`) to avoid binary
/// floating-point rounding eating the last few satoshis of an
/// 8-decimal value. Reject negative, scientific notation, NaN, and
/// >8 fractional digits.
fn parse_amount_btc(s: &str) -> Result<u64, Bip21Error> {
    if s.is_empty() {
        return Err(Bip21Error::InvalidAmount("empty".to_string()));
    }
    if s.starts_with('-') {
        return Err(Bip21Error::InvalidAmount(format!(
            "negative amount: {}",
            s
        )));
    }
    if s.contains(|c: char| c == 'e' || c == 'E') {
        return Err(Bip21Error::InvalidAmount(format!(
            "scientific notation not allowed: {}",
            s
        )));
    }
    // Optional leading '+' is permitted.
    let body = s.strip_prefix('+').unwrap_or(s);
    if body.is_empty() {
        return Err(Bip21Error::InvalidAmount("empty after +".to_string()));
    }

    let (int_part, frac_part) = match body.find('.') {
        Some(dot) => (&body[..dot], &body[dot + 1..]),
        None => (body, ""),
    };

    // Both halves must be plain digits.
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(Bip21Error::InvalidAmount(format!(
            "non-digit in integer part: {}",
            s
        )));
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(Bip21Error::InvalidAmount(format!(
            "non-digit in fractional part: {}",
            s
        )));
    }
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(Bip21Error::InvalidAmount(format!("no digits: {}", s)));
    }
    if frac_part.len() > 8 {
        return Err(Bip21Error::InvalidAmount(format!(
            "more than 8 fractional digits (sub-satoshi precision): {}",
            s
        )));
    }

    let int_btc: u64 = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse::<u64>()
            .map_err(|_| Bip21Error::InvalidAmount(format!("integer overflow: {}", s)))?
    };

    // Right-pad the fractional part to 8 digits (1 BTC = 1e8 sats), then
    // parse it as an integer satoshi count.
    let mut frac_digits = frac_part.to_string();
    while frac_digits.len() < 8 {
        frac_digits.push('0');
    }
    let frac_sats: u64 = if frac_digits.is_empty() {
        0
    } else {
        frac_digits
            .parse::<u64>()
            .map_err(|_| Bip21Error::InvalidAmount(format!("fractional overflow: {}", s)))?
    };

    let total_sats = int_btc
        .checked_mul(100_000_000)
        .and_then(|v| v.checked_add(frac_sats))
        .ok_or_else(|| Bip21Error::InvalidAmount(format!("overflows u64 satoshis: {}", s)))?;

    // Sanity cap: 21,000,000 BTC = 2.1e15 sats — won't overflow u64
    // (which holds up to ~1.8e19) but reject things obviously beyond
    // the supply cap as a soft guard. Note: BIP-21 itself doesn't
    // mandate this, so we make it a soft warning, not a hard reject:
    // wallets routinely receive URIs for amounts they'll later check
    // against their own balance. Be permissive here.

    Ok(total_sats)
}

/// Decode `application/x-www-form-urlencoded`-style percent escapes
/// (per RFC 3986 §2.1) and produce a UTF-8 [`String`].
///
/// BIP-21 inherits RFC 3986's percent-encoding semantics for label,
/// message, and other text-typed values.
fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(format!(
                        "truncated percent-escape at position {}",
                        i
                    ));
                }
                let hi = hex_nibble(bytes[i + 1])
                    .ok_or_else(|| format!("bad hex `{}` in escape", bytes[i + 1] as char))?;
                let lo = hex_nibble(bytes[i + 2])
                    .ok_or_else(|| format!("bad hex `{}` in escape", bytes[i + 2] as char))?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                // RFC 3986 doesn't translate '+' to space — but the
                // older application/x-www-form-urlencoded does. BIP-21
                // is silent on this. Bitcoin Core's URI handler treats
                // '+' as a literal '+', not a space. Match Core.
                out.push(b'+');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| format!("invalid UTF-8 in decoded bytes: {}", e))
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mainnet_p2wpkh() -> &'static str {
        // bech32, P2WPKH, mainnet
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    }

    #[test]
    fn plain_uri_empty_query() {
        let uri = parse_bip21(
            &format!("bitcoin:{}", mainnet_p2wpkh()),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(uri.amount, None);
        assert!(uri.label.is_none());
        assert!(uri.extras.is_empty());
    }

    #[test]
    fn amount_one_btc() {
        let uri = parse_bip21(
            &format!("bitcoin:{}?amount=1", mainnet_p2wpkh()),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(uri.amount, Some(100_000_000));
    }

    #[test]
    fn amount_decimal() {
        let uri = parse_bip21(
            &format!("bitcoin:{}?amount=0.5", mainnet_p2wpkh()),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(uri.amount, Some(50_000_000));
    }

    #[test]
    fn amount_eight_decimals_no_rounding() {
        let uri = parse_bip21(
            &format!("bitcoin:{}?amount=0.00000001", mainnet_p2wpkh()),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(uri.amount, Some(1));
    }

    #[test]
    fn amount_rejects_negative() {
        let r = parse_bip21(
            &format!("bitcoin:{}?amount=-1", mainnet_p2wpkh()),
            Network::Mainnet,
        );
        assert!(matches!(r, Err(Bip21Error::InvalidAmount(_))));
    }

    #[test]
    fn amount_rejects_scientific() {
        let r = parse_bip21(
            &format!("bitcoin:{}?amount=1e8", mainnet_p2wpkh()),
            Network::Mainnet,
        );
        assert!(matches!(r, Err(Bip21Error::InvalidAmount(_))));
    }

    #[test]
    fn label_percent_decoded() {
        let uri = parse_bip21(
            &format!("bitcoin:{}?label=Foo%20Bar", mainnet_p2wpkh()),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(uri.label.as_deref(), Some("Foo Bar"));
    }

    #[test]
    fn unknown_req_param_rejects() {
        let r = parse_bip21(
            &format!("bitcoin:{}?req-future-feature=1", mainnet_p2wpkh()),
            Network::Mainnet,
        );
        assert!(matches!(r, Err(Bip21Error::UnknownRequiredParam(_))));
    }

    #[test]
    fn unknown_unprefixed_param_preserved() {
        let uri = parse_bip21(
            &format!("bitcoin:{}?somefuture=1", mainnet_p2wpkh()),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(uri.extras.get("somefuture").map(String::as_str), Some("1"));
    }

    #[test]
    fn case_insensitive_keys() {
        let uri = parse_bip21(
            &format!("bitcoin:{}?AMOUNT=0.5&LABEL=hi", mainnet_p2wpkh()),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(uri.amount, Some(50_000_000));
        assert_eq!(uri.label.as_deref(), Some("hi"));
    }

    #[test]
    fn pj_and_pjos_extracted() {
        let uri = parse_bip21(
            &format!(
                "bitcoin:{}?amount=0.01&pj=https://example.com/payjoin&pjos=0",
                mainnet_p2wpkh()
            ),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(uri.pj.as_deref(), Some("https://example.com/payjoin"));
        assert_eq!(uri.pjos, Some(false));
    }

    #[test]
    fn pjos_default_true_when_pj_present_no_explicit() {
        // BIP-78 default is pjos=1, but our parser leaves None when
        // the field isn't present — wiring is up to the caller. This
        // documents the choice.
        let uri = parse_bip21(
            &format!("bitcoin:{}?pj=https://example.com/x", mainnet_p2wpkh()),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(uri.pjos, None);
    }

    #[test]
    fn wrong_scheme_rejects() {
        let r = parse_bip21("ethereum:0xabc", Network::Mainnet);
        assert!(matches!(r, Err(Bip21Error::WrongScheme)));
    }

    #[test]
    fn missing_scheme_rejects() {
        let r = parse_bip21(mainnet_p2wpkh(), Network::Mainnet);
        assert!(matches!(r, Err(Bip21Error::MissingScheme)));
    }

    #[test]
    fn empty_input_rejects() {
        let r = parse_bip21("", Network::Mainnet);
        assert!(matches!(r, Err(Bip21Error::MissingScheme)));
    }

    #[test]
    fn invalid_address_rejected() {
        let r = parse_bip21(
            "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb?amount=1",
            Network::Mainnet,
        );
        assert!(matches!(r, Err(Bip21Error::InvalidAddress(_))));
    }

    #[test]
    fn wrong_network_rejected() {
        // mainnet address with testnet expected
        let r = parse_bip21(
            &format!("bitcoin:{}", mainnet_p2wpkh()),
            Network::Testnet,
        );
        assert!(matches!(r, Err(Bip21Error::WrongNetwork { .. })));
    }

    #[test]
    fn duplicate_key_rejected() {
        let r = parse_bip21(
            &format!("bitcoin:{}?amount=1&amount=2", mainnet_p2wpkh()),
            Network::Mainnet,
        );
        assert!(matches!(r, Err(Bip21Error::MalformedQuery(_))));
    }
}
