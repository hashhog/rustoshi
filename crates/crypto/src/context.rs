//! Process-wide secp256k1 context with side-channel blinding.
//!
//! Bitcoin Core's `ECC_Start` (`bitcoin-core/src/key.cpp:572-587`) creates the
//! process-wide signing context exactly once and immediately calls
//! `secp256k1_context_randomize(ctx, vseed.data())` with 32 bytes from
//! `GetRandBytes(vseed)`. The randomization seeds the per-context scalar
//! blinding (`secp256k1_scalar_blind`) which is the published defense against
//! differential side-channel attacks on the C `ecmult_const` codepath.
//!
//! Without it, every sign / derive call uses the default zero blinding —
//! publicly known seed material — and leaks more state through EM/timing/power
//! side channels than the equivalent Core operation. The libsecp256k1 header
//! comment is explicit (`secp256k1.h:285-290`):
//! *"it is highly recommended to call secp256k1_context_randomize on the
//!   context before calling any sign-related ECDSA functions"*.
//!
//! Rustoshi historically created a fresh `Secp256k1::new()` at every signing
//! / derivation site (~31 production sites; cf. W159 BUG-4 + W161 BUG-7) AND
//! never randomized any of them. This module closes that gap by providing a
//! single process-wide `Secp256k1<All>` that is randomized at first use.
//!
//! Use [`secp_ctx`] anywhere a `&Secp256k1<All>` (sign + verify) is needed.

use std::sync::OnceLock;

use secp256k1::{All, Secp256k1};

static SECP_CTX: OnceLock<Secp256k1<All>> = OnceLock::new();

/// Returns a process-wide `Secp256k1<All>` context, initialised with
/// side-channel-blinding randomization on first use.
///
/// Mirrors Bitcoin Core's `ECC_Start` (`key.cpp:572-587`): one context per
/// process, randomized once with 32 fresh bytes from the OS CSPRNG. Reusing
/// the same context avoids per-call allocation of the ~150KiB (with
/// `lowmemory`) precomputation tables, AND ensures every sign / derive op
/// goes through a blinded context — closing the
/// "side-channel-blinding-disabled" UNIVERSAL fleet pattern (W159 / W161).
pub fn secp_ctx() -> &'static Secp256k1<All> {
    SECP_CTX.get_or_init(|| {
        let mut ctx = Secp256k1::new();
        let mut rng = rand::thread_rng();
        ctx.randomize(&mut rng);
        ctx
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_same_context_on_repeat_calls() {
        let a = secp_ctx() as *const _;
        let b = secp_ctx() as *const _;
        assert_eq!(a, b, "secp_ctx should return the same process-wide context");
    }

    #[test]
    fn signs_and_verifies_through_blinded_context() {
        use secp256k1::{Message, SecretKey};
        let secp = secp_ctx();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(secp, &secret);
        let msg = Message::from_digest([7u8; 32]);
        let sig = secp.sign_ecdsa(&msg, &secret);
        assert!(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok());
    }
}
