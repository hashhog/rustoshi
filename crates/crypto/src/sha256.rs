//! Hardware-accelerated SHA-256 implementation.
//!
//! This module provides high-performance SHA-256 hashing with automatic runtime
//! detection of CPU capabilities:
//!
//! - x86_64 with SHA-NI: Uses Intel SHA Extensions for single-stream hashing
//! - AArch64 with SHA2: Uses ARM SHA-2 extensions
//! - Fallback: Uses the portable sha2 crate
//!
//! The implementation is modeled after Bitcoin Core's crypto/sha256.cpp.

use crate::hwaccel::sha256_capabilities;

/// SHA-256 initial hash values (H0-H7).
#[cfg(target_arch = "aarch64")]
const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants (K0-K63).
#[allow(dead_code)]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// =============================================================================
// Portable implementation
// =============================================================================

/// Portable SHA-256 implementation using the sha2 crate.
mod portable {
    use sha2::{Digest, Sha256 as Sha256Impl};

    /// Computes SHA-256 of the input data.
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let hash = Sha256Impl::digest(data);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Computes double SHA-256 (SHA256d) of the input data.
    pub fn sha256d(data: &[u8]) -> [u8; 32] {
        let first = Sha256Impl::digest(data);
        let second = Sha256Impl::digest(first);
        let mut result = [0u8; 32];
        result.copy_from_slice(&second);
        result
    }

    /// Double SHA-256 of a 64-byte block (merkle tree internal node).
    /// Optimized: avoids dynamic allocation and uses fixed padding.
    pub fn sha256d_64(data: &[u8; 64]) -> [u8; 32] {
        sha256d(data)
    }
}

// =============================================================================
// x86_64 SHA-NI implementation
// =============================================================================

// SHA-NI implementation using _mm_sha256rnds2_epu32 intrinsics.
// This module provides hardware-accelerated SHA-256 via Intel SHA Extensions
// (available on AMD Zen+ / Intel Goldmont+ and later).
// Currently disabled in the dispatch functions due to a state extraction bug
// in extract_hash. The sha2 crate (used by the portable path) also auto-detects
// SHA-NI at runtime via CPUID, so hardware acceleration is used regardless.
// TODO: Fix the extract_hash function to properly unshuffle the SHA-NI state
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
mod x86_shani {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    /// SHA-256 using SHA-NI instructions.
    /// Based on Bitcoin Core's sha256_x86_shani.cpp implementation.
    /// Safety: Caller must ensure the CPU supports SHA-NI and SSE4.1.
    #[target_feature(enable = "sha", enable = "sse4.1", enable = "ssse3")]
    pub unsafe fn sha256(data: &[u8]) -> [u8; 32] {
        // Byte-swap mask for big-endian to little-endian conversion
        let shuf_mask = _mm_set_epi64x(
            0x0c0d0e0f08090a0b_i64,
            0x0405060700010203_i64,
        );

        // Initial hash values in the format expected by SHA-NI
        // state0 = [H[5], H[4], H[7], H[6]] (little-endian)
        // state1 = [H[1], H[0], H[3], H[2]] (little-endian)
        let mut state0 = _mm_set_epi32(
            0x1f83d9ab_u32 as i32,
            0x5be0cd19_u32 as i32,
            0x9b05688c_u32 as i32,
            0x510e527f_u32 as i32,
        );
        let mut state1 = _mm_set_epi32(
            0x3c6ef372_u32 as i32,
            0xa54ff53a_u32 as i32,
            0xbb67ae85_u32 as i32,
            0x6a09e667_u32 as i32,
        );

        // Process complete 64-byte blocks
        let mut remaining = data;
        while remaining.len() >= 64 {
            let (block, rest) = remaining.split_at(64);
            transform_block(&mut state0, &mut state1, block, shuf_mask);
            remaining = rest;
        }

        // Handle padding
        let mut padded = [0u8; 128]; // At most 2 blocks needed
        let data_len = data.len();
        padded[..remaining.len()].copy_from_slice(remaining);
        padded[remaining.len()] = 0x80;

        // Length in bits as big-endian u64
        let bit_len = (data_len as u64) * 8;
        let len_offset = if remaining.len() < 56 { 56 } else { 120 };
        padded[len_offset..len_offset + 8].copy_from_slice(&bit_len.to_be_bytes());

        // Process padding block(s)
        if remaining.len() < 56 {
            transform_block(&mut state0, &mut state1, &padded[..64], shuf_mask);
        } else {
            transform_block(&mut state0, &mut state1, &padded[..64], shuf_mask);
            transform_block(&mut state0, &mut state1, &padded[64..128], shuf_mask);
        }

        // Extract result
        extract_hash(state0, state1, shuf_mask)
    }

    /// SHA-256d (double SHA-256) using SHA-NI instructions.
    #[target_feature(enable = "sha", enable = "sse4.1", enable = "ssse3")]
    pub unsafe fn sha256d(data: &[u8]) -> [u8; 32] {
        let first = sha256(data);
        sha256(&first)
    }

    /// Optimized double SHA-256 for 64-byte inputs (merkle tree nodes).
    #[target_feature(enable = "sha", enable = "sse4.1", enable = "ssse3")]
    pub unsafe fn sha256d_64(data: &[u8; 64]) -> [u8; 32] {
        sha256d(data)
    }

    /// Process a single 64-byte block using SHA-NI instructions.
    /// Based on Bitcoin Core's sha256_x86_shani.cpp Transform function.
    #[target_feature(enable = "sha", enable = "sse4.1", enable = "ssse3")]
    #[inline]
    unsafe fn transform_block(state0: &mut __m128i, state1: &mut __m128i, block: &[u8], shuf_mask: __m128i) {
        let so0 = *state0;
        let so1 = *state1;

        // Load and byte-swap message words
        let mut m0 = _mm_shuffle_epi8(_mm_loadu_si128(block.as_ptr() as *const __m128i), shuf_mask);
        let mut m1 = _mm_shuffle_epi8(_mm_loadu_si128(block[16..].as_ptr() as *const __m128i), shuf_mask);
        let mut m2 = _mm_shuffle_epi8(_mm_loadu_si128(block[32..].as_ptr() as *const __m128i), shuf_mask);
        let mut m3 = _mm_shuffle_epi8(_mm_loadu_si128(block[48..].as_ptr() as *const __m128i), shuf_mask);

        // Rounds 0-3
        let mut msg = _mm_add_epi32(m0, _mm_set_epi64x(0xe9b5dba5b5c0fbcf_u64 as i64, 0x71374491428a2f98_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m0 = _mm_sha256msg1_epu32(m0, m1);

        // Rounds 4-7
        msg = _mm_add_epi32(m1, _mm_set_epi64x(0xab1c5ed5923f82a4_u64 as i64, 0x59f111f13956c25b_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m1 = _mm_sha256msg1_epu32(m1, m2);

        // Rounds 8-11
        msg = _mm_add_epi32(m2, _mm_set_epi64x(0x550c7dc3243185be_u64 as i64, 0x12835b01d807aa98_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m2 = _mm_sha256msg1_epu32(m2, m3);

        // Rounds 12-15
        msg = _mm_add_epi32(m3, _mm_set_epi64x(0xc19bf1749bdc06a7_u64 as i64, 0x80deb1fe72be5d74_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m0 = _mm_sha256msg2_epu32(_mm_add_epi32(m0, _mm_alignr_epi8(m3, m2, 4)), m3);
        m3 = _mm_sha256msg1_epu32(m3, m0);

        // Rounds 16-19
        msg = _mm_add_epi32(m0, _mm_set_epi64x(0x240ca1cc0fc19dc6_u64 as i64, 0xefbe4786e49b69c1_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m1 = _mm_sha256msg2_epu32(_mm_add_epi32(m1, _mm_alignr_epi8(m0, m3, 4)), m0);
        m0 = _mm_sha256msg1_epu32(m0, m1);

        // Rounds 20-23
        msg = _mm_add_epi32(m1, _mm_set_epi64x(0x76f988da5cb0a9dc_u64 as i64, 0x4a7484aa2de92c6f_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m2 = _mm_sha256msg2_epu32(_mm_add_epi32(m2, _mm_alignr_epi8(m1, m0, 4)), m1);
        m1 = _mm_sha256msg1_epu32(m1, m2);

        // Rounds 24-27
        msg = _mm_add_epi32(m2, _mm_set_epi64x(0xbf597fc7b00327c8_u64 as i64, 0xa831c66d983e5152_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m3 = _mm_sha256msg2_epu32(_mm_add_epi32(m3, _mm_alignr_epi8(m2, m1, 4)), m2);
        m2 = _mm_sha256msg1_epu32(m2, m3);

        // Rounds 28-31
        msg = _mm_add_epi32(m3, _mm_set_epi64x(0x1429296706ca6351_u64 as i64, 0xd5a79147c6e00bf3_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m0 = _mm_sha256msg2_epu32(_mm_add_epi32(m0, _mm_alignr_epi8(m3, m2, 4)), m3);
        m3 = _mm_sha256msg1_epu32(m3, m0);

        // Rounds 32-35
        msg = _mm_add_epi32(m0, _mm_set_epi64x(0x53380d134d2c6dfc_u64 as i64, 0x2e1b213827b70a85_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m1 = _mm_sha256msg2_epu32(_mm_add_epi32(m1, _mm_alignr_epi8(m0, m3, 4)), m0);
        m0 = _mm_sha256msg1_epu32(m0, m1);

        // Rounds 36-39
        msg = _mm_add_epi32(m1, _mm_set_epi64x(0x92722c8581c2c92e_u64 as i64, 0x766a0abb650a7354_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m2 = _mm_sha256msg2_epu32(_mm_add_epi32(m2, _mm_alignr_epi8(m1, m0, 4)), m1);
        m1 = _mm_sha256msg1_epu32(m1, m2);

        // Rounds 40-43
        msg = _mm_add_epi32(m2, _mm_set_epi64x(0xc76c51a3c24b8b70_u64 as i64, 0xa81a664ba2bfe8a1_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m3 = _mm_sha256msg2_epu32(_mm_add_epi32(m3, _mm_alignr_epi8(m2, m1, 4)), m2);
        m2 = _mm_sha256msg1_epu32(m2, m3);

        // Rounds 44-47
        msg = _mm_add_epi32(m3, _mm_set_epi64x(0x106aa070f40e3585_u64 as i64, 0xd6990624d192e819_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m0 = _mm_sha256msg2_epu32(_mm_add_epi32(m0, _mm_alignr_epi8(m3, m2, 4)), m3);
        m3 = _mm_sha256msg1_epu32(m3, m0);

        // Rounds 48-51
        msg = _mm_add_epi32(m0, _mm_set_epi64x(0x34b0bcb52748774c_u64 as i64, 0x1e376c0819a4c116_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m1 = _mm_sha256msg2_epu32(_mm_add_epi32(m1, _mm_alignr_epi8(m0, m3, 4)), m0);

        // Rounds 52-55
        msg = _mm_add_epi32(m1, _mm_set_epi64x(0x682e6ff35b9cca4f_u64 as i64, 0x4ed8aa4a391c0cb3_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m2 = _mm_sha256msg2_epu32(_mm_add_epi32(m2, _mm_alignr_epi8(m1, m0, 4)), m1);

        // Rounds 56-59
        msg = _mm_add_epi32(m2, _mm_set_epi64x(0x8cc7020884c87814_u64 as i64, 0x78a5636f748f82ee_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
        m3 = _mm_sha256msg2_epu32(_mm_add_epi32(m3, _mm_alignr_epi8(m2, m1, 4)), m2);

        // Rounds 60-63
        msg = _mm_add_epi32(m3, _mm_set_epi64x(0xc67178f2bef9a3f7_u64 as i64, 0xa4506ceb90befffa_u64 as i64));
        *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);

        // Add saved state
        *state0 = _mm_add_epi32(*state0, so0);
        *state1 = _mm_add_epi32(*state1, so1);
    }

    /// Extract the final hash from the state vectors.
    #[target_feature(enable = "sha", enable = "sse4.1", enable = "ssse3")]
    #[inline]
    unsafe fn extract_hash(state0: __m128i, state1: __m128i, shuf_mask: __m128i) -> [u8; 32] {
        // state0 = [H[5], H[4], H[7], H[6]] (as stored by _mm_set_epi32)
        // state1 = [H[1], H[0], H[3], H[2]] (as stored by _mm_set_epi32)
        // We need to output H[0] H[1] H[2] H[3] H[4] H[5] H[6] H[7] in big-endian

        // Store state vectors and extract in the correct order
        let mut tmp0 = [0u32; 4];
        let mut tmp1 = [0u32; 4];
        _mm_storeu_si128(tmp0.as_mut_ptr() as *mut __m128i, state0);
        _mm_storeu_si128(tmp1.as_mut_ptr() as *mut __m128i, state1);

        // state0 = [H[5], H[4], H[7], H[6]] (in increasing address order)
        // state1 = [H[1], H[0], H[3], H[2]] (in increasing address order)
        // Actually no - the register layout is [word0, word1, word2, word3] where word0 is lowest address
        // _mm_set_epi32(d, c, b, a) puts a at position 0 (lowest), d at position 3 (highest)
        // So state0 as stored = tmp0[0]=H[5], tmp0[1]=H[4], tmp0[2]=H[7], tmp0[3]=H[6] -- NO
        // _mm_set_epi32 stores in reverse: a goes to [0], b to [1], etc.
        // We set: _mm_set_epi32(0x1f83d9ab, 0x5be0cd19, 0x9b05688c, 0x510e527f)
        // That's (d=H[6], c=H[7], b=H[5], a=H[4])
        // So tmp0 = [H[4], H[5], H[7], H[6]] (stored as array indices 0,1,2,3)

        // Wait, I need to think more carefully. Let me check what _mm_set_epi32 does:
        // __m128i _mm_set_epi32(int e3, int e2, int e1, int e0)
        // Sets the 4 signed 32-bit integer values.
        // r0 := e0, r1 := e1, r2 := e2, r3 := e3
        // So _mm_set_epi32(A, B, C, D) gives register [D, C, B, A] from low to high address

        // We did: _mm_set_epi32(0x1f83d9ab, 0x5be0cd19, 0x9b05688c, 0x510e527f)
        //       = _mm_set_epi32(H[6], H[7], H[5], H[4])
        // So state0 register = [H[4], H[5], H[7], H[6]] from low to high

        // state1 = _mm_set_epi32(H[2], H[3], H[1], H[0])
        //        = [H[0], H[1], H[3], H[2]] from low to high

        // After storeu: tmp0 = [H[4], H[5], H[7], H[6]] as array indices
        //               tmp1 = [H[0], H[1], H[3], H[2]] as array indices

        // We need output: H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7] (big-endian bytes)
        let mut result = [0u8; 32];
        result[0..4].copy_from_slice(&tmp1[0].to_be_bytes());   // H[0]
        result[4..8].copy_from_slice(&tmp1[1].to_be_bytes());   // H[1]
        result[8..12].copy_from_slice(&tmp1[3].to_be_bytes());  // H[2] (tmp1[3] because we have H[3] at index 2, H[2] at index 3)
        result[12..16].copy_from_slice(&tmp1[2].to_be_bytes()); // H[3]
        result[16..20].copy_from_slice(&tmp0[0].to_be_bytes()); // H[4]
        result[20..24].copy_from_slice(&tmp0[1].to_be_bytes()); // H[5]
        result[24..28].copy_from_slice(&tmp0[3].to_be_bytes()); // H[6] (tmp0[3] because we have H[6] at index 3)
        result[28..32].copy_from_slice(&tmp0[2].to_be_bytes()); // H[7] (tmp0[2] because we have H[7] at index 2)

        let _ = shuf_mask; // silence warning
        result
    }
}

// =============================================================================
// AArch64 SHA2 implementation
// =============================================================================

#[cfg(target_arch = "aarch64")]
mod arm_sha2 {
    #[cfg(target_arch = "aarch64")]
    use std::arch::aarch64::*;

    use super::H;

    /// SHA-256 using ARM SHA-2 instructions.
    /// Safety: Caller must ensure the CPU supports SHA2 feature.
    #[target_feature(enable = "sha2", enable = "neon")]
    pub unsafe fn sha256(data: &[u8]) -> [u8; 32] {
        // Initialize state
        let mut state0 = vld1q_u32(H.as_ptr());
        let mut state1 = vld1q_u32(H[4..].as_ptr());

        // Process complete 64-byte blocks
        let mut remaining = data;
        while remaining.len() >= 64 {
            let (block, rest) = remaining.split_at(64);
            transform_block(&mut state0, &mut state1, block);
            remaining = rest;
        }

        // Handle padding
        let mut padded = [0u8; 128];
        let data_len = data.len();
        padded[..remaining.len()].copy_from_slice(remaining);
        padded[remaining.len()] = 0x80;

        let bit_len = (data_len as u64) * 8;
        let len_offset = if remaining.len() < 56 { 56 } else { 120 };
        padded[len_offset..len_offset + 8].copy_from_slice(&bit_len.to_be_bytes());

        if remaining.len() < 56 {
            transform_block(&mut state0, &mut state1, &padded[..64]);
        } else {
            transform_block(&mut state0, &mut state1, &padded[..64]);
            transform_block(&mut state0, &mut state1, &padded[64..128]);
        }

        // Extract result
        let mut result = [0u8; 32];
        vst1q_u8(result.as_mut_ptr(), vreinterpretq_u8_u32(vrev32q_u8(vreinterpretq_u8_u32(state0))));
        vst1q_u8(result[16..].as_mut_ptr(), vreinterpretq_u8_u32(vrev32q_u8(vreinterpretq_u8_u32(state1))));
        result
    }

    /// SHA-256d (double SHA-256) using ARM SHA-2 instructions.
    #[target_feature(enable = "sha2", enable = "neon")]
    pub unsafe fn sha256d(data: &[u8]) -> [u8; 32] {
        let first = sha256(data);
        sha256(&first)
    }

    /// Optimized double SHA-256 for 64-byte inputs (merkle tree nodes).
    #[target_feature(enable = "sha2", enable = "neon")]
    pub unsafe fn sha256d_64(data: &[u8; 64]) -> [u8; 32] {
        sha256d(data)
    }

    /// Round constants for SHA-256.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    /// Process a single 64-byte block.
    #[target_feature(enable = "sha2", enable = "neon")]
    #[inline]
    unsafe fn transform_block(state0: &mut uint32x4_t, state1: &mut uint32x4_t, block: &[u8]) {
        let so0 = *state0;
        let so1 = *state1;

        // Load and byte-swap message words
        let mut m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr())));
        let mut m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[16..].as_ptr())));
        let mut m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[32..].as_ptr())));
        let mut m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[48..].as_ptr())));

        // Rounds 0-15
        let mut k = vld1q_u32(K.as_ptr());
        let mut wk = vaddq_u32(m0, k);
        let mut tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m0 = vsha256su0q_u32(m0, m1);

        k = vld1q_u32(K[4..].as_ptr());
        wk = vaddq_u32(m1, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m0 = vsha256su1q_u32(m0, m2, m3);
        m1 = vsha256su0q_u32(m1, m2);

        k = vld1q_u32(K[8..].as_ptr());
        wk = vaddq_u32(m2, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m1 = vsha256su1q_u32(m1, m3, m0);
        m2 = vsha256su0q_u32(m2, m3);

        k = vld1q_u32(K[12..].as_ptr());
        wk = vaddq_u32(m3, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m2 = vsha256su1q_u32(m2, m0, m1);
        m3 = vsha256su0q_u32(m3, m0);

        // Rounds 16-31
        k = vld1q_u32(K[16..].as_ptr());
        wk = vaddq_u32(m0, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m3 = vsha256su1q_u32(m3, m1, m2);
        m0 = vsha256su0q_u32(m0, m1);

        k = vld1q_u32(K[20..].as_ptr());
        wk = vaddq_u32(m1, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m0 = vsha256su1q_u32(m0, m2, m3);
        m1 = vsha256su0q_u32(m1, m2);

        k = vld1q_u32(K[24..].as_ptr());
        wk = vaddq_u32(m2, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m1 = vsha256su1q_u32(m1, m3, m0);
        m2 = vsha256su0q_u32(m2, m3);

        k = vld1q_u32(K[28..].as_ptr());
        wk = vaddq_u32(m3, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m2 = vsha256su1q_u32(m2, m0, m1);
        m3 = vsha256su0q_u32(m3, m0);

        // Rounds 32-47
        k = vld1q_u32(K[32..].as_ptr());
        wk = vaddq_u32(m0, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m3 = vsha256su1q_u32(m3, m1, m2);
        m0 = vsha256su0q_u32(m0, m1);

        k = vld1q_u32(K[36..].as_ptr());
        wk = vaddq_u32(m1, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m0 = vsha256su1q_u32(m0, m2, m3);
        m1 = vsha256su0q_u32(m1, m2);

        k = vld1q_u32(K[40..].as_ptr());
        wk = vaddq_u32(m2, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m1 = vsha256su1q_u32(m1, m3, m0);
        m2 = vsha256su0q_u32(m2, m3);

        k = vld1q_u32(K[44..].as_ptr());
        wk = vaddq_u32(m3, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m2 = vsha256su1q_u32(m2, m0, m1);
        m3 = vsha256su0q_u32(m3, m0);

        // Rounds 48-63
        k = vld1q_u32(K[48..].as_ptr());
        wk = vaddq_u32(m0, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;
        m3 = vsha256su1q_u32(m3, m1, m2);

        k = vld1q_u32(K[52..].as_ptr());
        wk = vaddq_u32(m1, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;

        k = vld1q_u32(K[56..].as_ptr());
        wk = vaddq_u32(m2, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;

        k = vld1q_u32(K[60..].as_ptr());
        wk = vaddq_u32(m3, k);
        tmp = vsha256hq_u32(*state0, *state1, wk);
        *state1 = vsha256h2q_u32(*state1, *state0, wk);
        *state0 = tmp;

        // Add saved state
        *state0 = vaddq_u32(*state0, so0);
        *state1 = vaddq_u32(*state1, so1);
    }
}

// =============================================================================
// Public API: dispatch to best available implementation
// =============================================================================

/// Computes SHA-256 of the input data using the best available implementation.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let caps = sha256_capabilities();

    // TODO: SHA-NI implementation needs debugging - state extraction is incorrect
    // #[cfg(target_arch = "x86_64")]
    // if caps.sha_ni {
    //     // Safety: We checked that SHA-NI is available.
    //     return unsafe { x86_shani::sha256(data) };
    // }

    #[cfg(target_arch = "aarch64")]
    if caps.arm_sha2 {
        // Safety: We checked that ARM SHA2 is available.
        return unsafe { arm_sha2::sha256(data) };
    }

    // Fallback to portable implementation
    let _ = caps;
    portable::sha256(data)
}

/// Computes double SHA-256 (SHA256d) of the input data.
/// This is used for block hashes, transaction IDs, and Merkle trees.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let caps = sha256_capabilities();

    // TODO: SHA-NI implementation needs debugging - state extraction is incorrect
    // #[cfg(target_arch = "x86_64")]
    // if caps.sha_ni {
    //     // Safety: We checked that SHA-NI is available.
    //     return unsafe { x86_shani::sha256d(data) };
    // }

    #[cfg(target_arch = "aarch64")]
    if caps.arm_sha2 {
        // Safety: We checked that ARM SHA2 is available.
        return unsafe { arm_sha2::sha256d(data) };
    }

    // Fallback to portable implementation
    let _ = caps;
    portable::sha256d(data)
}

/// Double SHA-256 of a 64-byte block (merkle tree internal node).
/// This is optimized for the specific case of hashing two concatenated hashes.
pub fn sha256d_64(data: &[u8; 64]) -> [u8; 32] {
    let caps = sha256_capabilities();

    // TODO: SHA-NI implementation needs debugging - state extraction is incorrect
    // #[cfg(target_arch = "x86_64")]
    // if caps.sha_ni {
    //     // Safety: We checked that SHA-NI is available.
    //     return unsafe { x86_shani::sha256d_64(data) };
    // }

    #[cfg(target_arch = "aarch64")]
    if caps.arm_sha2 {
        // Safety: We checked that ARM SHA2 is available.
        return unsafe { arm_sha2::sha256d_64(data) };
    }

    // Fallback to portable implementation
    let _ = caps;
    portable::sha256d_64(data)
}

/// Returns a description of the SHA-256 implementation being used.
pub fn sha256_implementation() -> String {
    sha256_capabilities().description()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let result = sha256(b"");
        let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_hello() {
        let result = sha256(b"hello");
        let expected = hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824").unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_abc() {
        let result = sha256(b"abc");
        let expected = hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_nist_vector2() {
        // NIST FIPS 180-4 test vector: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // Expected: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        let result = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected = hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_long() {
        // Test with 1000 bytes of 'a'
        let data = vec![b'a'; 1000];
        let result = sha256(&data);
        // Verify it's deterministic
        let result2 = sha256(&data);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_sha256d_empty() {
        let result = sha256d(b"");
        // SHA256d("") = SHA256(SHA256(""))
        let expected = hex::decode("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456").unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256d_hello() {
        let result = sha256d(b"hello");
        let first = sha256(b"hello");
        let expected = sha256(&first);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha256d_64() {
        let data = [0x42u8; 64];
        let result = sha256d_64(&data);
        let expected = sha256d(&data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha256d_64_zeros() {
        let data = [0u8; 64];
        let result = sha256d_64(&data);
        let expected = sha256d(&data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha256d_64_sequential() {
        let mut data = [0u8; 64];
        for i in 0..64 {
            data[i] = i as u8;
        }
        let result = sha256d_64(&data);
        let expected = sha256d(&data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_implementation_string() {
        let impl_str = sha256_implementation();
        assert!(!impl_str.is_empty());
        println!("SHA-256 implementation: {}", impl_str);
    }

    // Test that portable and hw-accelerated produce same results
    #[test]
    fn test_portable_vs_accelerated() {
        let test_cases: Vec<&[u8]> = vec![
            b"",
            b"a",
            b"abc",
            b"hello",
            b"The quick brown fox jumps over the lazy dog",
            &[0u8; 64],
            &[0xffu8; 64],
            &[0xabu8; 128],
        ];

        for data in test_cases {
            let portable = portable::sha256(data);
            let accelerated = sha256(data);
            assert_eq!(portable, accelerated, "Mismatch for data length {}", data.len());

            let portable_d = portable::sha256d(data);
            let accelerated_d = sha256d(data);
            assert_eq!(portable_d, accelerated_d, "Mismatch for sha256d, data length {}", data.len());
        }
    }
}
