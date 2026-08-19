// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of SHA-384 and SHA-512.

use alloc::vec::Vec;
use core::array;
use zkboo::backend::{Allocator, Backend, WordRef};
// use zkboo::circuit::Circuit;

fn zip_arrays<A, B, const N: usize>(lhs: [A; N], rhs: [B; N]) -> [(A, B); N] {
    let mut lhs = lhs.into_iter();
    let mut rhs = rhs.into_iter();
    return core::array::from_fn(|_| (lhs.next().unwrap(), rhs.next().unwrap()));
}

pub fn ch<B: Backend>(
    x: WordRef<B, u64>,
    y: WordRef<B, u64>,
    z: WordRef<B, u64>,
) -> WordRef<B, u64> {
    // Single-AND form of `(x & y) ^ (!x & z)`: `z ^ (x & (y ^ z))`.
    return z.clone() ^ (x & (y ^ z));
}

pub fn maj<B: Backend>(
    x: WordRef<B, u64>,
    y: WordRef<B, u64>,
    z: WordRef<B, u64>,
) -> WordRef<B, u64> {
    // Single-AND form of `(x&y) ^ (x&z) ^ (y&z)`: `x ^ ((x ^ y) & (x ^ z))`.
    return x.clone() ^ ((x.clone() ^ y) & (x ^ z));
}

pub fn bsig0<B: Backend>(x: WordRef<B, u64>) -> WordRef<B, u64> {
    return x.clone().rotate_right(28) ^ x.clone().rotate_right(34) ^ x.rotate_right(39);
}

pub fn bsig1<B: Backend>(x: WordRef<B, u64>) -> WordRef<B, u64> {
    return x.clone().rotate_right(14) ^ x.clone().rotate_right(18) ^ x.rotate_right(41);
}

pub fn ssig0<B: Backend>(x: WordRef<B, u64>) -> WordRef<B, u64> {
    return x.clone().rotate_right(1) ^ x.clone().rotate_right(8) ^ (x >> 7);
}

pub fn ssig1<B: Backend>(x: WordRef<B, u64>) -> WordRef<B, u64> {
    return x.clone().rotate_right(19) ^ x.clone().rotate_right(61) ^ (x >> 6);
}

#[rustfmt::skip]
pub const K_WORDS: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// Packs a byte string whose length is a multiple of 8 into big-endian [u64] words.
fn bytes_to_u64<B: Backend>(bytes: Vec<WordRef<B, u8>>) -> Vec<WordRef<B, u64>> {
    assert!(bytes.len() % 8 == 0, "byte length must be a multiple of 8");
    let mut words: Vec<WordRef<B, u64>> = Vec::with_capacity(bytes.len() / 8);
    let mut chunk: Vec<WordRef<B, u8>> = Vec::with_capacity(8);
    for byte in bytes {
        chunk.push(byte);
        if chunk.len() == 8 {
            words.push(WordRef::<B, u64>::from_be_bytes(core::mem::take(&mut chunk)).unwrap());
        }
    }
    return words;
}

/// The SHA-384/SHA-512 padding function.
pub fn pad_u64<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> Vec<WordRef<B, u64>> {
    return pad_u64_with_prefix(allocator, msg, 0);
}

/// Variant of [pad_u64] for a message logically preceded by `prefix_bytes` already-processed bytes
/// (used for midstate resumption).
pub fn pad_u64_with_prefix<B: Backend>(
    allocator: Allocator<B>,
    mut msg: Vec<WordRef<B, u8>>,
    prefix_bytes: usize,
) -> Vec<WordRef<B, u64>> {
    assert!(
        prefix_bytes % SHA512_BLOCKSIZE == 0,
        "prefix must be a whole number of blocks"
    );
    let l = msg.len();
    let l_mod128 = l % 128;
    let k = if l_mod128 <= 111 {
        111 - l_mod128
    } else {
        239 - l_mod128
    };
    msg.push(allocator.alloc(0x80u8));
    msg.extend((0..k).into_iter().map(|_| allocator.alloc(0u8)));
    assert!(msg.len() % 8 == 0);
    let mut msg_u64 = bytes_to_u64(msg);
    let bit_len = ((prefix_bytes + l) as u128) * 8;
    msg_u64.push(allocator.alloc((bit_len >> 64) as u64));
    msg_u64.push(allocator.alloc(bit_len as u64));
    return msg_u64;
}

pub const SHA512_BLOCKSIZE: usize = 128;

/// The SHA-512 compression function, starting from the public constant `init_hash`.
#[allow(non_snake_case)]
pub fn compress_u64<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u64>>,
    init_hash: &[u64; 8],
) -> [WordRef<B, u64>; 8] {
    let init: [WordRef<B, u64>; 8] = array::from_fn(|i| allocator.alloc(init_hash[i]));
    return compress_u64_from(allocator, msg, init);
}

/// Variant of [compress_u64] resuming from an arbitrary (possibly secret) chaining value `init`
/// instead of a public constant — the primitive behind midstate caching (e.g. resuming after a
/// fixed HMAC key block).
#[allow(non_snake_case)]
pub fn compress_u64_from<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u64>>,
    init: [WordRef<B, u64>; 8],
) -> [WordRef<B, u64>; 8] {
    const SHA512_BLOCKSIZE_U64: usize = SHA512_BLOCKSIZE / 8;
    let n = msg.len() / SHA512_BLOCKSIZE_U64;
    assert_eq!(
        n * SHA512_BLOCKSIZE_U64,
        msg.len(),
        "Message must be padded to multiple of 16 u64 words"
    );
    let mut H: [WordRef<B, u64>; 8] = init;
    for i in 0..n {
        let block = &msg.as_slice()[i * SHA512_BLOCKSIZE_U64..(i + 1) * SHA512_BLOCKSIZE_U64];
        let mut W: [WordRef<B, u64>; 80] = core::array::from_fn(|t| {
            if t < SHA512_BLOCKSIZE_U64 {
                block[t].clone()
            } else {
                allocator.alloc(0)
            }
        });
        for t in SHA512_BLOCKSIZE_U64..80 {
            W[t] = ssig1(W[t - 2].clone())
                + W[t - 7].clone()
                + ssig0(W[t - 15].clone())
                + W[t - 16].clone();
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = H.clone();
        let mut T1: WordRef<B, u64>;
        let mut T2: WordRef<B, u64>;
        for (Wt, &Kt) in W.into_iter().zip(K_WORDS.iter()) {
            T1 = h + bsig1(e.clone()) + ch(e.clone(), f.clone(), g.clone()) + Wt + Kt;
            T2 = bsig0(a.clone()) + maj(a.clone(), b.clone(), c.clone());
            [h, g, f, e, d, c, b, a] = [g, f, e, d + T1.clone(), c, b, a, T1 + T2];
        }
        H = zip_arrays([a, b, c, d, e, f, g, h], H).map(|(l, r)| l + r);
    }
    return H;
}

const SHA384_INIT_HASH: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// Computes the SHA-384 hash digest of the given message.
///
/// The message is taken as a vector of bytes ([u8] words).
/// The digest is returned as an array of 6 [u64] words.
///
/// To get an array of 48 bytes, use the [sha384bytes] function instead.
pub fn sha384<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u64>; 6] {
    let msg = pad_u64(allocator.clone(), msg);
    let [a, b, c, d, e, f, _, _] = compress_u64(allocator, msg, &SHA384_INIT_HASH);
    return [a, b, c, d, e, f];
}

/// Computes the SHA-384 hash digest of the given message.
///
/// The message is taken as a vector of bytes ([u8] words).
/// The digest is returned as an array of 48 [u8] words.
///
/// To get an array of 6 [u64] words, use the [sha384] function instead.
pub fn sha384bytes<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 48] {
    return sha384(allocator, msg)
        .into_iter()
        .flat_map(|word| word.into_be_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}

const SHA512_INIT_HASH: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Computes the SHA-512 hash digest of the given message.
///
/// The message is taken as a vector of bytes ([u8] words).
/// The digest is returned as an array of 8 [u64] words.
pub fn sha512<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u64>; 8] {
    let msg = pad_u64(allocator.clone(), msg);
    return compress_u64(allocator, msg, &SHA512_INIT_HASH);
}

/// Computes the SHA-512 hash digest of the given message.
///
/// The message is taken as a vector of bytes ([u8] words).
/// The digest is returned as an array of 64 [u8] words.
///
/// To get an array of 8 [u64] words, use the [sha512] function instead.
pub fn sha512bytes<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 64] {
    return sha512(allocator, msg)
        .into_iter()
        .flat_map(|word| word.into_be_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}

/// A reusable HMAC-SHA512 keyed state.
pub struct Sha512Hmac<B: Backend> {
    ipad_midstate: [WordRef<B, u64>; 8],
    opad_midstate: [WordRef<B, u64>; 8],
}

impl<B: Backend> Sha512Hmac<B> {
    /// Prepares the keyed state for `key`, compressing the two key blocks once.
    pub fn new(allocator: Allocator<B>, key: Vec<WordRef<B, u8>>) -> Self {
        let mut key = key;
        if key.len() > SHA512_BLOCKSIZE {
            key = sha512(allocator.clone(), key)
                .into_iter()
                .flat_map(WordRef::<B, u64>::into_be_bytes)
                .collect();
        }
        if key.len() < SHA512_BLOCKSIZE {
            key.extend((0..SHA512_BLOCKSIZE - key.len()).map(|_| allocator.alloc(0u8)));
        }
        let ipad_block = bytes_to_u64(key.iter().map(|w| w.clone() ^ 0x36u8).collect());
        let opad_block = bytes_to_u64(key.into_iter().map(|w| w ^ 0x5cu8).collect());
        let iv_i: [WordRef<B, u64>; 8] = array::from_fn(|i| allocator.alloc(SHA512_INIT_HASH[i]));
        let iv_o: [WordRef<B, u64>; 8] = array::from_fn(|i| allocator.alloc(SHA512_INIT_HASH[i]));
        return Sha512Hmac {
            ipad_midstate: compress_u64_from(allocator.clone(), ipad_block, iv_i),
            opad_midstate: compress_u64_from(allocator, opad_block, iv_o),
        };
    }

    /// Computes `HMAC-SHA512(key, msg)` reusing the cached key midstates.
    pub fn mac(&self, allocator: Allocator<B>, msg: Vec<WordRef<B, u8>>) -> [WordRef<B, u64>; 8] {
        let inner_blocks = pad_u64_with_prefix(allocator.clone(), msg, SHA512_BLOCKSIZE);
        let ipad = array::from_fn(|i| self.ipad_midstate[i].clone());
        let inner = compress_u64_from(allocator.clone(), inner_blocks, ipad);
        let inner_bytes: Vec<WordRef<B, u8>> = inner
            .into_iter()
            .flat_map(WordRef::<B, u64>::into_be_bytes)
            .collect();
        let outer_blocks = pad_u64_with_prefix(allocator.clone(), inner_bytes, SHA512_BLOCKSIZE);
        let opad = array::from_fn(|i| self.opad_midstate[i].clone());
        return compress_u64_from(allocator, outer_blocks, opad);
    }

    /// Convenience [Sha512Hmac::mac] returning the 64-byte MAC.
    pub fn mac_bytes(
        &self,
        allocator: Allocator<B>,
        msg: Vec<WordRef<B, u8>>,
    ) -> [WordRef<B, u8>; 64] {
        return self
            .mac(allocator, msg)
            .into_iter()
            .flat_map(WordRef::<B, u64>::into_be_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .ok()
            .expect("64 MAC bytes");
    }
}
