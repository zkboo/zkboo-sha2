// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of SHA-224 and SHA-256.

use alloc::vec::Vec;
use core::array;
use zkboo::backend::{Allocator, Backend, WordRef};

fn zip_arrays<A, B, const N: usize>(lhs: [A; N], rhs: [B; N]) -> [(A, B); N] {
    let mut lhs = lhs.into_iter();
    let mut rhs = rhs.into_iter();
    return core::array::from_fn(|_| (lhs.next().unwrap(), rhs.next().unwrap()));
}

pub fn ch<B: Backend>(
    x: WordRef<B, u32>,
    y: WordRef<B, u32>,
    z: WordRef<B, u32>,
) -> WordRef<B, u32> {
    return (x.clone() & y) ^ (!x & z);
}

pub fn maj<B: Backend>(
    x: WordRef<B, u32>,
    y: WordRef<B, u32>,
    z: WordRef<B, u32>,
) -> WordRef<B, u32> {
    return (x.clone() & y.clone()) ^ (x & z.clone()) ^ (y & z);
}

pub fn bsig0<B: Backend>(x: WordRef<B, u32>) -> WordRef<B, u32> {
    return x.clone().rotate_right(2) ^ x.clone().rotate_right(13) ^ x.rotate_right(22);
}

pub fn bsig1<B: Backend>(x: WordRef<B, u32>) -> WordRef<B, u32> {
    return x.clone().rotate_right(6) ^ x.clone().rotate_right(11) ^ x.rotate_right(25);
}

pub fn ssig0<B: Backend>(x: WordRef<B, u32>) -> WordRef<B, u32> {
    return x.clone().rotate_right(7) ^ x.clone().rotate_right(18) ^ (x >> 3);
}

pub fn ssig1<B: Backend>(x: WordRef<B, u32>) -> WordRef<B, u32> {
    return x.clone().rotate_right(17) ^ x.clone().rotate_right(19) ^ (x >> 10);
}

#[rustfmt::skip]
pub const K_WORDS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The SHA-224/SHA-256 padding function.
pub fn pad_u32<B: Backend>(
    allocator: Allocator<B>,
    mut msg: Vec<WordRef<B, u8>>,
) -> Vec<WordRef<B, u32>> {
    let l = msg.len();
    let l_mod64 = l % 64;
    let k = if l_mod64 <= 55 {
        55 - l_mod64
    } else {
        119 - l_mod64
    };
    msg.push(allocator.alloc(0x80u8));
    // msg.append(&mut allocator.alloc_vec(&vec![0u8; k]));
    msg.extend((0..k).into_iter().map(|_| allocator.alloc(0u8)));
    assert!(msg.len() % 4 == 0);
    let mut msg_u32: Vec<WordRef<B, u32>> = Vec::new();
    let mut chunk: Vec<WordRef<B, u8>> = Vec::new();
    for byte in msg {
        chunk.push(byte);
        if chunk.len() == 4 {
            msg_u32.push(WordRef::<B, u32>::from_be_bytes(chunk.try_into().unwrap()).unwrap());
            chunk = Vec::new();
        }
    }
    msg_u32.push(allocator.alloc(((l * 8) as u64 >> 32) as u32));
    msg_u32.push(allocator.alloc((l * 8) as u32));
    return msg_u32;
}

pub const SHA256_BLOCKSIZE: usize = 64;

/// The SHA-256 compression function.
#[allow(non_snake_case)]
pub fn compress_u32<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u32>>,
    init_hash: &[u32; 8],
) -> [WordRef<B, u32>; 8] {
    const SHA256_BLOCKSIZE_U32: usize = SHA256_BLOCKSIZE / 4;
    let n = msg.len() / SHA256_BLOCKSIZE_U32;
    assert_eq!(
        n * SHA256_BLOCKSIZE_U32,
        msg.len(),
        "Message must be padded to multiple of 16 u32 words"
    );
    // let mut H = allocator.alloc_array(*init_hash);
    let mut H: [WordRef<B, u32>; 8] = array::from_fn(|i| allocator.alloc(init_hash[i]));
    for i in 0..n {
        let block = &msg.as_slice()[i * SHA256_BLOCKSIZE_U32..(i + 1) * SHA256_BLOCKSIZE_U32];
        let mut W: [WordRef<B, u32>; 64] = core::array::from_fn(|t| {
            if t < SHA256_BLOCKSIZE_U32 {
                block[t].clone()
            } else {
                allocator.alloc(0)
            }
        });
        for t in SHA256_BLOCKSIZE_U32..64 {
            W[t] = ssig1(W[t - 2].clone())
                + W[t - 7].clone()
                + ssig0(W[t - 15].clone())
                + W[t - 16].clone();
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = H.clone();
        let mut T1: WordRef<B, u32>;
        let mut T2: WordRef<B, u32>;
        for (Wt, &Kt) in W.into_iter().zip(K_WORDS.iter()) {
            T1 = h + bsig1(e.clone()) + ch(e.clone(), f.clone(), g.clone()) + Wt + Kt;
            T2 = bsig0(a.clone()) + maj(a.clone(), b.clone(), c.clone());
            [h, g, f, e, d, c, b, a] = [g, f, e, d + T1.clone(), c, b, a, T1 + T2];
        }
        H = zip_arrays([a, b, c, d, e, f, g, h], H).map(|(l, r)| l + r);
    }
    return H;
}

const SHA224_INIT_HASH: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

/// Computes the SHA-224 hash digest of the given message.
///
/// The message is taken as a vector of bytes ([u8] words).
/// The digest is returned as an array of 7 [u32] words.
///
/// To get an array of 28 [u8] words, use the [sha224bytes] function instead.
pub fn sha224<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u32>; 7] {
    let msg = pad_u32(allocator.clone(), msg);
    let [a, b, c, d, e, f, g, _] = compress_u32(allocator, msg, &SHA224_INIT_HASH);
    return [a, b, c, d, e, f, g];
}

/// Computes the SHA-224 hash digest of the given message.
///
/// The message is taken as a vector of bytes ([u8] words).
/// The digest is returned as an array of 28 [u8] words.
///
/// To get an array of 7 [u32] words, use the [sha224] function instead.
pub fn sha224bytes<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 28] {
    return sha224(allocator, msg)
        .into_iter()
        .flat_map(|word| word.into_be_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}

const SHA256_INIT_HASH: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Computes the SHA-256 hash digest of the given message.
///
/// The message is taken as a vector of bytes ([u8] words).
/// The digest is returned as an array of 8 [u32] words.
///
/// To get an array of 32 [u8] words, use the [sha256bytes] function instead.
pub fn sha256<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u32>; 8] {
    let msg = pad_u32(allocator.clone(), msg);
    return compress_u32(allocator, msg, &SHA256_INIT_HASH);
}

/// Computes the SHA-256 hash digest of the given message.
///
/// The message is taken as a vector of bytes ([u8] words).
/// The digest is returned as an array of 32 [u8] words.
///
/// To get an array of 8 [u32] words, use the [sha256] function instead.
pub fn sha256bytes<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 32] {
    return sha256(allocator, msg)
        .into_iter()
        .flat_map(|word| word.into_be_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}
