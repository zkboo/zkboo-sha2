// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates midstate resumption: compressing a message's first block to a chaining value and
//! resuming from it (with prefix-aware padding) must equal hashing the whole message, and the
//! keyed HMAC-SHA512 must equal a from-scratch HMAC.

#![cfg(all(feature = "sha256", feature = "sha512"))]

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_sha2::{
    sha256::{compress_u32_from, pad_u32_with_prefix},
    sha256bytes,
    sha512::{Sha512Hmac, compress_u64_from, pad_u64_with_prefix},
    sha512bytes,
};

type WP = OwnedFlexibleWordPool<usize>;

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

/// SHA-256 of a 100-byte message, computed both directly and via a one-block midstate + resume.
struct Sha256Midstate;

impl Circuit for Sha256Midstate {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let a = frontend.allocator();
        let msg: Vec<u8> = (0..100u8).collect();
        // Direct hash.
        let direct = sha256bytes(a.clone(), msg.iter().map(|&b| a.alloc(b)).collect());
        direct.into_iter().for_each(|w| frontend.output(w));
        // Midstate: compress the first 64-byte block from the IV, resume over the tail.
        const IV: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let iv = core::array::from_fn(|i| a.alloc(IV[i]));
        let first: Vec<_> = msg[..64]
            .chunks(4)
            .map(|c| {
                let bytes: Vec<_> = c.iter().map(|&b| a.alloc(b)).collect();
                zkboo::backend::WordRef::<B, u32>::from_be_bytes(bytes)
                    .ok()
                    .unwrap()
            })
            .collect();
        let midstate = compress_u32_from(a.clone(), first, iv);
        let tail = pad_u32_with_prefix(
            a.clone(),
            msg[64..].iter().map(|&b| a.alloc(b)).collect(),
            64,
        );
        let resumed = compress_u32_from(a, tail, midstate);
        resumed
            .into_iter()
            .flat_map(|w| w.into_be_bytes())
            .for_each(|w| frontend.output(w));
    }
}

/// SHA-512 of a 200-byte message, direct and via a 128-byte-block midstate + resume.
struct Sha512Midstate;

impl Circuit for Sha512Midstate {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let a = frontend.allocator();
        let msg: Vec<u8> = (0..200u8).collect();
        let direct = sha512bytes(a.clone(), msg.iter().map(|&b| a.alloc(b)).collect());
        direct.into_iter().for_each(|w| frontend.output(w));
        const IV: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];
        let iv = core::array::from_fn(|i| a.alloc(IV[i]));
        let first: Vec<_> = msg[..128]
            .chunks(8)
            .map(|c| {
                let bytes: Vec<_> = c.iter().map(|&b| a.alloc(b)).collect();
                zkboo::backend::WordRef::<B, u64>::from_be_bytes(bytes)
                    .ok()
                    .unwrap()
            })
            .collect();
        let midstate = compress_u64_from(a.clone(), first, iv);
        let tail = pad_u64_with_prefix(
            a.clone(),
            msg[128..].iter().map(|&b| a.alloc(b)).collect(),
            128,
        );
        let resumed = compress_u64_from(a, tail, midstate);
        resumed
            .into_iter()
            .flat_map(|w| w.into_be_bytes())
            .for_each(|w| frontend.output(w));
    }
}

/// HMAC-SHA512 with a >128-byte key, via the keyed Sha512Hmac, checked against RFC-style vectors.
struct HmacKeyed {
    key: Vec<u8>,
    msg: Vec<u8>,
}

impl Circuit for HmacKeyed {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let a = frontend.allocator();
        let key = self.key.iter().map(|&b| a.alloc(b)).collect();
        let hmac = Sha512Hmac::new(a.clone(), key);
        let mac = hmac.mac_bytes(a.clone(), self.msg.iter().map(|&b| a.alloc(b)).collect());
        mac.into_iter().for_each(|w| frontend.output(w));
    }
}

#[test]
fn test_sha256_midstate_matches_direct() {
    let out = exec::<_, WP>(&Sha256Midstate).u8;
    assert_eq!(out.len(), 64);
    assert_eq!(
        &out[..32],
        &out[32..],
        "midstate resume must equal direct SHA-256"
    );
}

#[test]
fn test_sha512_midstate_matches_direct() {
    let out = exec::<_, WP>(&Sha512Midstate).u8;
    assert_eq!(out.len(), 128);
    assert_eq!(
        &out[..64],
        &out[64..],
        "midstate resume must equal direct SHA-512"
    );
}

#[test]
fn test_keyed_hmac_matches_reference() {
    // RFC 4231 Test Case 6: 131-byte key (>block), "Test Using Larger Than Block-Size Key".
    let out = exec::<_, WP>(&HmacKeyed {
        key: vec![0xaa; 131],
        msg: b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
    })
    .u8;
    assert_eq!(
        to_hex(&out),
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
    );
}
