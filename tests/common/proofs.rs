use zeroize::Zeroize;
use zkboo::{
    circuit::Circuit,
    crypto::{HashPRG, Hasher},
    executor::{OwnedFlexibleWordPool, exec},
    prover::{par_prove, prove, views::OwnedFlexibleWordTriplePool},
    verifier::{par_verify, replay::OwnedFlexibleWordPairPool, verify},
};

type WP = OwnedFlexibleWordPool<usize>;
type WTP = OwnedFlexibleWordTriplePool<usize>;
type WPP = OwnedFlexibleWordPairPool<usize>;

#[derive(Debug)]
struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Hasher for Blake3Hasher {
    type Digest = [u8; 32];
    const DIGEST_SIZE: usize = 32;
    fn new() -> Self {
        return Self {
            inner: blake3::Hasher::new(),
        };
    }
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    fn finalize_into(&mut self, out: &mut Self::Digest) {
        let result = self.inner.finalize();
        out.copy_from_slice(result.as_bytes());
        self.inner.reset();
    }
}

impl Zeroize for Blake3Hasher {
    fn zeroize(&mut self) {
        self.inner.reset();
    }
}
type H = Blake3Hasher;
type PS = HashPRG<H>;
type PV = HashPRG<H>;
type S = <H as Hasher>::Digest;

const SEED_ENTROPY: &[u8] = b"seed entropy";
const NUM_PROOF_ITERS: usize = 64;

/// Global flag to enable proof testing.
const TEST_PROOF: bool = true;

pub fn test_proof<C: Circuit + Sync>(circuit: &C) {
    if TEST_PROOF {
        let expected_output = exec::<C, WP>(circuit);
        let mut proof;
        let mut is_valid;
        // [seq prove, seq verify]
        proof = prove::<C, H, PS, PV, S, WTP>(circuit, NUM_PROOF_ITERS, SEED_ENTROPY);
        is_valid = verify::<C, H, PV, S, WPP>(circuit, &expected_output, &proof)
            .expect("Error verifying proof [seq prove, seq verify]");
        assert!(is_valid, "Proof is invalid [seq prove, seq verify].");
        // [seq prove, par verify]
        proof = prove::<C, H, PS, PV, S, WTP>(circuit, NUM_PROOF_ITERS, SEED_ENTROPY);
        is_valid = par_verify::<C, H, PV, S, WPP>(circuit, &expected_output, &proof)
            .expect("Error verifying proof [seq prove, seq verify]");
        assert!(is_valid, "Proof is invalid [seq prove, seq verify].");
        // [par prove, seq verify]
        proof = par_prove::<C, H, PS, PV, S, WTP>(circuit, NUM_PROOF_ITERS, SEED_ENTROPY);
        is_valid = verify::<C, H, PV, S, WPP>(circuit, &expected_output, &proof)
            .expect("Error verifying proof [seq prove, seq verify]");
        assert!(is_valid, "Proof is invalid [seq prove, seq verify].");
        // [par prove, par verify]
        proof = par_prove::<C, H, PS, PV, S, WTP>(circuit, NUM_PROOF_ITERS, SEED_ENTROPY);
        is_valid = par_verify::<C, H, PV, S, WPP>(circuit, &expected_output, &proof)
            .expect("Error verifying proof [seq prove, seq verify]");
        assert!(is_valid, "Proof is invalid [seq prove, seq verify].");
    }
}
