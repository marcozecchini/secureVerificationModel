#![no_main]
risc0_zkvm::guest::entry!(main);

use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

fn main() {
    // Read IMAGE_IDs passed by the host (avoids circular dependency with methods)
    let image_id_a: [u32; 8] = env::read();
    let image_id_b: [u32; 8] = env::read();

    // Read journals of the two proofs
    let journal_a: Vec<u8>       = env::read();
    let journal_b_final: Vec<u8> = env::read();

    // Verify both proofs in-circuit
    env::verify(image_id_a, &journal_a).expect("guest-a verification failed");
    env::verify(image_id_b, &journal_b_final).expect("guest-b verification failed");

    // Commit SHA-256 of the concatenation of both journals
    let mut combined = journal_a;
    combined.extend_from_slice(&journal_b_final);
    let hash: [u8; 32] = Sha256::digest(&combined).into();
    env::commit_slice(&hash);
}
