#![no_main]
risc0_zkvm::guest::entry!(main);

use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Verifies a Merkle leaf opening. Takes raw leaf bytes (hashes them internally).
fn merkle_verify(leaf: &[u8], siblings: &[[u8; 32]], is_right: &[bool], root: [u8; 32]) -> bool {
    let mut current = sha256(leaf);
    for (sibling, &right) in siblings.iter().zip(is_right.iter()) {
        let combined: Vec<u8> = if right {
            sibling.iter().chain(current.iter()).copied().collect()
        } else {
            current.iter().chain(sibling.iter()).copied().collect()
        };
        current = sha256(&combined);
    }
    current == root
}

fn main() {
    let is_genesis: bool = env::read();

    if is_genesis {
        // ── Step 0: first query ───────────────────────────────────────────────
        let r_q: [u8; 32]                = env::read(); // R_Q root (IVC invariant)
        let vk_bytes: [u8; 32]           = env::read(); // server public key (IVC invariant)
        let c_a: [u8; 32]                = env::read(); // commitment to all answers (IVC invariant)
        let is_final: bool               = env::read(); // true if this is the last step

        let q_j: Vec<u8>                 = env::read(); // raw query bytes
        let a_j: u8                      = env::read(); // server answer (0 or 1)
        let siblings: Vec<[u8; 32]>      = env::read(); // Merkle proof siblings
        let is_right: Vec<bool>          = env::read(); // Merkle proof path flags
        let sig_vec: Vec<u8>             = env::read(); // EdDSA signature (64 bytes)

        // MerkleVerify(R_Q, j, q_j, π_j)
        assert!(merkle_verify(&q_j, &siblings, &is_right, r_q), "invalid Merkle proof (step 0)");

        // h_j = H(q_j); verify EdDSA(vk_server, (h_j, a_j), σ_j)
        let h_j = sha256(&q_j);
        let mut msg = h_j.to_vec();
        msg.push(a_j);
        let sig_bytes: [u8; 64] = sig_vec.try_into().expect("signature must be 64 bytes");
        let vk = VerifyingKey::from_bytes(&vk_bytes).expect("invalid public key");
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&msg, &sig).expect("invalid EdDSA signature (step 0)");

        let answers = vec![a_j];

        // Final step: verify Open(C_A, answers, r_A) = SHA256(answers || r_A) == C_A
        if is_final {
            let r_a: [u8; 32] = env::read();
            let mut input = answers.clone();
            input.extend_from_slice(&r_a);
            assert_eq!(sha256(&input), c_a, "invalid C_A opening (step 0)");
        }

        let journal: ([u8; 32], [u8; 32], [u8; 32], Vec<u8>) = (r_q, vk_bytes, c_a, answers);
        env::commit_slice(&bincode::serialize(&journal).unwrap());

    } else {
        // ── Step k>=1: IVC verification + new query ───────────────────────────
        let image_id: [u32; 8]           = env::read();
        let prev_journal: Vec<u8>        = env::read();
        let is_final: bool               = env::read();

        let q_j: Vec<u8>                 = env::read();
        let a_j: u8                      = env::read();
        let siblings: Vec<[u8; 32]>      = env::read();
        let is_right: Vec<bool>          = env::read();
        let sig_vec: Vec<u8>             = env::read();

        // Verify the previous step in-circuit
        env::verify(image_id, &prev_journal).expect("IVC self-verification failed");

        // Recover accumulated state from previous step
        let (r_q, vk_bytes, c_a, mut answers): ([u8; 32], [u8; 32], [u8; 32], Vec<u8>) =
            bincode::deserialize(&prev_journal).expect("deserialization failed");

        // MerkleVerify(R_Q, j, q_j, π_j)
        assert!(merkle_verify(&q_j, &siblings, &is_right, r_q), "invalid Merkle proof");

        // h_j = H(q_j); verify EdDSA(vk_server, (h_j, a_j), σ_j)
        let h_j = sha256(&q_j);
        let mut msg = h_j.to_vec();
        msg.push(a_j);
        let sig_bytes: [u8; 64] = sig_vec.try_into().expect("signature must be 64 bytes");
        let vk = VerifyingKey::from_bytes(&vk_bytes).expect("invalid public key");
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&msg, &sig).expect("invalid EdDSA signature");

        answers.push(a_j);

        // Final step: verify Open(C_A, answers, r_A) = SHA256(answers || r_A) == C_A
        if is_final {
            let r_a: [u8; 32] = env::read();
            let mut input = answers.clone();
            input.extend_from_slice(&r_a);
            assert_eq!(sha256(&input), c_a, "invalid C_A opening");
        }

        let journal: ([u8; 32], [u8; 32], [u8; 32], Vec<u8>) = (r_q, vk_bytes, c_a, answers);
        env::commit_slice(&bincode::serialize(&journal).unwrap());
    }
}
