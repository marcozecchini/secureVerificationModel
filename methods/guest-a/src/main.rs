#![no_main]
risc0_zkvm::guest::entry!(main);

use risc0_zkvm::guest::env;
use risc0_zkvm::guest::sha::{Impl, Sha256};

fn sha256(data: &[u8]) -> [u8; 32] {
    (*Impl::hash_bytes(data)).into()
}

/// Verifies Com(msg; r) = expected, where Com = SHA256(msg || r).
fn commitment_open(msg: &[u8], r: &[u8; 32], expected: &[u8; 32]) {
    let mut input = msg.to_vec();
    input.extend_from_slice(r);
    assert_eq!(sha256(&input), *expected, "commitment opening failed");
}

/// Verifies a Merkle path. Takes raw leaf bytes (hashes them internally).
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
    // ── Commitment opening: C_B = SHA256(benchmark_id || r_B) ─────────────────
    let c_b: [u8; 32]         = env::read();
    let r_b: [u8; 32]         = env::read();
    let benchmark_id: Vec<u8> = env::read(); // e.g. b"F1-score"
    commitment_open(&benchmark_id, &r_b, &c_b);

    // ── Commitment opening: C_τ = SHA256(τ_bytes || r_τ) ─────────────────────
    let c_tau: [u8; 32]       = env::read();
    let r_tau: [u8; 32]       = env::read();
    let tau_num: u32          = env::read();
    let tau_den: u32          = env::read();
    let mut tau_bytes = tau_num.to_le_bytes().to_vec();
    tau_bytes.extend_from_slice(&tau_den.to_le_bytes());
    commitment_open(&tau_bytes, &r_tau, &c_tau);

    // ── MerkleVerify(R_sets, i, Set_i, π_Set_i) ──────────────────────────────
    let r_sets: [u8; 32]            = env::read();
    let set_index: u32              = env::read();
    let set_indices: Vec<u32>       = env::read();
    let set_siblings: Vec<[u8; 32]> = env::read();
    let set_is_right: Vec<bool>     = env::read();

    // Encode Set_i as concatenated LE bytes of its indices
    let mut set_bytes = Vec::new();
    for idx in &set_indices {
        set_bytes.extend_from_slice(&idx.to_le_bytes());
    }
    assert!(
        merkle_verify(&set_bytes, &set_siblings, &set_is_right, r_sets),
        "challenge set Merkle proof failed"
    );

    // ── B({q_j}, {a_j}) < τ ───────────────────────────────────────────────────
    // Queries: raw bytes with last byte = ground truth label (0 or 1)
    // Answers: server predictions (0 or 1)
    let queries: Vec<Vec<u8>> = env::read();
    let answers: Vec<u8>      = env::read();
    let n = queries.len();
    assert_eq!(answers.len(), n, "queries/answers length mismatch");

    let mut tp: u32 = 0;
    let mut fp: u32 = 0;
    let mut false_neg: u32 = 0;
    for i in 0..n {
        let gt   = *queries[i].last().unwrap(); // last byte = ground truth
        let pred = answers[i];
        match (pred, gt) {
            (1, 1) => tp += 1,
            (1, 0) => fp += 1,
            (0, 1) => false_neg += 1,
            _      => {}
        }
    }

    let f1_num = 2 * tp;
    let f1_den = 2 * tp + fp + false_neg;

    // Assert F1 < τ: f1_num / f1_den < tau_num / tau_den
    // ↔ f1_num * tau_den < f1_den * tau_num
    assert!(
        f1_den == 0 || f1_num * tau_den < f1_den * tau_num,
        "F1-score is not below threshold — complaint invalid"
    );

    // ── Journal: public statement of the complaint ────────────────────────────
    // Layout: C_B(32) || C_τ(32) || R_sets(32) || set_index(4) || f1_num(4) || f1_den(4)
    let mut journal = Vec::new();
    journal.extend_from_slice(&c_b);
    journal.extend_from_slice(&c_tau);
    journal.extend_from_slice(&r_sets);
    journal.extend_from_slice(&set_index.to_le_bytes());
    journal.extend_from_slice(&f1_num.to_le_bytes());
    journal.extend_from_slice(&f1_den.to_le_bytes());
    env::commit_slice(&journal);
}
