use std::time::Instant;
use sha2::{Digest, Sha256};
use ed25519_dalek::{SigningKey, Signer};
use rand::{rngs::OsRng, Rng};
use methods::{
    GUEST_A_ELF, GUEST_A_ID,
    GUEST_B_ELF, GUEST_B_ID,
    RECURSIVE_GUEST_ELF, RECURSIVE_GUEST_ID,
};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let combined: Vec<u8> = left.iter().chain(right.iter()).copied().collect();
    sha256(&combined)
}

/// Builds a Merkle tree from raw leaf data (leaf stored as SHA256(leaf_bytes)).
fn build_merkle_tree(leaves: &[Vec<u8>]) -> Vec<Vec<[u8; 32]>> {
    let n = leaves.len().next_power_of_two();
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| sha256(l)).collect();
    while level.len() < n {
        level.push(sha256(b""));
    }
    let mut tree = vec![level.clone()];
    while level.len() > 1 {
        let next: Vec<[u8; 32]> = level.chunks(2)
            .map(|p| node_hash(&p[0], &p[1]))
            .collect();
        tree.push(next.clone());
        level = next;
    }
    tree
}

fn merkle_root(tree: &[Vec<[u8; 32]>]) -> [u8; 32] {
    *tree.last().unwrap().first().unwrap()
}

/// Returns (siblings, is_right) for the leaf at leaf_idx.
fn merkle_proof(tree: &[Vec<[u8; 32]>], leaf_idx: usize) -> (Vec<[u8; 32]>, Vec<bool>) {
    let mut siblings = Vec::new();
    let mut is_right_flags = Vec::new();
    let mut idx = leaf_idx;
    for level in &tree[..tree.len() - 1] {
        let is_right = idx % 2 == 1;
        let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
        siblings.push(level[sibling_idx]);
        is_right_flags.push(is_right);
        idx /= 2;
    }
    (siblings, is_right_flags)
}

/// Commitment scheme: Com(msg; r) = SHA256(msg || r).
fn commit(msg: &[u8], r: &[u8; 32]) -> [u8; 32] {
    let mut input = msg.to_vec();
    input.extend_from_slice(r);
    sha256(&input)
}

// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let prover = default_prover();
    let mut rng = OsRng;

    const N: usize = 10_000;    // total queries in Q
    const T: usize = 5;         // number of challenge sets
    const N_PER_SET: usize = 20; // queries per set (n in the paper)

    // ── Build query set Q ────────────────────────────────────────────────────
    // Each query: arbitrary bytes. Last byte = ground truth label (j % 2).
    let queries: Vec<Vec<u8>> = (0..N).map(|j| {
        let mut q = format!("query_{}", j).into_bytes();
        q.push((j % 2) as u8);
        q
    }).collect();

    let rq_tree = build_merkle_tree(&queries);
    let r_q: [u8; 32] = merkle_root(&rq_tree);
    println!("[host] R_Q root (Merkle over {} queries): {:?}", N, r_q);

    // ── Build challenge sets ─────────────────────────────────────────────────
    // Set_i = query indices [i*N_PER_SET .. (i+1)*N_PER_SET)
    // Set_0: pre-purchase evaluation (not used here)
    // Set_1: complaint set (used below)
    let sets: Vec<Vec<usize>> = (0..T)
        .map(|i| (i * N_PER_SET..(i + 1) * N_PER_SET).collect())
        .collect();

    // Encode each Set_i as concatenated LE bytes of its u32 indices
    let sets_data: Vec<Vec<u8>> = sets.iter().map(|set| {
        let mut bytes = Vec::new();
        for &idx in set {
            bytes.extend_from_slice(&(idx as u32).to_le_bytes());
        }
        bytes
    }).collect();
    let rsets_tree = build_merkle_tree(&sets_data);
    let r_sets: [u8; 32] = merkle_root(&rsets_tree);
    println!("[host] R_sets root (Merkle over {} sets of {} queries): {:?}", T, N_PER_SET, r_sets);

    // ── Generate EdDSA key pair for server ───────────────────────────────────
    let signing_key = SigningKey::generate(&mut rng);
    let vk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    println!("[host] Server EdDSA public key: {:?}", vk_bytes);

    // ── Complaint scenario: use Set_1 (indices 20..39) ───────────────────────
    // Server predicts all 1s after degradation.
    // Ground truths alternate 0/1 → TP=10, FP=10, FN=0 → F1=20/30≈0.667 < 0.70
    let complaint_set_idx = 1usize;
    let complaint_set = &sets[complaint_set_idx];
    let server_answers: Vec<u8> = complaint_set.iter().map(|_| 1u8).collect();

    // Verify F1 claim locally before proving
    let (tp, fp, fn_) = complaint_set.iter().zip(server_answers.iter())
        .fold((0u32, 0u32, 0u32), |(tp, fp, fn_), (&j, &a)| {
            let gt = (j % 2) as u8;
            match (a, gt) {
                (1, 1) => (tp + 1, fp, fn_),
                (1, 0) => (tp, fp + 1, fn_),
                (0, 1) => (tp, fp, fn_ + 1),
                _ => (tp, fp, fn_),
            }
        });
    println!("[host] F1 claim: {}/{} ≈ {:.3} (τ=0.70, complaint valid: {})",
        2*tp, 2*tp+fp+fn_,
        (2*tp) as f64 / (2*tp+fp+fn_).max(1) as f64,
        2*tp * 100 < (2*tp+fp+fn_) * 70
    );

    // ── Generate commitments ─────────────────────────────────────────────────
    // C_A = SHA256(answers || r_A)
    let r_a: [u8; 32] = rng.gen();
    let c_a: [u8; 32] = commit(&server_answers, &r_a);

    // C_B = SHA256(benchmark_id || r_B)
    let r_b: [u8; 32] = rng.gen();
    let benchmark_id: Vec<u8> = b"F1-score".to_vec();
    let c_b: [u8; 32] = commit(&benchmark_id, &r_b);

    // C_τ = SHA256(tau_bytes || r_τ) where tau_bytes = tau_num || tau_den (LE u32)
    let r_tau: [u8; 32] = rng.gen();
    let tau_num: u32 = 70;
    let tau_den: u32 = 100;
    let mut tau_bytes = tau_num.to_le_bytes().to_vec();
    tau_bytes.extend_from_slice(&tau_den.to_le_bytes());
    let c_tau: [u8; 32] = commit(&tau_bytes, &r_tau);

    println!("[host] C_B: {:?}", c_b);
    println!("[host] C_τ: {:?}", c_tau);
    println!("[host] C_A: {:?}", c_a);

    // ── Sign (H(q_j), a_j) for each query in complaint set ───────────────────
    let signatures: Vec<Vec<u8>> = complaint_set.iter().zip(server_answers.iter())
        .map(|(&j, &a_j)| {
            let h_j = sha256(&queries[j]);
            let mut msg = h_j.to_vec();
            msg.push(a_j);
            signing_key.sign(&msg).to_bytes().to_vec()
        })
        .collect();

    // ── Merkle proof for Set_1 in R_sets ─────────────────────────────────────
    let (set_siblings, set_is_right) = merkle_proof(&rsets_tree, complaint_set_idx);
    let set_indices_u32: Vec<u32> = complaint_set.iter().map(|&i| i as u32).collect();

    // ── Prove Guest A ─────────────────────────────────────────────────────────
    println!("[host] Proving Guest A (Open(C_B), Open(C_τ), MerkleVerify(R_sets), F1<τ)...");
    let complaint_queries: Vec<Vec<u8>> = complaint_set.iter()
        .map(|&j| queries[j].clone())
        .collect();

    let env_a = ExecutorEnv::builder()
        .write(&c_b).unwrap()
        .write(&r_b).unwrap()
        .write(&benchmark_id).unwrap()
        .write(&c_tau).unwrap()
        .write(&r_tau).unwrap()
        .write(&tau_num).unwrap()
        .write(&tau_den).unwrap()
        .write(&r_sets).unwrap()
        .write(&(complaint_set_idx as u32)).unwrap()
        .write(&set_indices_u32).unwrap()
        .write(&set_siblings).unwrap()
        .write(&set_is_right).unwrap()
        .write(&complaint_queries).unwrap()
        .write(&server_answers).unwrap()
        .build().unwrap();

    let t_a = Instant::now();
    let receipt_a: Receipt = prover
        .prove_with_opts(env_a, GUEST_A_ELF, &ProverOpts::succinct())
        .unwrap()
        .receipt;
    println!("[host] Guest A proof time: {:.2?}", t_a.elapsed());

    let jb = &receipt_a.journal.bytes;
    let f1_num_out = u32::from_le_bytes(jb[100..104].try_into().unwrap());
    let f1_den_out = u32::from_le_bytes(jb[104..108].try_into().unwrap());
    println!("[host] Guest A journal: set_idx={}, F1={}/{}",
        u32::from_le_bytes(jb[96..100].try_into().unwrap()),
        f1_num_out, f1_den_out
    );

    // ── Prove Guest B IVC chain (20 steps) ───────────────────────────────────
    println!("[host] Proving Guest B IVC chain ({} steps)...", N_PER_SET);
    let mut prev_receipt: Option<Receipt> = None;
    let mut prev_journal: Vec<u8> = Vec::new();

    for (step, &j) in complaint_set.iter().enumerate() {
        let q_j = &queries[j];
        let a_j = server_answers[step];
        let sig = &signatures[step];
        let is_final = step == N_PER_SET - 1;
        let (siblings, is_right) = merkle_proof(&rq_tree, j);

        println!("[host] Proving Guest B step {} (query_idx={}, is_final={})...", step, j, is_final);

        let env_b = if step == 0 {
            let mut builder = ExecutorEnv::builder();
            builder
                .write(&true).unwrap()       // is_genesis
                .write(&r_q).unwrap()        // R_Q root
                .write(&vk_bytes).unwrap()   // server public key
                .write(&c_a).unwrap()        // commitment to all answers
                .write(&is_final).unwrap()   // is_final flag
                .write(q_j).unwrap()         // query bytes
                .write(&a_j).unwrap()        // server answer
                .write(&siblings).unwrap()   // Merkle proof siblings
                .write(&is_right).unwrap()   // Merkle proof is_right flags
                .write(sig).unwrap();        // EdDSA signature
            if is_final {
                builder.write(&r_a).unwrap(); // r_A for C_A opening (final step only)
            }
            builder.build().unwrap()
        } else {
            let mut builder = ExecutorEnv::builder();
            builder
                .write(&false).unwrap()          // is_genesis
                .write(&GUEST_B_ID).unwrap()     // image_id for env::verify
                .write(&prev_journal).unwrap()   // previous step journal
                .write(&is_final).unwrap()       // is_final flag
                .write(q_j).unwrap()             // query bytes
                .write(&a_j).unwrap()            // server answer
                .write(&siblings).unwrap()       // Merkle proof siblings
                .write(&is_right).unwrap()       // Merkle proof is_right flags
                .write(sig).unwrap();            // EdDSA signature
            if is_final {
                builder.write(&r_a).unwrap();    // r_A for C_A opening (final step only)
            }
            builder.add_assumption(prev_receipt.clone().unwrap());
            builder.build().unwrap()
        };

        let t_b = Instant::now();
        let receipt_b: Receipt = prover
            .prove_with_opts(env_b, GUEST_B_ELF, &ProverOpts::succinct())
            .unwrap()
            .receipt;
        println!("[host] Guest B step {} proof time: {:.2?}", step, t_b.elapsed());

        prev_journal = receipt_b.journal.bytes.clone();
        prev_receipt = Some(receipt_b);
    }

    let receipt_b_final = prev_receipt.unwrap();
    let (final_r_q, _vk, final_c_a, final_answers): ([u8;32], [u8;32], [u8;32], Vec<u8>) =
        bincode::deserialize(&receipt_b_final.journal.bytes).unwrap();
    assert_eq!(final_r_q, r_q, "R_Q mismatch in Guest B final journal");
    assert_eq!(final_c_a, c_a, "C_A mismatch in Guest B final journal");
    println!("[host] Guest B verified {} answers: {:?}", final_answers.len(), final_answers);

    // ── Prove Recursive Guest (Groth16) ───────────────────────────────────────
    println!("[host] Proving Recursive Guest (Groth16, aggregates A + B_final)...");
    let t_rec = Instant::now();

    // ExecutorEnv and default_prover use Rc (not Send): build everything inside the thread.
    let final_receipt: Receipt = std::thread::Builder::new()
        .stack_size(128 * 1024 * 1024) // 128 MB — Groth16 uses deep recursion
        .spawn(move || {
            let env_rec = ExecutorEnv::builder()
                .write(&GUEST_A_ID).unwrap()
                .write(&GUEST_B_ID).unwrap()
                .write(&receipt_a.journal.bytes).unwrap()
                .write(&receipt_b_final.journal.bytes).unwrap()
                .add_assumption(receipt_a)
                .add_assumption(receipt_b_final)
                .build()
                .unwrap();
            default_prover()
                .prove_with_opts(env_rec, RECURSIVE_GUEST_ELF, &ProverOpts::groth16())
                .unwrap()
                .receipt
        })
        .unwrap()
        .join()
        .unwrap();

    println!("[host] Recursive Guest proof time: {:.2?}", t_rec.elapsed());
    final_receipt.verify(RECURSIVE_GUEST_ID).unwrap();
    println!("[host] Complaint proof verified successfully!");
    println!("[host] Final journal (SHA-256 of A||B journals): {:?}", final_receipt.journal.bytes);
}
