# Verifiable AI Subscription Complaint — RISC0 Prototype

Rust workspace implementing the ZK-SNARK complaint proof from the **VASC** protocol
(Verifiable AI Subscription Contracts). It proves, in zero-knowledge, that a server's
model degraded after a subscription was signed.

The proof corresponds to Section 5.3 of the paper and certifies:

- `Open(C_B, B, r_B)` — the benchmark function committed in Phase 1 opens correctly
- `Open(C_τ, τ, r_τ)` — the threshold committed in Phase 1 opens correctly
- `MerkleVerify(R_sets, i, Set_i, π)` — the challenge set belongs to the agreed pool
- `B({q_j}, {a_j}) < τ` — the server's answers fail the benchmark (F1-score below threshold)
- For all `j ∈ Set_i`: `MerkleVerify(R_Q, j, q_j, π_j)` + `H(q_j) = h_j` + `Verify(vk_server, (h_j, a_j), σ_j)` — each query belongs to the committed query set and carries a valid server signature on its answer

---

## Project Structure

```
accountingSubscription/
├── Cargo.toml                  # workspace root
├── rust-toolchain.toml         # pins RISC0 toolchain
├── host/
│   └── src/main.rs             # orchestrator: builds trees, generates proofs, verifies
└── methods/
    ├── Cargo.toml              # declares guest packages for risc0-build
    ├── build.rs                # compiles guest ELFs and generates IMAGE_IDs
    ├── src/lib.rs              # re-exports ELF binaries and IMAGE_IDs to host
    ├── guest-a/
    │   └── src/main.rs         # verifies Open(C_B), Open(C_τ), MerkleVerify(R_sets), F1 < τ
    ├── guest-b/
    │   └── src/main.rs         # IVC chain: 20 steps of MerkleVerify(R_Q) + EdDSA + Open(C_A)
    └── recursive-guest/
        └── src/main.rs         # aggregates guest-a + guest-b with Groth16
```

---

## Protocol Parameters (this experiment)

| Parameter | Value | Description |
|-----------|-------|-------------|
| N | 10,000 | Total queries in Q |
| T | 5 | Number of challenge sets |
| n | 20 | Queries per set |
| Complaint set | Set₁ (indices 20–39) | Set used for the complaint |
| Benchmark | F1-score | Ratio 2·TP / (2·TP + FP + FN) |
| Threshold τ | 70/100 | Minimum acceptable F1 |
| Degraded server | Predicts all 1s | F1 ≈ 0.667 < 0.70 → complaint valid |
| Commitment scheme | SHA-256(msg ‖ r) | Hash-based, binding and hiding |
| Signature scheme | EdDSA (Ed25519) | Server signs (H(q_j), a_j) per query |

---

## Architecture

```
HOST
 │
 ├─ Guest A (single proof, succinct)
 │    Private inputs: r_B, benchmark_id, r_τ, τ, R_sets path, queries, answers
 │    Public outputs (journal): C_B ‖ C_τ ‖ R_sets ‖ set_idx ‖ f1_num ‖ f1_den
 │
 ├─ Guest B × 20 steps (IVC chain, succinct)
 │    Step 0 (genesis):  R_Q, vk_server, C_A, q_0, a_0, π_0, σ_0
 │    Step k (k≥1):      env::verify(prev) + q_k, a_k, π_k, σ_k
 │    Step 19 (final):   also verifies Open(C_A, answers, r_A)
 │    Public outputs (journal): R_Q ‖ vk_server ‖ C_A ‖ [a_0..a_19]
 │
 └─ Recursive Guest (Groth16, single on-chain verifiable proof)
      env::verify(guest-a)
      env::verify(guest-b final)
      Public output (journal): SHA-256(journal_A ‖ journal_B)
```

> **Design note**: guest programs cannot import `methods` (circular dependency —
> `methods` compiles guests via `risc0-build`). IMAGE_IDs needed for `env::verify`
> are passed as private inputs from the host.

---

## Requirements

- Rust (stable toolchain)
- RISC0 toolchain: installed automatically via `rust-toolchain.toml`
- For real proofs: a machine with sufficient RAM (≥ 16 GB recommended)
- For Groth16 locally: GPU with stark2snark setup

Install the RISC0 toolchain if not already present:

```bash
curl -L https://risczero.com/install | bash
rzup install
```

---

## Running

### Dev mode — instant execution, no real proofs

```bash
RISC0_DEV_MODE=1 cargo run -p host
```

### Full local proof (real STARKs, no Groth16)

```bash
cargo run --release -p host
```

> First build compiles RISC0's C++ circuits from source — this takes several minutes
> but is cached for subsequent runs.

### With detailed logs

```bash
RUST_LOG=info RISC0_DEV_MODE=1 cargo run -p host
```

### Groth16 via Bonsai (remote proving service)

The final recursive proof uses `ProverOpts::groth16()`. To offload it to Bonsai:

```bash
BONSAI_API_KEY="<your-key>" BONSAI_API_URL="https://api.bonsai.xyz" \
  cargo run --release -p host
```

> With `RISC0_DEV_MODE=1` the Groth16 step is simulated without a real proof.

---

## Expected Output (dev mode)

```
[host] R_Q root (Merkle over 10000 queries): [...]
[host] R_sets root (Merkle over 5 sets of 20 queries): [...]
[host] F1 claim: 20/30 ≈ 0.667 (τ=0.70, complaint valid: true)
[host] Proving Guest A ...
[host] Guest A proof time: ~6s
[host] Proving Guest B IVC chain (20 steps)...
[host] Guest B step 0 proof time: ~22s
...
[host] Guest B step 19 proof time: ~22s
[host] Proving Recursive Guest (Groth16)...
[host] Complaint proof verified successfully!
[host] Final journal (SHA-256 of A||B journals): [...]
```
