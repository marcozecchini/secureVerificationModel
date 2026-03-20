# RISC0 Recursive Proof Workspace

Workspace Rust che dimostra prove ricorsive e IVC con RISC0 zkVM v1.2.

## Struttura

```
workspace/
├── Cargo.toml              # workspace root (members: host, methods)
├── methods/                # genera ELF e IMAGE_ID per tutti i guest
├── guest-a/                # prova foglia: legge u32, committa input*2
├── guest-b/                # step IVC: catena incrementale Vec<u32>
├── guest-c/                # prova foglia: legge String, committa SHA-256
├── recursive-guest/        # aggregatore: verifica A+B+C, committa SHA-256
└── host/                   # orchestratore prove
```

## Architettura

- **Guest A**: `u32 → u32*2` (commita con `env::commit`)
- **Guest C**: `String → SHA-256([u8; 32])` (commita con `env::commit_slice`)
- **Guest B (IVC)**: catena di N step; ogni step verifica il precedente
  in-circuit con `env::verify` e appende un valore alla lista `Vec<u32>`
  (serializzata con `bincode`)
- **Recursive Guest**: aggrega le tre prove con `env::verify` e committa
  `SHA-256(journal_a ‖ journal_c ‖ journal_b_final)`

> **Nota design**: i guest non possono importare `methods` (dipendenza
> circolare — `methods` compila i guest tramite `risc0-build`). Gli IMAGE_ID
> necessari per `env::verify` vengono passati come input dall'host.

## Esecuzione

### Dev mode — nessuna prova reale, esecuzione istantanea

```bash
RISC0_DEV_MODE=1 cargo run -p host
```

### Prova locale completa

```bash
cargo run --release -p host
```

### Log dettagliato

```bash
RUST_LOG=info RISC0_DEV_MODE=1 cargo run -p host
```

### Prova con Groth16 finale tramite Bonsai

Il proof finale usa `ProverOpts::groth16()`. Localmente richiede GPU con
setup stark2snark. In alternativa, usa il servizio Bonsai:

```bash
BONSAI_API_KEY="<your-key>" BONSAI_API_URL="https://api.bonsai.xyz" \
  cargo run --release -p host
```

> Con `RISC0_DEV_MODE=1` il Groth16 viene simulato senza prova reale.
# secureVerificationModel
