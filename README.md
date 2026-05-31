# Zero — Rinha de Backend 2026 (Rust, io_uring zero-syscall)

Backend de detecção de fraude por busca vetorial para a
[Rinha de Backend 2026](https://github.com/zanfranceschi/rinha-de-backend-2026).

**Tese:** o gargalo de p99 no rig (Mac Mini Late 2014, 1 CPU) não é compute (a
busca IVF é ~1-3 µs) — é syscall/scheduling/queueing. O diferencial inédito na
rinha é um **worker io_uring "zero-syscall"** (`DEFER_TASKRUN` + multishot recv
em provided-buffer ring + registered files/buffers), com fallback **epoll
hardened** como rede de segurança e braço de controle de A/B.

## Arquitetura (regra-legal: bridge, ≥1 LB + 2 APIs round-robin)

```
k6 :9999 ─► lb (io_uring multishot accept + SCM_RIGHTS fd-pass) ─► worker0 / worker1
                                                                    io_uring zero-syscall
                                                                    IVF int16 (RAM + mlock + hugepages)
```

## Crates

| Crate | Papel |
|---|---|
| `zero-index` | núcleo sem deps: formato pair-SoA, quant int16, normalização 14-dim (f32), busca IVF + repair |
| `zero-convert` | build-time: `references.json[.gz]` → k-means++ (k=4096) → `index.bin` |
| `zero-gate` | valida FP/FN vs `expected_fraud_score` do `test-data.json` |
| `zero-server` | (Linux) bin `lb`/`worker` — epoll e io_uring |

## Accuracy

A normalização é portada **bit-a-bit** do top1 (pipeline f32) que crava
accuracy 6000. O `zero-gate` valida localmente (direcional no arm64); o árbitro
bit-exato é o **offline gate amd64**.

## Build & teste

```sh
cargo test -p zero-index
cargo run --release -p zero-convert -- data/references.json.gz /tmp/index.bin
cargo run --release -p zero-gate -- /tmp/index.bin test/test-data.json
```

Medição de p99: ver `tools/provision-box.md` (box amd64 dedicado).

Design: `docs/specs/`. Plano: `docs/plans/`.
