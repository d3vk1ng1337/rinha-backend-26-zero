# Zero

A submission for [Rinha de Backend 2026](https://github.com/zanfranceschi/rinha-de-backend-2026):
fraud detection by vector search. Each transaction is reduced to a 14-dimensional
feature vector. We find its 5 nearest reference vectors through an int16 IVF
index (AVX2-accelerated distance) and return `fraud_score = fraud_count / 5`,
the fraction of those neighbors labeled fraudulent. The service is written in
Rust as single-threaded epoll workers sitting behind a round-robin load balancer
that hands off accepted connections to the workers via `SCM_RIGHTS` fd passing.

## Crates

- `zero-index` — core index, no external dependencies: vector format, int16
  quantization, 14-dim normalization, and IVF nearest-neighbor search.
- `zero-convert` — offline build step that turns the reference set into the
  packed `index.bin` consumed at runtime.
- `zero-gate` — accuracy check: runs the index against `test-data.json` and
  reports false positives and false negatives versus the expected scores.
- `zero-server` — the runtime binaries (Linux): the load balancer and the worker.

## Build and test

```sh
cargo test -p zero-index
cargo run --release -p zero-convert -- <refs> <out.bin>
cargo run --release -p zero-gate -- <index.bin> <test-data.json>
docker compose -f deploy/docker-compose.yml up --build
```

With the data checked into this repository:

```sh
cargo run --release -p zero-convert -- data/references.json.gz /tmp/index.bin
cargo run --release -p zero-gate -- /tmp/index.bin test/test-data.json
```
