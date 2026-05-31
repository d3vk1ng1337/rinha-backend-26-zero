# Box de medição amd64 (Linux/Haswell-class)

O Mac **não serve** para medir o projeto Zero:
- `io_uring` não roda sob OrbStack/rosetta (a crate `io-uring` é Linux-only e o
  servidor nem compila no macOS).
- p99 em arm64 virtualizado **não prediz** o rig oficial (Mac Mini Late 2014,
  Haswell amd64). A memória do projeto registra isso explicitamente.

Por isso precisamos de um box **Linux amd64 dedicado** (vCPU dedicado, sem
noisy-neighbor) pra: (a) compilar/rodar o `zero-server`, (b) medir **deltas** de
p99 (io_uring × epoll, mlock on/off, mmap × read-to-RAM), (c) confirmar direção
antes de gastar uma submissão no rig.

## Opção recomendada (rápida, p/ o prazo de 5/jun)

**Hetzner Cloud CCX13** (vCPU dedicado AMD, 2 vCPU, 8 GB, ~€0.02/h ≈ €13/mês,
cobrança por hora — destrói depois):

```sh
# (no painel Hetzner ou via hcloud CLI)
hcloud server create --name zero-bench --type ccx13 --image ubuntu-24.04 --ssh-key <sua-key>
```

Gêmeo de microarquitetura mais fiel (opcional, melhor fidelidade absoluta):
**Hetzner dedicated/auction** com Xeon E3/E5 Haswell-Broadwell (~€30-45/mês), ou
um **mini-PC Haswell refurb** (i5-4278U, ~US$80 — o gêmeo real, mas não chega no
prazo). Pro nosso uso (medir *direção* de efeito), o CCX13 já resolve.

## Setup no box

```sh
ssh root@<ip>
apt-get update && apt-get install -y docker.io docker-compose-v2 git build-essential curl
# k6
curl -sL https://github.com/grafana/k6/releases/latest/download/k6-*-linux-amd64.tar.gz | tar xz
install k6*/k6 /usr/local/bin/

# rust (pra build local; o compose usa multi-stage e dispensa)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"

# kernel >= 6.x (Ubuntu 24.04 já tem 6.8/6.11 HWE) — confirmar io_uring:
uname -r
grep -i io_uring /boot/config-$(uname -r) || true   # CONFIG_IO_URING=y esperado

git clone <repo-zero> && cd rinha-backend-26-zero
```

## Reproduzir o rig (cgroup + bridge + limites exatos)

O `deploy/docker-compose.yml` já fixa: rede **bridge**, `seccomp:unconfined`,
limites **0.10/0.45/0.45 CPU** + **32/150/150 MB**, tmpfs pros sockets. Subir:

```sh
docker compose -f deploy/docker-compose.yml up -d --build
curl -s localhost:9999/ready
```

## Medir (A/B io_uring × epoll)

```sh
# baseline epoll
WORKER_IO=epoll docker compose ... up -d && k6 run test/k6-script.js   # anota p99
# tratamento io_uring
WORKER_IO=uring docker compose ... up -d && k6 run test/k6-script.js   # anota p99 + erros
```

Promover io_uring **só** se bater epoll na cauda com **zero erros** em 3+ runs.
Accuracy continua no gate amd64 (`tools/offline-gate.py` / `zero-gate`), nunca no
p99.

## Importante
- **Não** confiar em p99 absoluto do box como sendo igual ao rig — confiar na
  **direção** do delta, e confirmar com **1 submissão** no rig antes de promover.
- `failure rate > 15%` no k6 zera o score (−3000). Qualquer erro HTTP é fatal.
