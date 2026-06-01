# SharkTTY Gateway — Implementation Plan

A standalone, self-hostable **keep-alive SSH gateway** (Rust), plus a separate
cloud **SaaS control-plane** layered on top. The gateway holds the live SSH/PTY
connection to a target host so a mobile client can drop, sleep, roam, and
reattach without losing the session — **without installing anything on the
target** (target only ever sees ordinary sshd).

## Locked decisions

- **Repo:** standalone (this repo). The App↔Gateway wire protocol lives in
  `gw-proto` and is shared with the iOS client via a published crate / submodule.
- **Transport (App↔Gateway):** QUIC via `quinn` (TLS 1.3, connection migration
  for roaming, multiplexed streams, 0-RTT reconnect). WebSocket fallback later.
- **SaaS backend:** the Rust gateway exposes a language-agnostic auth/quota hook
  (gRPC or HTTP); the SaaS control-plane is a **separate backend service**
  (language TBD) that implements it.
- **Payment:** deferred. Build accounts + quota + usage metering first; wire a
  payment provider in as a late, swappable step.

## Security model (non-negotiable)

- **Delegated signing** is the default key path: the private key never leaves
  the device. The gateway forwards each auth challenge to the client to sign
  (`ServerFrame::SignRequest` / `ClientFrame::SignResponse`). The target sees
  plain publickey auth — no server-side support required.
- **Password** and **gateway-stored key** modes are offered for generality
  (autonomous reconnect, password-only hosts). They trade key custody for
  convenience; secrets are held transiently, zeroized, never logged.
- A compromised gateway can read/inject **live** sessions for their lifetime but
  **cannot** steal a delegated key. Self-hosting reduces the trusted party to
  the operator; confidential-computing + attestation can shrink it further.
- App↔Gateway is always TLS (QUIC). Scrollback buffers are in-memory, bounded,
  and never persisted to disk by default.

---

## Stage 1: Protocol + QUIC transport skeleton
**Goal**: A client can open a QUIC connection to the gateway, complete the
`Hello` handshake, and round-trip framed `gw-proto` messages (echo).
**Success Criteria**:
- `gw-proto` frame set + length-prefixed `postcard` codec, with round-trip tests.
- `gw-transport` brings up a `quinn` server + client endpoint with a dev
  self-signed cert; a bidirectional stream carries length-prefixed frames.
- `gw-server` binary loads TOML config, starts the endpoint, accepts a client,
  and echoes frames.
**Tests**: codec round-trip (4 tests); loopback QUIC echo integration test
(client connects → `Hello` → `Ping`/`Pong`).
**Status**: ✅ Complete — `gw-proto` + `gw-transport` (QUIC/TLS, framing, ALPN,
migration-ready) + server accept loop. All tests green.

## Stage 2: SSH proxy core (key + password)
**Goal**: The gateway connects to a real target over SSH, opens a PTY, and
streams it to the client both ways; resize works.
**Success Criteria**:
- `gw-ssh` connects via `russh` and authenticates three ways:
  **delegated-signing key**, **password**, **gateway-stored key**.
- `Open` → live shell; `Data` flows both directions; `Resize` propagates.
- Delegated signing: gateway emits `SignRequest`, client returns
  `SignResponse`, auth completes; target needs no special config.
**Tests**: against a local sshd in CI (container) — password login echoes a
command; delegated-signing login with a test key; resize reflected by `stty`.
**Status**: ✅ Complete (gateway side) — `gw-ssh` connects via russh with
**password**, **private-key**, and **delegated-signing** auth (russh `Signer`
adapter → `RemoteSigner` → `ControlSigner` forwards `SignRequest`/`SignResponse`
over the control stream; private key never reaches the gateway). PTY + actor
loop. Builds green. **Remaining**: the iOS client's signing side (sign the
challenge with the on-device key); RSA delegated hash selection; live-sshd
integration test.

## Stage 3: Keep-alive session manager + containerization (OSS MVP)
**Goal**: A client can disconnect and reattach to the same live session with
scrollback replayed; ship a one-command self-host.
**Success Criteria**:
- `gw-core` keeps the SSH/PTY alive after the client drops (detach), retains a
  bounded scrollback ring buffer, and replays it on `Hello { resume }`.
- Resume tokens; idle/lifetime caps; clean teardown.
- `deploy/`: Dockerfile + docker-compose + one-command bring-up (auto TLS).
**Tests**: connect → run a long-lived command → kill client → reconnect with
resume token → scrollback + live output intact.
**Status**: ✅ Complete (core) — `gw-core` session manager with bounded
scrollback, detach/replay, resume tokens (5 unit tests); end-to-end wiring in
`gw-server` (negotiate → sender/receiver tasks → detach vs close). `deploy/`
has the Dockerfile + compose. **Remaining**: idle/lifetime reaper; the
container-based end-to-end test.

## Stage 4: SaaS control-plane (accounts + quota)
**Goal**: Multi-tenant gateway gated by a separate backend: per-user auth,
quota, and bandwidth limits, with usage metering.
**Success Criteria**:
- Gateway gains an **auth/quota hook** (gRPC or HTTP) called on client connect:
  validates an account token, returns plan limits.
- Per-user **token-bucket** rate/bandwidth limiting enforced in the data plane.
- Usage metering (bytes forwarded, session-minutes) reported to the backend.
- Separate backend service: register/login, plans, quota, usage storage
  (Postgres). Language TBD; talks to the gateway over the hook contract.
**Tests**: hook rejects an over-quota user; bandwidth cap observed; usage
counters reconcile end-to-end.
**Status**: ✅ Gateway side complete — `gw-core::quota` (`AuthHook` + `AllowAll`,
`Entitlement`, `TokenBucket`, `UsageMeter`; 5 tests) wired into the handler
(authorize-on-connect, per-connection metering, bandwidth throttle);
`Hello.account_token`. `gw-server` is now lib+bin: `serve(config, hook)` lets an
embedder choose the hook, and a built-in **`HttpAuthHook`** authorization
webhook (`auth_webhook_url` config; POSTs `{client_name, account_token}`,
applies the returned entitlement; 2 tests) connects it to a control plane. The
control-plane backend that answers the webhook lives in a **separate (private)
repo**.

## Stage 5: Productionization (+ payment integration point)
**Goal**: Operable, observable, and ready to attach billing.
**Success Criteria**:
- Usage dashboard / admin endpoints; metrics (`tracing` + Prometheus) and
  structured logs; health/readiness probes.
- WebSocket fallback transport for UDP-blocked networks.
- A clean, swappable **payment integration point** (no provider wired yet):
  plan → entitlement → quota mapping, webhook ingestion stub.
**Tests**: metrics scrape; WS fallback round-trip; entitlement change updates
quota without restart.
**Status**: Not Started.

---

## Crate map

| crate          | role |
|----------------|------|
| `gw-proto`     | App↔Gateway wire protocol (frames + codec). Shared with the iOS client. |
| `gw-transport` | QUIC endpoints (`quinn`): TLS, multiplexed streams, framing, migration. |
| `gw-ssh`       | SSH client to the target (`russh`): delegated-signing / password / stored-key auth. |
| `gw-core`      | Session manager: live PTY, scrollback ring buffer, detach/replay, resume. |
| `gw-server`    | The `shark-gateway` daemon: config, endpoint, wiring, observability. |

Remove this file when all stages are complete.
