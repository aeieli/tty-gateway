# shark-gateway

A self-hostable **keep-alive SSH gateway** for [SharkTTY](https://github.com/your-org/sharktty)
(and any client speaking the `gw-proto` protocol).

The gateway holds the live SSH session and PTY to a target host on your behalf,
so a mobile client can **drop, sleep, roam between networks, and reattach**
without losing the session — and **without installing anything on the target**.
The target only ever sees an ordinary `sshd` connection.

Think of it as moving the role of `tmux`/`mosh` off the target and onto a box
*you* control.

## Why

iOS/iPadOS suspends apps shortly after they leave the foreground, tearing down
live connections. The durable fix is to keep the session state somewhere that
stays awake. The two options are the target host (needs `tmux`/`mosh`) or a
gateway you run. This is the latter — open source, so the only party that can
see your live sessions is whoever runs the box (ideally you).

## Security model

- **Delegated signing (default):** the private key never leaves the device. The
  gateway forwards each SSH auth challenge to the client to sign, so it never
  holds your key and the target sees plain publickey auth. A compromised gateway
  can read/inject your *live* sessions for their lifetime, but **cannot steal a
  delegated key**.
- **Password / gateway-stored key:** offered for generality (password-only
  hosts, autonomous reconnect). Secrets are held transiently and never logged.
- App↔Gateway is always TLS (QUIC). Scrollback is in-memory and bounded.
- Self-host to shrink the trusted party to yourself; confidential-computing +
  attestation can shrink it further. A managed cloud option is planned as an
  explicit, opt-in trade-off.

## Architecture

```
 iPad app  ⇄ QUIC/TLS (roaming, 0-RTT resume) ⇄  shark-gateway  ⇄ plain SSH ⇄  target sshd
                                                  └ holds PTY + scrollback; survives client drops
```

| crate          | role |
|----------------|------|
| `gw-proto`     | App↔Gateway wire protocol (frames + codec). Shared with the client. |
| `gw-transport` | QUIC endpoints (`quinn`): TLS, multiplexed streams, framing, migration. |
| `gw-ssh`       | SSH client to the target (`russh`): delegated-signing / password / stored key. |
| `gw-core`      | Session manager: live PTY, scrollback ring buffer, detach/replay, resume. |
| `gw-server`    | The `shark-gateway` daemon. |

## Status

Working end-to-end (password + private-key auth), 15 tests green. See
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for the staged roadmap.

- **Stage 1 — protocol + QUIC transport:** ✅ complete (TLS, framing, migration-ready; echo test).
- **Stage 2 — SSH proxy:** ✅ password, private-key, **and delegated signing** (gateway side; client-signing is app work).
- **Stage 3 — keep-alive + container:** ✅ core complete (scrollback, detach/replay, resume).
- **Stage 4 — SaaS quota:** ✅ gateway side done (auth hook + HTTP authorization webhook, token-bucket limiter, metering); control-plane backend in a separate repo.
- **Stage 5 — productionization + billing:** ⬜ not started (payment deferred by design).

## Develop

```sh
cargo build --all
cargo test --all
```

## Self-host (once Stage 3 lands)

```sh
cd deploy
cp shark-gateway.example.toml shark-gateway.toml   # edit listen / TLS
docker compose up -d
```

## License

AGPL-3.0-only. Open-core: the gateway is AGPL (network use requires sharing
modifications), with a separate managed service offered on top.
