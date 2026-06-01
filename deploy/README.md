# shark-gateway 部署

keep-alive SSH 网关，**QUIC/UDP** 协议。经 Traefik 的 **shark-udp (:4433/udp)** 入口
做 UDP 透传暴露（端到端 TLS 仍在网关上终止，Traefik 不解密）。
采用与 echo-api 一致的 **蓝绿部署** + Cargo 构建缓存。

## 目录结构

```
deploy/
├── Dockerfile.cached          # Rust 多阶段构建（缓存 cargo registry/git/target）
├── prod-build.sh              # 生产蓝绿部署脚本（deploy/rollback/status/switch）
├── shark-gateway.prod.toml    # 生产配置（listen / TLS / auth_webhook_url）
├── tls/                       # 放 cert.pem / key.pem（git 忽略；缺失则自签）
│
├── Dockerfile                 # 简单自托管镜像（docker compose 用）
├── docker-compose.yml         # 一键自托管（直接发布 4433/udp）
└── shark-gateway.example.toml # 自托管示例配置
```

## 网络拓扑

```
iPad 客户端 ─QUIC/UDP─▶ host:4433/udp ─▶ Traefik(shark-udp) ─UDP透传─▶ shark-gateway:4433
                                                                          │
                                                  ─POST /v1/authorize─▶ cloud-api:8080 (ttynet)
```

- `traefik_network`：Traefik UDP 透传到网关。
- `ttynet`：网关访问控制面 `cloud-api`（鉴权 / 配额）。

> 客户端 QUIC 连接 `tty-api.safafish.com:4433/udp`。该主机名的证书应放到 `tls/`
> 并在 `shark-gateway.prod.toml` 中启用 `tls_cert`/`tls_key`；缺失时网关自签（仅开发）。

## ⚠️ 蓝绿与有状态会话

网关把 PTY 与回滚缓冲保存在**内存**里。蓝绿切换停掉旧容器时，落在旧容器上的活动
会话会断开（客户端可重连，但会话状态不保留）。这是按设计的限制——keep-alive 抗的是
*客户端*掉线，不是*网关*重启。

## 前置条件（重要）

Traefik 需要一个 **UDP 入口**。本仓库已在 `~/traefik/config/traefik-with-stdout.yml`
增加：

```yaml
entryPoints:
  shark-udp:
    address: ":4433/udp"
```

并在 Traefik 启动脚本里发布该端口（`-p 4433:4433/udp`）。**修改后需重启 Traefik**：

```bash
~/traefik/restart-traefik-with-logs.sh
```

## 使用

```bash
# 从项目根目录执行
./deploy/prod-build.sh           # 部署新版本（默认 main 分支）
./deploy/prod-build.sh status    # 查看状态
./deploy/prod-build.sh rollback  # 回滚

# 纯自托管（不走 Traefik，直接发布 UDP）：
cd deploy && cp shark-gateway.example.toml shark-gateway.toml && docker compose up -d
```
