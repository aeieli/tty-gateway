#!/bin/bash

# shark-gateway 生产环境构建脚本 - 蓝绿部署（Rust + 缓存优化）
# QUIC/UDP 网关，经 Traefik 的 shark-udp(:4433/udp) 入口透传暴露。
#
# 使用方法:
#   ./deploy/prod-build.sh          # 默认部署新版本
#   ./deploy/prod-build.sh deploy   # 部署新版本
#   ./deploy/prod-build.sh rollback # 回滚到上一个版本
#   ./deploy/prod-build.sh status   # 查看当前状态
#   ./deploy/prod-build.sh switch   # 手动切换到备用容器
#
# ⚠️ 注意：网关把 PTY/回滚缓冲保存在内存里，蓝绿切换停掉旧容器时，落在旧容器上的
#    活动会话会断开（客户端可重连，但会话状态不保留）。这是按设计的限制。

set -e

# ---------- 配置 ----------
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY_DIR="${DEPLOY_DIR:-/home/eric/server/tty-gateway}"
STATE_FILE="${STATE_FILE:-$DEPLOY_DIR/.bluegreen-state}"

# Cargo 缓存目录
CACHE_BASE_DIR="${CACHE_BASE_DIR:-/home/eric/.cache/shark-gateway-build}"
CARGO_REGISTRY_CACHE="${CARGO_REGISTRY_CACHE:-${CACHE_BASE_DIR}/registry}"
CARGO_GIT_CACHE="${CARGO_GIT_CACHE:-${CACHE_BASE_DIR}/git}"
CARGO_TARGET_CACHE="${CARGO_TARGET_CACHE:-${CACHE_BASE_DIR}/target}"

# 容器 / 镜像
BASE_NAME="shark-gateway"
IMAGE_NAME="localhost/shark-gateway"
IMAGE_TAG="0.0.1"
TRAEFIK_NETWORK="traefik_network"   # Traefik UDP 透传网络
APP_NETWORK="ttynet"                # 网关 <-> 控制面 内部网络

# Traefik UDP 入口（见 traefik 静态配置中的 entryPoints.shark-udp）
UDP_ENTRYPOINT="shark-udp"
INTERNAL_PORT="4433"

# 配置文件 / TLS 目录 / 密钥文件
CONFIG_FILE="${CONFIG_FILE:-${PROJECT_ROOT}/deploy/shark-gateway.prod.toml}"
TLS_DIR="${TLS_DIR:-${PROJECT_ROOT}/deploy/tls}"
SECRET_ENV="${SECRET_ENV:-${PROJECT_ROOT}/deploy/secret.env}"   # gitignored: SHARK_GATEWAY_KEY

# Git 分支
BRANCH="${2:-main}"

# 蓝绿容器名
BLUE_CONTAINER="${BASE_NAME}-blue"
GREEN_CONTAINER="${BASE_NAME}-green"

ACTION="${1:-deploy}"

# ---------- 工具函数 ----------
function setup_cache_dirs() {
    echo "📁 设置 Cargo 缓存目录..."
    mkdir -p "$CARGO_REGISTRY_CACHE" "$CARGO_GIT_CACHE" "$CARGO_TARGET_CACHE"
    echo "   registry: $CARGO_REGISTRY_CACHE"
    echo "   git:      $CARGO_GIT_CACHE"
    echo "   target:   $CARGO_TARGET_CACHE"
    echo ""
}

function check_environment() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "❌ 错误: 配置文件不存在: $CONFIG_FILE"
        exit 1
    fi
    echo "✅ 配置文件: $CONFIG_FILE"

    mkdir -p "$DEPLOY_DIR" "$TLS_DIR"
    if [ ! -f "$TLS_DIR/cert.pem" ] || [ ! -f "$TLS_DIR/key.pem" ]; then
        echo "⚠️  $TLS_DIR 下未找到 cert.pem/key.pem —— 网关将生成自签证书（仅开发用）。"
        echo "   生产环境请放置 tty-api.safafish.com 的证书并在 shark-gateway.prod.toml 中启用 tls_*。"
    fi

    if [ -f "$SECRET_ENV" ]; then
        echo "✅ 密钥文件: $SECRET_ENV"
    else
        echo "⚠️  未找到 $SECRET_ENV —— 网关不带 X-Gateway-Key 调用控制面，控制面会拒绝内部端点。"
        echo "   请创建该文件并写入 SHARK_GATEWAY_KEY=<与 cloud-api 一致的密钥>。"
    fi

    if ! podman network exists "$TRAEFIK_NETWORK"; then
        echo "❌ 错误: Traefik 网络不存在: $TRAEFIK_NETWORK"
        exit 1
    fi
    if ! podman network exists "$APP_NETWORK"; then
        echo "🔧 创建内部网络: $APP_NETWORK"
        podman network create "$APP_NETWORK"
    fi
}

function get_current_container() {
    if podman ps --format "{{.Names}}" | grep -q "^${BLUE_CONTAINER}$"; then
        echo "$BLUE_CONTAINER"
    elif podman ps --format "{{.Names}}" | grep -q "^${GREEN_CONTAINER}$"; then
        echo "$GREEN_CONTAINER"
    else
        echo ""
    fi
}

function get_standby_container() {
    local current=$(get_current_container)
    if [ "$current" = "$BLUE_CONTAINER" ]; then
        echo "$GREEN_CONTAINER"
    elif [ "$current" = "$GREEN_CONTAINER" ]; then
        echo "$BLUE_CONTAINER"
    else
        echo "$BLUE_CONTAINER"
    fi
}

function save_state() {
    local current_container="$1"
    local previous_container="$2"
    local timestamp=$(date '+%Y-%m-%d_%H:%M:%S')
    cat > "$STATE_FILE" <<EOF
CURRENT_CONTAINER=$current_container
PREVIOUS_CONTAINER=$previous_container
LAST_DEPLOYMENT="$timestamp"
DEPLOYMENT_COUNT=$((${DEPLOYMENT_COUNT:-0} + 1))
EOF
    echo "📝 状态已保存到 $STATE_FILE"
}

function load_state() {
    if [ -f "$STATE_FILE" ]; then
        source "$STATE_FILE"
    else
        CURRENT_CONTAINER=""; PREVIOUS_CONTAINER=""; LAST_DEPLOYMENT=""; DEPLOYMENT_COUNT=0
    fi
}

function show_status() {
    echo "📊 shark-gateway 蓝绿部署状态"
    echo "============================="
    load_state
    local current_running=$(get_current_container)
    echo ""
    echo "🔄 当前运行: ${current_running:-无}"
    echo "   上次部署: ${LAST_DEPLOYMENT:-未知}"
    echo "   部署次数: ${DEPLOYMENT_COUNT:-0}"
    echo "   入口:     udp://${UDP_ENTRYPOINT} (:${INTERNAL_PORT}/udp)"
    echo ""
    echo "📦 容器详情:"
    podman ps -a --filter "name=${BASE_NAME}-" \
        --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}" || echo "   无容器"
}

# 网关无 HTTP 健康端点：确认容器持续运行且日志无即时崩溃
function gateway_health_check() {
    local container="$1"
    sleep 3
    if ! podman ps --filter "name=$container" --filter "status=running" -q | grep -q .; then
        return 1
    fi
    if podman logs --tail 50 "$container" 2>&1 | grep -qiE 'panic|error binding|address already in use'; then
        return 1
    fi
    return 0
}

function perform_deploy() {
    echo "🚀 shark-gateway 生产环境蓝绿部署"
    echo "================================="
    echo "分支: ${BRANCH}"
    echo "入口: ${UDP_ENTRYPOINT} (:${INTERNAL_PORT}/udp)"
    echo ""

    check_environment
    setup_cache_dirs

    cd "$PROJECT_ROOT"
    current_branch=$(git branch --show-current)
    if [ "$current_branch" != "$BRANCH" ]; then
        echo "切换到 $BRANCH 分支..."
        git checkout "$BRANCH" || { echo "❌ 无法切换到 $BRANCH"; exit 1; }
    fi
    echo "拉取最新 $BRANCH 代码..."
    git pull origin "$BRANCH" || echo "⚠️  无法拉取最新代码，使用本地版本"

    local GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    echo "🔖 Git Commit: $GIT_COMMIT"

    echo "构建镜像（Cargo 缓存）..."
    local build_start=$(date +%s)
    podman build \
        --format docker \
        --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
        --build-arg GIT_COMMIT="$GIT_COMMIT" \
        --volume "${CARGO_REGISTRY_CACHE}:/usr/local/cargo/registry:rw" \
        --volume "${CARGO_GIT_CACHE}:/usr/local/cargo/git:rw" \
        --volume "${CARGO_TARGET_CACHE}:/src/target:rw" \
        --file "deploy/Dockerfile.cached" \
        .
    local build_time=$(( $(date +%s) - build_start ))
    echo "✅ 镜像构建成功: ${IMAGE_NAME}:${IMAGE_TAG} (耗时 ${build_time}s)"

    local current_container=$(get_current_container)
    local new_container=$(get_standby_container)
    [ -n "$current_container" ] && echo "📦 当前: $current_container → 🆕 部署到: $new_container" \
                                || echo "📦 首次部署: $new_container"

    if podman ps -a --format "{{.Names}}" | grep -q "^${new_container}$"; then
        podman stop "$new_container" 2>/dev/null || true
        podman rm "$new_container" 2>/dev/null || true
    fi

    # 共享密钥（如存在）通过 --env-file 注入 SHARK_GATEWAY_KEY。
    local secret_arg=()
    [ -f "$SECRET_ENV" ] && secret_arg=(--env-file "$SECRET_ENV")

    echo "启动新容器: $new_container"
    podman run \
        --name "$new_container" \
        --network "$APP_NETWORK" \
        -v "${CONFIG_FILE}:/etc/shark-gateway/shark-gateway.toml:ro" \
        -v "${TLS_DIR}:/etc/shark-gateway/tls:ro" \
        "${secret_arg[@]}" \
        -e RUST_LOG="${RUST_LOG:-shark_gateway=info,gw_server=info}" \
        --cpus=2 \
        --memory=2g \
        -d \
        --restart always \
        --label "traefik.enable=true" \
        --label "traefik.udp.routers.${BASE_NAME}.entrypoints=${UDP_ENTRYPOINT}" \
        --label "traefik.udp.routers.${BASE_NAME}.service=${BASE_NAME}" \
        --label "traefik.udp.services.${BASE_NAME}.loadbalancer.server.port=${INTERNAL_PORT}" \
        --label "branch=${BRANCH}" \
        "${IMAGE_NAME}:${IMAGE_TAG}"

    echo "连接到 Traefik 网络..."
    podman network connect "$TRAEFIK_NETWORK" "$new_container"

    echo "执行健康检查..."
    if ! gateway_health_check "$new_container"; then
        echo "❌ 新容器健康检查失败，查看日志:"
        podman logs --tail 50 "$new_container" || true
        podman rm -f "$new_container" 2>/dev/null || true
        exit 1
    fi
    echo "✅ 健康检查通过"

    if [ -n "$current_container" ]; then
        echo "⏸️  等待在途请求完成（10s）..."
        sleep 10
        echo "停止旧容器: $current_container"
        podman stop "$current_container"
    fi

    save_state "$new_container" "$current_container"
    echo ""
    echo "✅ 部署成功！"
    echo "   入口: ${UDP_ENTRYPOINT} → 客户端 QUIC 连 tty-api.safafish.com:${INTERNAL_PORT}/udp"
    echo "   活动容器: $new_container"
    if [ -n "$current_container" ]; then
        echo "   备用容器: $current_container (已停止)  回滚: $0 rollback"
    fi
}

function perform_rollback() {
    echo "🔄 shark-gateway 回滚"
    echo "====================="
    check_environment
    load_state
    local current_container=$(get_current_container)
    [ -z "$current_container" ] && { echo "❌ 没有正在运行的容器"; exit 1; }

    local standby_container
    [ "$current_container" = "$BLUE_CONTAINER" ] && standby_container="$GREEN_CONTAINER" || standby_container="$BLUE_CONTAINER"
    if ! podman ps -a --format "{{.Names}}" | grep -q "^${standby_container}$"; then
        echo "❌ 备用容器不存在: $standby_container"; exit 1
    fi

    echo "启动备用容器: $standby_container"
    podman start "$standby_container"
    if ! gateway_health_check "$standby_container"; then
        echo "❌ 备用容器启动失败"; exit 1
    fi
    podman network disconnect "$TRAEFIK_NETWORK" "$standby_container" 2>/dev/null || true
    podman network connect "$TRAEFIK_NETWORK" "$standby_container"

    echo "⏸️  等待在途请求完成（10s）..."
    sleep 10
    echo "停止当前容器: $current_container"
    podman stop "$current_container"
    save_state "$standby_container" "$current_container"
    echo "✅ 回滚完成，活动容器: $standby_container"
}

case "$ACTION" in
    deploy)   perform_deploy ;;
    rollback) perform_rollback ;;
    switch)   perform_rollback ;;
    status)   show_status ;;
    *)
        echo "用法: $0 [deploy|rollback|status|switch] [branch]"
        exit 1 ;;
esac
