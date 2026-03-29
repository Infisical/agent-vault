#!/bin/sh
set -e

# Agent Vault installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Infisical/agent-vault/main/install.sh | sh
#
# Supports: macOS (Intel + Apple Silicon), Linux (amd64 + arm64)
# Works for both fresh install and upgrade.

REPO="Infisical/agent-vault"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="$HOME/.agent-vault"
PID_FILE="$DATA_DIR/agent-vault.pid"
DB_FILE="$DATA_DIR/agent-vault.db"

# ── Helpers ──────────────────────────────────────────────────────────────────

info()  { printf '  %s\n' "$*"; }
warn()  { printf '  [warn] %s\n' "$*" >&2; }
error() { printf '  [error] %s\n' "$*" >&2; exit 1; }

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        error "Required command '$1' not found. Please install it and try again."
    fi
}

# Use sudo only if we don't have write permission to INSTALL_DIR.
maybe_sudo() {
    if [ -w "$INSTALL_DIR" ]; then
        "$@"
    else
        info "Elevated permissions required to write to $INSTALL_DIR"
        sudo "$@"
    fi
}

# ── Detect platform ─────────────────────────────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "darwin" ;;
        Linux)  echo "linux" ;;
        *)      error "Unsupported operating system: $(uname -s). This installer supports macOS and Linux." ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64" ;;
        arm64|aarch64)  echo "arm64" ;;
        *)              error "Unsupported architecture: $(uname -m). This installer supports x86_64 and arm64." ;;
    esac
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    need_cmd curl
    need_cmd tar
    need_cmd uname

    OS="$(detect_os)"
    ARCH="$(detect_arch)"

    info "Detected platform: ${OS}/${ARCH}"

    # ── Check for existing installation ──────────────────────────────────

    EXISTING_VERSION=""
    SERVER_WAS_RUNNING=false

    if command -v agent-vault > /dev/null 2>&1; then
        EXISTING_VERSION="$(agent-vault version 2>/dev/null || echo "unknown")"
        info "Existing installation found: ${EXISTING_VERSION}"

        # ── Stop running server ──────────────────────────────────────────
        if [ -f "$PID_FILE" ]; then
            PID="$(cat "$PID_FILE" 2>/dev/null || echo "")"
            if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
                info "Stopping running server (PID ${PID})..."
                agent-vault server stop 2>/dev/null || true
                # Wait up to 10 seconds for the process to exit
                i=0
                while [ $i -lt 20 ] && kill -0 "$PID" 2>/dev/null; do
                    sleep 0.5
                    i=$((i + 1))
                done
                if kill -0 "$PID" 2>/dev/null; then
                    warn "Server did not stop within 10 seconds. Proceeding anyway."
                else
                    info "Server stopped."
                    SERVER_WAS_RUNNING=true
                fi
            fi
        fi

        # ── Back up database ─────────────────────────────────────────────
        if [ -f "$DB_FILE" ]; then
            TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
            BACKUP_FILE="${DB_FILE}.backup-${TIMESTAMP}"
            info "Backing up database to ${BACKUP_FILE}"
            cp "$DB_FILE" "$BACKUP_FILE"
            # Also back up WAL and SHM files if they exist
            [ -f "${DB_FILE}-wal" ] && cp "${DB_FILE}-wal" "${BACKUP_FILE}-wal"
            [ -f "${DB_FILE}-shm" ] && cp "${DB_FILE}-shm" "${BACKUP_FILE}-shm"
        fi
    fi

    # ── Fetch latest version ─────────────────────────────────────────────

    info "Fetching latest release..."
    LATEST="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name":[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/')"

    if [ -z "$LATEST" ]; then
        error "Could not determine the latest release version. Check your internet connection or try again later."
    fi

    info "Latest version: v${LATEST}"

    # ── Download and extract ─────────────────────────────────────────────

    ARCHIVE="agent-vault_${LATEST}_${OS}_${ARCH}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/v${LATEST}/${ARCHIVE}"

    TMP_DIR="$(mktemp -d)"
    info "Downloading ${ARCHIVE}..."

    if ! curl -fSL --progress-bar -o "${TMP_DIR}/${ARCHIVE}" "$URL"; then
        error "Download failed. The release may not include a binary for ${OS}/${ARCH}."
    fi

    info "Extracting..."
    tar xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"

    if [ ! -f "${TMP_DIR}/agent-vault" ]; then
        error "Archive did not contain the expected 'agent-vault' binary."
    fi

    chmod +x "${TMP_DIR}/agent-vault"

    # ── Install ──────────────────────────────────────────────────────────

    maybe_sudo mv "${TMP_DIR}/agent-vault" "${INSTALL_DIR}/agent-vault"

    # ── Verify ───────────────────────────────────────────────────────────

    INSTALLED_VERSION="$(agent-vault version 2>/dev/null || echo "")"
    if [ -z "$INSTALLED_VERSION" ]; then
        warn "Could not verify installed binary."
        if [ -n "$EXISTING_VERSION" ]; then
            warn "A database backup was saved at: ${BACKUP_FILE}"
        fi
        error "Installation may have failed. Check that ${INSTALL_DIR} is in your PATH."
    fi

    echo ""
    info "Agent Vault ${INSTALLED_VERSION} installed successfully."

    if [ -n "$EXISTING_VERSION" ] && [ "$EXISTING_VERSION" != "unknown" ]; then
        info "Upgraded from ${EXISTING_VERSION}"
        info "Database backup: ${BACKUP_FILE}"
    fi

    if [ "$SERVER_WAS_RUNNING" = true ]; then
        echo ""
        info "The server was stopped for the upgrade."
        info "Run 'agent-vault server' to start it again."
        info "Database migrations (if any) will run automatically on startup."
    fi
}

main "$@"
