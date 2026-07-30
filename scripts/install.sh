#!/bin/sh
# One-line installer for the GRYM CLI and TUI.
# Usage: curl -fsSL https://raw.githubusercontent.com/owner/grym/main/scripts/install.sh | sh
#        curl ... | sh -s -- --install-dir /usr/local/bin --bin grym

set -eu

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
REPO="grym"
OWNER="Karmanya03"
INSTALL_DIR="${INSTALL_DIR:-}"
VERSION="${VERSION:-latest}"
BIN="${BIN:-grym}"
NO_MODIFY_PATH="${NO_MODIFY_PATH:-0}"
FORCE_MUSL="${FORCE_MUSL:-0}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info() { printf '  %s\n' "$*"; }
error() { printf 'error: %s\n' "$*" >&2; exit 1; }

detect_owner() {
    # If the project already knows the owner, hard-code it here; otherwise the
    # release workflow can rewrite this placeholder.
    printf '%s' "$OWNER"
}

latest_release() {
    _owner="$1"
    _repo="$2"
    curl -fsSL "https://api.github.com/repos/${_owner}/${_repo}/releases/latest" | \
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1
}

os_name() {
    case "$(uname -s)" in
        Linux*)       printf 'linux';;
        Darwin*)      printf 'macos';;
        CYGWIN*|MSYS*|MINGW*) printf 'windows';;
        *)            printf 'unknown';;
    esac
}

arch_name() {
    case "$(uname -m)" in
        x86_64|amd64)   printf 'x86_64';;
        aarch64|arm64)  printf 'aarch64';;
        armv7l)         printf 'armv7';;
        *)              printf 'unknown';;
    esac
}

is_musl() {
    if [ "$FORCE_MUSL" = "1" ]; then
        return 0
    fi
    # ldd on musl libc systems reports itself as musl.
    if command -v ldd >/dev/null 2>&1; then
        ldd --version 2>&1 | grep -qi 'musl' && return 0
        if [ -x /bin/ls ]; then
            ldd /bin/ls 2>&1 | grep -qi 'musl' && return 0
        fi
    fi
    if [ -f /etc/alpine-release ]; then
        return 0
    fi
    if command -v apk >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

target_triple() {
    _os="$1"
    _arch="$2"
    if [ "$_os" = "linux" ]; then
        if is_musl; then
            printf '%s-unknown-linux-musl' "$_arch"
        else
            printf '%s-unknown-linux-gnu' "$_arch"
        fi
    elif [ "$_os" = "macos" ]; then
        printf '%s-apple-darwin' "$_arch"
    elif [ "$_os" = "windows" ]; then
        printf '%s-pc-windows-msvc' "$_arch"
    else
        printf 'unknown'
    fi
}

asset_name() {
    _version="$1"
    _target="$2"
    _bin="$3"
    if [ "$(os_name)" = "windows" ]; then
        printf '%s-%s-%s.zip' "$3" "$_version" "$_target"
    else
        printf '%s-%s-%s.tar.gz' "$3" "$_version" "$_target"
    fi
}

asset_url() {
    _owner="$1"
    _repo="$2"
    _version="$3"
    _asset="$4"
    printf 'https://github.com/%s/%s/releases/download/%s/%s' \
        "$_owner" "$_repo" "$_version" "$_asset"
}

detect_install_dir() {
    if [ -n "$INSTALL_DIR" ]; then
        printf '%s' "$INSTALL_DIR"
        return 0
    fi

    # Prefer a user-local location that does not require sudo. Global locations
    # are only used when the current user already has write permission.
    if [ -d "$HOME/.local/bin" ] && [ -w "$HOME/.local/bin" ]; then
        printf '%s' "$HOME/.local/bin"
        return 0
    fi
    if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        printf '%s' /usr/local/bin
        return 0
    fi
    if [ -d /usr/bin ] && [ -w /usr/bin ]; then
        printf '%s' /usr/bin
        return 0
    fi
    # Fallback: create a private directory.
    printf '%s' "$HOME/.local/bin"
}

ensure_dir() {
    _dir="$1"
    if [ ! -d "$_dir" ]; then
        mkdir -p "$_dir" || error "cannot create install directory $_dir"
    fi
    if [ ! -w "$_dir" ]; then
        error "install directory $_dir is not writable (try sudo or a different --install-dir)"
    fi
}

add_to_path_unix() {
    _dir="$1"
    _export_line="export PATH=\"$_dir:\$PATH\""
    _fish_line="fish_add_path $_dir"

    _updated=0
    # Update existing shell rc files.
    for _rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile"; do
        if [ -f "$_rc" ]; then
            if ! grep -qxF "$_export_line" "$_rc" 2>/dev/null; then
                printf '%s\n' "$_export_line" >> "$_rc"
                _updated=1
            fi
        fi
    done
    if [ -n "${SHELL:-}" ] && [ -f "$HOME/.config/fish/config.fish" ]; then
        if ! grep -qxF "$_fish_line" "$HOME/.config/fish/config.fish" 2>/dev/null; then
            printf '%s\n' "$_fish_line" >> "$HOME/.config/fish/config.fish"
            _updated=1
        fi
    fi
    # If no known rc file exists, create ~/.bashrc so first-time users still get PATH.
    if [ "$_updated" = "0" ]; then
        printf '%s\n' "$_export_line" >> "$HOME/.bashrc"
        _updated=1
    fi
    if [ "$_updated" = "1" ]; then
        info "Added $_dir to PATH in your shell configuration files."
        info "Run 'source ~/.bashrc' (or ~/.zshrc) or open a new terminal to use it."
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ "$#" -gt 0 ]; do
    case "$1" in
        --install-dir)
            INSTALL_DIR="$2"; shift 2;;
        --install-dir=*)
            INSTALL_DIR="${1#*=}"; shift;;
        --version)
            VERSION="$2"; shift 2;;
        --version=*)
            VERSION="${1#*=}"; shift;;
        --bin)
            BIN="$2"; shift 2;;
        --bin=*)
            BIN="${1#*=}"; shift;;
        --musl)
            FORCE_MUSL=1; shift;;
        --no-modify-path)
            NO_MODIFY_PATH=1; shift;;
        --owner)
            OWNER="$2"; shift 2;;
        --owner=*)
            OWNER="${1#*=}"; shift;;
        --help|-h)
            cat <<EOF
Usage: install.sh [OPTIONS]

Options:
  --install-dir DIR    Directory to install the binary (default: auto-detected)
  --version VERSION    Release tag to install (default: latest)
  --bin BIN            Binary to install: grym or grym-tui (default: grym)
  --musl               Force the Linux musl build (glibc-error-free/static)
  --no-modify-path     Do not add the install directory to PATH
  --owner OWNER        GitHub owner to use (default: $OWNER)
  --help, -h           Show this help
EOF
            exit 0
            ;;
        *)
            error "unknown option: $1"
            ;;
    esac
done

if [ "$BIN" != "grym" ] && [ "$BIN" != "grym-tui" ]; then
    error "--bin must be 'grym' or 'grym-tui'"
fi

# ---------------------------------------------------------------------------
# Detect platform
# ---------------------------------------------------------------------------
OS=$(os_name)
ARCH=$(arch_name)
if [ "$OS" = "unknown" ] || [ "$ARCH" = "unknown" ]; then
    error "unsupported platform: $(uname -s) $(uname -m)"
fi

TARGET=$(target_triple "$OS" "$ARCH")
info "Detected platform: $OS $ARCH -> $TARGET"

# ---------------------------------------------------------------------------
# Resolve version
# ---------------------------------------------------------------------------
OWNER=$(detect_owner)
if [ "$VERSION" = "latest" ] || [ -z "$VERSION" ]; then
    info "Resolving latest release..."
    VERSION=$(latest_release "$OWNER" "$REPO")
    if [ -z "$VERSION" ]; then
        error "could not determine the latest release for $OWNER/$REPO"
    fi
fi
info "Installing $BIN $VERSION for $TARGET"

# ---------------------------------------------------------------------------
# Prepare install directory
# ---------------------------------------------------------------------------
INSTALL_DIR=$(detect_install_dir)
ensure_dir "$INSTALL_DIR"
info "Install directory: $INSTALL_DIR"

# ---------------------------------------------------------------------------
# Download and install
# ---------------------------------------------------------------------------
ASSET=$(asset_name "$VERSION" "$TARGET" "$BIN")
URL=$(asset_url "$OWNER" "$REPO" "$VERSION" "$ASSET")
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading $ASSET..."
if ! curl -fsSL --retry 3 --retry-delay 1 "$URL" -o "$TMPDIR/$ASSET"; then
    printf 'error: failed to download %s\n' "$URL" >&2
    error "Check the release tag, owner, and that an asset exists for $TARGET."
fi

info "Extracting..."
cd "$TMPDIR"
if [ "${ASSET%.zip}" != "$ASSET" ]; then
    unzip -q "$ASSET"
else
    tar -xzf "$ASSET"
fi

if [ ! -f "$TMPDIR/$BIN" ] && [ ! -f "$TMPDIR/$BIN.exe" ]; then
    error "expected binary '$BIN' not found in the downloaded archive"
fi

if [ -f "$TMPDIR/$BIN" ]; then
    install -m 755 "$TMPDIR/$BIN" "$INSTALL_DIR/$BIN"
fi
if [ -f "$TMPDIR/$BIN.exe" ]; then
    install -m 755 "$TMPDIR/$BIN.exe" "$INSTALL_DIR/$BIN.exe"
fi

# ---------------------------------------------------------------------------
# Update PATH
# ---------------------------------------------------------------------------
if [ "$NO_MODIFY_PATH" != "1" ] && [ "$(os_name)" != "windows" ]; then
    add_to_path_unix "$INSTALL_DIR"
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
if command -v "$INSTALL_DIR/$BIN" >/dev/null 2>&1; then
    info "Installed: $INSTALL_DIR/$BIN"
    "$INSTALL_DIR/$BIN" --version || true
else
    info "Installed to $INSTALL_DIR, but it is not in your current PATH."
fi

info "Done."
