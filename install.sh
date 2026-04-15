#!/bin/bash

set -e

REPO="topxeq/goconnectit"
BINARY_NAME="goconnectit"
INSTALL_DIR="/usr/local/bin"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_os() {
    case "$(uname -s)" in
        Darwin*)    echo "darwin" ;;
        Linux*)     echo "linux" ;;
        CYGWIN*|MINGW*|MSYS*)    echo "windows" ;;
        *)          echo "unknown" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)    echo "amd64" ;;
        arm64|aarch64)   echo "arm64" ;;
        *)               echo "unknown" ;;
    esac
}

get_latest_version() {
    curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

download_file() {
    local url="$1"
    local output="$2"
    
    if command -v curl &> /dev/null; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget &> /dev/null; then
        wget -q "$url" -O "$output"
    else
        log_error "curl or wget is required"
        exit 1
    fi
}

main() {
    log_info "Installing goconnectit..."
    
    OS=$(detect_os)
    ARCH=$(detect_arch)
    
    if [ "$OS" = "unknown" ] || [ "$ARCH" = "unknown" ]; then
        log_error "Unsupported OS or architecture: $OS/$ARCH"
        exit 1
    fi
    
    log_info "Detected OS: $OS, Architecture: $ARCH"
    
    VERSION=$(get_latest_version)
    if [ -z "$VERSION" ]; then
        log_error "Failed to get latest version"
        exit 1
    fi
    log_info "Latest version: $VERSION"
    
    if [ "$OS" = "windows" ]; then
        ARCHIVE_NAME="${BINARY_NAME}-${OS}-${ARCH}.zip"
    else
        ARCHIVE_NAME="${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    fi
    
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"
    log_info "Downloading from: $DOWNLOAD_URL"
    
    TMP_DIR=$(mktemp -d)
    ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
    
    download_file "$DOWNLOAD_URL" "$ARCHIVE_PATH"
    
    log_info "Extracting..."
    cd "$TMP_DIR"
    
    if [ "$OS" = "windows" ]; then
        unzip -o "$ARCHIVE_PATH"
    else
        tar -xzf "$ARCHIVE_PATH"
    fi
    
    if [ "$OS" != "windows" ]; then
        log_info "Installing to ${INSTALL_DIR}/${BINARY_NAME}"
        sudo mkdir -p "$INSTALL_DIR"
        sudo mv "$BINARY_NAME" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi
    
    rm -rf "$TMP_DIR"
    
    log_info "Installation complete!"
    log_info "Run '${BINARY_NAME} -h' for usage information."
}

main "$@"
