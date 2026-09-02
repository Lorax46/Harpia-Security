#!/bin/bash
set -euo pipefail

PROWLER_VERSION="${PROWLER_VERSION:-5.2.0}"

install_prowler() {
    echo "[harpia] Instalando Prowler v${PROWLER_VERSION}..."
    pip install "prowler==${PROWLER_VERSION}" --quiet
    echo "[harpia] Prowler instalado com sucesso."
}

run_scan() {
    local provider="${1:-aws}"
    local output_dir="${PROWLER_OUTPUT_DIR:-./output}"
    mkdir -p "$output_dir"
    
    echo "[harpia] Iniciando scan: provider=${provider}"
    prowler "$provider" \
        --output-directory "$output_dir" \
        --output-formats json csv html \
        --quiet
    echo "[harpia] Scan finalizado. Output: ${output_dir}"
}

case "${1:-install}" in
    install) install_prowler ;;
    scan)   run_scan "${2:-aws}" ;;
    *)      echo "Uso: $0 {install|scan [provider]}" ;;
esac
