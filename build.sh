#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  build.sh -- install missing dependencies and compile the whole project.
#
#  Tested on Ubuntu 24.04. Run from the repository root:
#       ./build.sh
#
#  It installs g++ and make if they are missing (needs sudo for apt), then
#  builds: gen-table, attack, gen-passwd, check-passwd.
# ---------------------------------------------------------------------------
set -euo pipefail

need_pkg() { ! dpkg -s "$1" >/dev/null 2>&1; }

if command -v apt-get >/dev/null 2>&1; then
    PKGS=()
    need_pkg build-essential && PKGS+=(build-essential)
    if [ "${#PKGS[@]}" -gt 0 ]; then
        echo ">> Installing missing packages: ${PKGS[*]}"
        if [ "$(id -u)" -eq 0 ]; then
            apt-get update -y && apt-get install -y "${PKGS[@]}"
        else
            sudo apt-get update -y && sudo apt-get install -y "${PKGS[@]}"
        fi
    fi
else
    echo ">> apt-get not found; assuming g++ and make are already installed."
fi

echo ">> Compiling..."
make -j"$(nproc)"

echo ">> Build complete. Binaries: gen-table, attack, gen-passwd, check-passwd"
