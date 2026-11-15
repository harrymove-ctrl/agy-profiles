#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${HOME}/.local/bin"
SKILL_DIR="${HOME}/.agents/skills"
WITH_SKILL=0
DRY_RUN=0
UNINSTALL=0
ASSUME_YES=0

usage() {
    cat <<'EOF'
Usage: install.sh [OPTIONS]

Install or remove agy-profiles and agyp symlinks using zero external dependencies.

Options:
  --prefix DIR       Target bin directory (default: ~/.local/bin)
  --with-skill       Also link the agy-profiles skill directory
  --skill-dir DIR    Target skills directory for --with-skill (default: ~/.agents/skills)
  --dry-run          Print planned operations without modifying the filesystem
  --uninstall        Remove installed symlinks pointing to this repository
  --yes              Overwrite conflicting non-repo symlinks without prompting
  -h, --help         Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            [[ $# -ge 2 ]] || { echo "Error: --prefix requires a directory argument" >&2; exit 2; }
            PREFIX="$2"
            shift 2
            ;;
        --skill-dir)
            [[ $# -ge 2 ]] || { echo "Error: --skill-dir requires a directory argument" >&2; exit 2; }
            SKILL_DIR="$2"
            shift 2
            ;;
        --with-skill)
            WITH_SKILL=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --yes)
            ASSUME_YES=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

run_cmd() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

check_python() {
    local py_bin
    py_bin="$(command -v python3 || true)"
    if [[ -z "${py_bin}" ]]; then
        echo "Error: python3 was not found in PATH" >&2
        exit 1
    fi
    if ! "${py_bin}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
        echo "Error: python3 >= 3.9 is required" >&2
        exit 1
    fi
}

remove_repo_link() {
    local link_path="$1"
    local expected_target="$2"
    if [[ -L "${link_path}" ]]; then
        local current_target
        current_target="$(readlink "${link_path}")"
        if [[ "${current_target}" == "${expected_target}" ]]; then
            run_cmd rm -f "${link_path}"
            echo "Removed symlink: ${link_path}"
        else
            echo "Skipped non-matching symlink: ${link_path} -> ${current_target}"
        fi
    elif [[ -e "${link_path}" ]]; then
        echo "Skipped non-symlink file: ${link_path}"
    else
        echo "Not installed: ${link_path}"
    fi
}

install_repo_link() {
    local src_path="$1"
    local dst_path="$2"
    if [[ -L "${dst_path}" ]]; then
        local existing_target
        existing_target="$(readlink "${dst_path}")"
        if [[ "${existing_target}" == "${src_path}" ]]; then
            echo "Already linked: ${dst_path} -> ${src_path}"
            return 0
        fi
        if [[ "${ASSUME_YES}" -ne 1 ]]; then
            echo "Conflict: ${dst_path} points to ${existing_target} (pass --yes to replace)" >&2
            exit 1
        fi
    elif [[ -e "${dst_path}" ]]; then
        echo "Conflict: ${dst_path} exists as a regular file or directory; remove it manually first" >&2
        exit 1
    fi
    run_cmd ln -sfn "${src_path}" "${dst_path}"
    echo "Linked: ${dst_path} -> ${src_path}"
}

BIN_PRIMARY="${SCRIPT_DIR}/bin/agy-profiles"
BIN_ALIAS="${SCRIPT_DIR}/bin/agyp"
SKILL_SRC="${SCRIPT_DIR}/.agents/skills/agy-profiles"

if [[ "${UNINSTALL}" -eq 1 ]]; then
    remove_repo_link "${PREFIX}/agy-profiles" "${BIN_PRIMARY}"
    remove_repo_link "${PREFIX}/agyp" "${BIN_ALIAS}"
    if [[ "${WITH_SKILL}" -eq 1 ]]; then
        remove_repo_link "${SKILL_DIR}/agy-profiles" "${SKILL_SRC}"
    fi
    exit 0
fi

check_python

if [[ ! -f "${BIN_PRIMARY}" || ! -f "${BIN_ALIAS}" ]]; then
    echo "Error: expected wrapper scripts in ${SCRIPT_DIR}/bin" >&2
    exit 1
fi

run_cmd chmod +x "${BIN_PRIMARY}" "${BIN_ALIAS}"
run_cmd mkdir -p "${PREFIX}"

install_repo_link "${BIN_PRIMARY}" "${PREFIX}/agy-profiles"
install_repo_link "${BIN_ALIAS}" "${PREFIX}/agyp"

if [[ "${WITH_SKILL}" -eq 1 ]]; then
    if [[ -d "${SKILL_SRC}" ]]; then
        run_cmd mkdir -p "${SKILL_DIR}"
        install_repo_link "${SKILL_SRC}" "${SKILL_DIR}/agy-profiles"
    else
        echo "Notice: skill directory ${SKILL_SRC} not present; skipping --with-skill" >&2
    fi
fi

case ":${PATH}:" in
    *":${PREFIX}:"*) ;;
    *)
        echo "Notice: add ${PREFIX} to your PATH to invoke agy-profiles and agyp directly."
        ;;
esac
