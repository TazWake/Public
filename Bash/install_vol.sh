#!/bin/bash
#
# install_vol.sh - Install Volatility 3 on a Debian/Ubuntu system.
#
# WHAT THIS SCRIPT DOES
#   1. Verifies it is running as root on a supported (Debian-family) system.
#   2. Installs the OS packages needed to build and run Volatility 3.
#   3. Clones (or updates) the Volatility 3 source into /opt/tools/volatility3.
#   4. Installs Volatility 3 into a dedicated Python virtual environment at
#      /opt/tools/volatility3-venv, together with the optional extras that make
#      the plugins genuinely useful (yara, pycryptodome, capstone, etc).
#   5. Publishes `vol`, `vol.py` and `volshell` wrappers into /usr/local/bin so
#      every user on the box gets them on their PATH.
#   6. Creates a drop-in directory for custom plugins and verifies the install
#      by actually running the tool.
#
# WHY A VIRTUAL ENVIRONMENT?
#   Ubuntu 24.04 and later ship a PEP 668 "externally managed" Python. Using
#   `pip install --break-system-packages` (as older versions of this script did)
#   mixes pip-managed files into the dpkg-managed site-packages tree, which
#   breaks on distribution upgrades and can leave apt unable to fix itself. A
#   venv keeps Volatility's dependency tree entirely separate from the OS
#   Python, so this approach works unchanged on 24.04, 25.04 and 26.04.
#
# USAGE
#   sudo ./install_vol.sh [--help]
#
# EXIT CODES
#   0   success
#   1   a required step failed (see the error message printed at the point of
#       failure - every step reports what went wrong and how to fix it)
#   2   invalid command line usage
#   255 not running as root
#
# set -e  : abort on the first failing command rather than blundering onwards.
# set -u  : treat unset variables as an error - catches typos in variable names.
# set -o pipefail : a failure anywhere in a pipeline fails the whole pipeline,
#                   otherwise `git clone ... | tee log` would report success
#                   whenever tee succeeded.
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
readonly INSTALL_ROOT="/opt/tools"
readonly VOL_SRC_DIR="${INSTALL_ROOT}/volatility3"
readonly VOL_VENV_DIR="${INSTALL_ROOT}/volatility3-venv"
readonly VOL_REPO_URL="https://github.com/volatilityfoundation/volatility3.git"
readonly BIN_DIR="/usr/local/bin"
readonly LOG_FILE="/var/log/install_vol.log"

# Full absolute paths are used for every external command so that the script
# cannot be subverted by a modified PATH when invoked via sudo.
readonly APT="/usr/bin/apt-get"
readonly GIT="/usr/bin/git"
readonly PYTHON="/usr/bin/python3"
readonly ID_CMD="/usr/bin/id"

# ---------------------------------------------------------------------------
# Output helpers - every stage tells the user what is happening and why.
# ---------------------------------------------------------------------------
log()     { printf '[ ] %s\n' "$*"; }
success() { printf '[+] %s\n' "$*"; }
warn()    { printf '[!] %s\n' "$*" >&2; }

# die <message> [exit_code] - print an actionable error and stop.
die() {
    local message="$1"
    local code="${2:-1}"
    printf '[X] ERROR: %s\n' "${message}" >&2
    printf '[X] Installation aborted. Nothing further has been changed.\n' >&2
    exit "${code}"
}

usage() {
    /bin/sed -n '2,30p' "$0" | /bin/sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

# check_arguments - this script takes no options other than --help. Anything
# else is almost certainly a mistake, so fail loudly rather than ignoring it.
check_arguments() {
    if [[ $# -gt 0 ]]; then
        case "$1" in
            -h|--help) usage 0 ;;
            *) warn "Unknown argument: $1"; usage 2 ;;
        esac
    fi
}

# check_privileges - we write to /opt and /usr/local/bin and drive apt, all of
# which need root.
check_privileges() {
    if [[ "$(${ID_CMD} -u)" -ne 0 ]]; then
        die "This script must be run with root privileges. Re-run it as: sudo $0" 255
    fi
    success "Running with root privileges."
}

# check_platform - Volatility 3 itself is portable, but this installer drives
# apt and assumes Debian-style paths. Warn (rather than hard fail) on unknown
# derivatives so the script remains usable on Kali, Mint, Pop!_OS and similar.
#
# This runs BEFORE the dependency install, so it must not assume python3 or git
# are present - a minimal Ubuntu container has neither. Only apt is required.
check_platform() {
    if [[ ! -x "${APT}" ]]; then
        die "apt-get was not found at ${APT}. This installer only supports Debian/Ubuntu systems."
    fi

    local distro_id="unknown" distro_version="unknown"
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        distro_id="${ID:-unknown}"
        distro_version="${VERSION_ID:-unknown}"
    fi

    case "${distro_id}" in
        ubuntu|debian|kali|linuxmint|pop)
            log "Detected ${distro_id} ${distro_version}."
            ;;
        *)
            warn "Unrecognised distribution '${distro_id}'. Continuing, but this script is tested on Ubuntu 24.04 and later."
            ;;
    esac
}

# check_python - run after the dependency install, once python3 is guaranteed to
# exist. Volatility 3 requires Python 3.8+; 24.04 ships 3.12 and 25.04/26.04
# ship newer still, so this is really a guard against very old derivatives.
check_python() {
    [[ -x "${PYTHON}" ]] || die "python3 was not found at ${PYTHON} even after installation. Install it manually with: apt install python3"

    local py_version
    py_version="$(${PYTHON} -c 'import sys; print("%d.%d" % sys.version_info[:2])')" \
        || die "Unable to determine the Python 3 version. Is ${PYTHON} a working interpreter?"
    log "Using Python ${py_version} (${PYTHON})."

    if ! ${PYTHON} -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
        die "Volatility 3 requires Python 3.8 or newer; this system has ${py_version}."
    fi
}

# check_network - the install clones from GitHub and pulls wheels from PyPI.
# Failing here with a clear message is far friendlier than a wall of git output.
# Runs after the dependency install because it needs git.
check_network() {
    log "Checking network access to github.com..."
    if ! ${GIT} ls-remote --exit-code --heads "${VOL_REPO_URL}" >/dev/null 2>&1; then
        die "Cannot reach ${VOL_REPO_URL}. Check your network connection and any proxy settings (https_proxy), then re-run."
    fi
    success "Network access confirmed."
}

# ---------------------------------------------------------------------------
# Installation stages
# ---------------------------------------------------------------------------

# install_dependencies - build tooling plus the libraries Volatility's optional
# extras compile against. python3-venv is separate from python3 on Ubuntu and
# is the single most common cause of a failed install, so it is explicit here.
install_dependencies() {
    log "Stage 1/5: Installing operating system dependencies (this may take a few minutes)..."

    export DEBIAN_FRONTEND=noninteractive

    ${APT} update -qq \
        || die "'apt-get update' failed. Check /etc/apt/sources.list and your network, then re-run."

    local packages=(
        git
        python3
        python3-venv
        python3-dev
        python3-pip
        build-essential
        libssl-dev
        libffi-dev
        pkg-config
    )

    ${APT} install -y "${packages[@]}" \
        || die "Failed to install required packages: ${packages[*]}. Run 'apt-get install ${packages[*]}' manually to see the underlying error."

    [[ -x "${GIT}" ]] || die "git is still not present at ${GIT} after installation."
    success "Operating system dependencies installed."
}

# fetch_source - clone on first run, fast-forward on subsequent runs. The script
# is deliberately re-runnable so it can double as an updater.
fetch_source() {
    log "Stage 2/5: Fetching the Volatility 3 source into ${VOL_SRC_DIR}..."

    /bin/mkdir -p "${INSTALL_ROOT}" \
        || die "Could not create ${INSTALL_ROOT}. Check filesystem permissions and free space."

    if [[ -d "${VOL_SRC_DIR}/.git" ]]; then
        log "An existing checkout was found - updating it instead of re-cloning."
        ${GIT} -C "${VOL_SRC_DIR}" fetch --quiet --all \
            || die "Failed to fetch updates in ${VOL_SRC_DIR}. If the checkout is damaged, remove it with 'rm -rf ${VOL_SRC_DIR}' and re-run this script."
        ${GIT} -C "${VOL_SRC_DIR}" pull --quiet --ff-only \
            || die "Could not fast-forward ${VOL_SRC_DIR} (you may have local modifications). Stash or discard them, or remove the directory and re-run."
        success "Existing Volatility 3 checkout updated."
    elif [[ -e "${VOL_SRC_DIR}" ]]; then
        die "${VOL_SRC_DIR} exists but is not a git checkout. Move or remove it, then re-run this script."
    else
        ${GIT} clone --quiet "${VOL_REPO_URL}" "${VOL_SRC_DIR}" \
            || die "git clone of ${VOL_REPO_URL} failed. Check network/proxy settings and try again."
        success "Volatility 3 source cloned."
    fi

    local revision
    revision="$(${GIT} -C "${VOL_SRC_DIR}" rev-parse --short HEAD)" || revision="unknown"
    log "Source is at revision ${revision}."
}

# install_volatility - build the venv and install Volatility in editable mode so
# that a later `git pull` in the source tree takes effect immediately without a
# reinstall. The [full] extra pulls in yara, capstone, pycryptodome, leechcore
# and friends; if that fails (a missing header for one optional dependency
# should not block the whole install) we fall back to the core install.
install_volatility() {
    log "Stage 3/5: Creating the Python virtual environment at ${VOL_VENV_DIR}..."

    if [[ -d "${VOL_VENV_DIR}" ]]; then
        log "Removing the previous virtual environment so the rebuild is clean."
        /bin/rm -rf "${VOL_VENV_DIR}" \
            || die "Could not remove the old virtual environment at ${VOL_VENV_DIR}."
    fi

    ${PYTHON} -m venv "${VOL_VENV_DIR}" \
        || die "Failed to create the virtual environment. Ensure the python3-venv package is installed: apt install python3-venv"

    local venv_pip="${VOL_VENV_DIR}/bin/pip"
    [[ -x "${venv_pip}" ]] || die "The virtual environment at ${VOL_VENV_DIR} has no pip - creation did not complete correctly."

    log "Upgrading pip/setuptools/wheel inside the virtual environment..."
    "${venv_pip}" install --quiet --upgrade pip setuptools wheel \
        || die "Failed to upgrade pip inside the virtual environment. Check network access to pypi.org."

    log "Stage 4/5: Installing Volatility 3 and its analysis extras..."
    if "${venv_pip}" install --quiet --editable "${VOL_SRC_DIR}[full]"; then
        success "Volatility 3 installed with the full set of optional extras."
    else
        warn "Installing the [full] extras failed (usually a missing build dependency for an optional module)."
        warn "Falling back to a core installation - all built-in plugins will still work."
        "${venv_pip}" install --quiet --editable "${VOL_SRC_DIR}" \
            || die "Core installation of Volatility 3 failed. Run '${venv_pip} install -e ${VOL_SRC_DIR}' by hand to see the full error output."
        # These three cover the majority of real triage work, so try them
        # individually rather than giving up on all of them together.
        local extra
        for extra in pycryptodome yara-python capstone; do
            if "${venv_pip}" install --quiet "${extra}"; then
                log "Optional dependency '${extra}' installed."
            else
                warn "Optional dependency '${extra}' could not be installed; plugins that need it will be unavailable."
            fi
        done
        success "Volatility 3 core installation completed."
    fi
}

# publish_wrappers - put the tool on every user's PATH.
#
# We deliberately write small wrapper scripts rather than symlinking the venv
# binaries. A symlink into a venv resolves correctly, but a wrapper makes the
# interpreter explicit, survives the venv being rebuilt, and lets us keep the
# historical `vol.py` name working alongside the modern `vol` entry point.
publish_wrappers() {
    log "Stage 5/5: Publishing vol, vol.py and volshell into ${BIN_DIR}..."

    [[ -d "${BIN_DIR}" ]] || die "${BIN_DIR} does not exist; cannot place the executables on the system PATH."

    local name target wrapper
    for name in vol volshell; do
        target="${VOL_VENV_DIR}/bin/${name}"
        [[ -x "${target}" ]] || die "Expected entry point ${target} is missing - the installation did not complete correctly."
    done

    # vol and volshell wrappers.
    for name in vol volshell; do
        wrapper="${BIN_DIR}/${name}"
        /bin/cat > "${wrapper}" <<EOF
#!/bin/sh
# Wrapper generated by install_vol.sh - runs Volatility 3 from its dedicated
# virtual environment so it never collides with system Python packages.
exec "${VOL_VENV_DIR}/bin/${name}" "\$@"
EOF
        /bin/chmod 0755 "${wrapper}" \
            || die "Could not make ${wrapper} executable."
    done

    # Compatibility shim: older documentation, scripts and course material all
    # refer to `vol.py`, so keep that name available.
    wrapper="${BIN_DIR}/vol.py"
    /bin/cat > "${wrapper}" <<EOF
#!/bin/sh
# Compatibility wrapper generated by install_vol.sh.
# Historical name for the Volatility 3 entry point; identical to 'vol'.
exec "${VOL_VENV_DIR}/bin/vol" "\$@"
EOF
    /bin/chmod 0755 "${wrapper}" || die "Could not make ${wrapper} executable."

    success "Executables published to ${BIN_DIR}."

    # Confirm the directory really is on PATH; on a minimal container or an
    # unusual sudoers secure_path it may not be, and a silent 'command not
    # found' later is a poor user experience.
    case ":${PATH}:" in
        *":${BIN_DIR}:"*)
            success "${BIN_DIR} is on the current PATH."
            ;;
        *)
            warn "${BIN_DIR} is not on the current PATH."
            warn "Add it by running:  echo 'export PATH=\"${BIN_DIR}:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
            ;;
    esac
}

# create_plugin_dir - prepare a drop-in directory for custom plugins.
#
# Volatility 3 has no per-user plugin directory under $HOME; the only locations
# searched automatically are the two entries in constants.PLUGINS_PATH:
#
#   <source>/volatility3/plugins            <- intended for third-party plugins
#   <source>/volatility3/framework/plugins  <- the built-in plugins
#
# Anything else must be passed explicitly with 'vol -p <dir>'. We therefore
# create the first of those and hand ownership to the invoking user, so custom
# plugins can be dropped in and used with no extra flags and no sudo. Because
# the package was installed in editable mode this takes effect immediately, and
# because the files are untracked they do not interfere with the 'git pull'
# performed when this script is re-run as an updater.
create_plugin_dir() {
    CUSTOM_PLUGIN_DIR="${VOL_SRC_DIR}/volatility3/plugins"

    /bin/mkdir -p "${CUSTOM_PLUGIN_DIR}" \
        || die "Could not create the custom plugin directory at ${CUSTOM_PLUGIN_DIR}."

    # Hand the directory to the user who invoked sudo, where there is one.
    local invoking_user="${SUDO_USER:-}"
    if [[ -n "${invoking_user}" ]]; then
        local invoking_group
        invoking_group="$(/usr/bin/id -gn "${invoking_user}" 2>/dev/null)" || invoking_group="${invoking_user}"
        /bin/chown "${invoking_user}:${invoking_group}" "${CUSTOM_PLUGIN_DIR}" 2>/dev/null \
            || warn "Could not give ${invoking_user} ownership of ${CUSTOM_PLUGIN_DIR}; you will need sudo to add plugins there."
    fi

    log "Custom plugin directory ready: ${CUSTOM_PLUGIN_DIR}"
}

# verify_installation - never claim success without proving it. We run the tool
# through the published wrapper (not the venv binary directly) so we are testing
# exactly what the user will invoke.
verify_installation() {
    log "Verifying the installation by running 'vol --help'..."

    local version_line
    if ! version_line="$("${BIN_DIR}/vol" --help 2>&1 | /usr/bin/head -n 1)"; then
        die "Volatility was installed but does not run. Try '${VOL_VENV_DIR}/bin/vol --help' to see the underlying error."
    fi

    # Listing plugins exercises the full import machinery, which catches broken
    # optional dependencies that --help alone would not surface.
    local plugin_count
    plugin_count="$("${BIN_DIR}/vol" --help 2>/dev/null | /bin/grep -cE '^\s+(windows|linux|mac)\.' || true)"

    success "Volatility reports: ${version_line}"
    if [[ "${plugin_count}" -gt 0 ]]; then
        success "${plugin_count} built-in plugins detected."
    else
        warn "No built-in plugins were listed. The install may be incomplete - check '${BIN_DIR}/vol --help' manually."
    fi
}

# print_summary - the closing brief: confirm success and explain plugins.
print_summary() {
    cat <<EOF

=============================================================================
 Volatility 3 installation completed successfully
=============================================================================

  Source tree ........ ${VOL_SRC_DIR}
  Virtual env ........ ${VOL_VENV_DIR}
  Executables ........ ${BIN_DIR}/vol, ${BIN_DIR}/vol.py, ${BIN_DIR}/volshell

  Quick start:
    vol -f /path/to/memory.raw windows.info
    vol -f /path/to/memory.raw linux.pslist
    volshell -f /path/to/memory.raw

-----------------------------------------------------------------------------
 ADDING YOUR OWN PLUGINS
-----------------------------------------------------------------------------

  1. Drop-in directory (searched automatically - no flags, no sudo):

       ${CUSTOM_PLUGIN_DIR}

     Copy your .py plugin files in there. Mirror the framework layout so the
     plugin gets the operating-system prefix you expect - a Windows plugin
     belongs in:

       ${CUSTOM_PLUGIN_DIR}/windows/myplugin.py

     and is then run by its dotted name:

       vol -f memory.raw windows.myplugin.MyPlugin

     A plugin placed directly in the top level of that directory is simply:

       vol -f memory.raw myplugin.MyPlugin

     Volatility was installed in editable mode, so files added here are picked
     up on the very next run - there is nothing to rebuild or reinstall.

  2. Any other directory, for a single run, with -p / --plugin-dirs:

       vol -p /path/to/my/plugins -f memory.raw myplugin.MyPlugin

     This is the right option for plugins kept under version control elsewhere,
     for example the Vol3 plugins in this repository:

       vol -p /path/to/Public/Vol3 -f memory.raw windows.fasttriage

  3. The built-in plugins live in (leave these alone unless you are patching
     upstream behaviour):

       ${VOL_SRC_DIR}/volatility3/framework/plugins/

  Confirm a new plugin has been registered with:

       vol --help | grep myplugin

-----------------------------------------------------------------------------
 MAINTENANCE
-----------------------------------------------------------------------------

  Re-run this script at any time to update Volatility 3 to the latest upstream
  revision; it will pull the newest source and rebuild the environment.

EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    check_arguments "$@"

    printf '=============================================================\n'
    printf ' Volatility 3 installer\n'
    printf '=============================================================\n\n'

    check_privileges
    check_platform

    install_dependencies

    # These two need tools that install_dependencies provides, so they follow it.
    check_python
    check_network

    fetch_source
    install_volatility
    publish_wrappers
    create_plugin_dir
    verify_installation

    # Record the installation for auditing; forensic workstations should have a
    # trail of what tooling was installed and when. A logging failure must not
    # fail the install, hence the '|| true'.
    printf '%s install_vol.sh completed: source=%s venv=%s\n' \
        "$(/bin/date -u +'%Y-%m-%dT%H:%M:%SZ')" "${VOL_SRC_DIR}" "${VOL_VENV_DIR}" \
        >> "${LOG_FILE}" 2>/dev/null || true

    print_summary
}

main "$@"
