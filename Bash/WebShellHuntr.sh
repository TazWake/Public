#!/usr/bin/env bash

# WebShellHuntr - read-only web-shell hunting for Linux live systems and
# mounted/captured Linux evidence. This is original Bash code inspired by the
# detection goals of BackdoorMan (filename, source-code and obfuscation checks),
# expanded for modern, multi-language Linux web estates.
#
# Public defensive references:
#   https://github.com/cys3c/BackdoorMan
#   https://github.com/nsacyber/Mitigating-Web-Shells
#   https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/
#       CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF
#   https://www.microsoft.com/en-us/security/blog/2026/04/02/
#       cookie-controlled-php-webshells-tradecraft-linux-hosting-environments/
#
# The script deliberately uses "set -uo pipefail" rather than errexit. A hunt
# should continue when an individual file becomes unreadable or a volatile
# process exits; material errors are counted and reported.
set -uo pipefail

readonly PROGRAM_NAME="WebShellHuntr"
readonly VERSION="1.0.0"
readonly EXIT_CLEAN=0
readonly EXIT_FINDINGS=1
readonly EXIT_ERROR=2
readonly EXIT_INTERRUPTED=130

export LC_ALL=C
umask 077

TARGET_ROOT_INPUT="/"
TARGET_ROOT=""
OUTPUT_DIR_INPUT=""
OUTPUT_DIR=""
KNOWN_GOOD_INPUT=""
KNOWN_GOOD_ROOT=""
HASH_LIST_INPUT=""
HASH_LIST=""
YARA_RULES_INPUT=""
YARA_RULES=""
CASE_REFERENCE="Not supplied"
EXAMINER="Not supplied"
SOURCE_IDENTIFIER="Not supplied"
MAX_FILE_MIB=8
MAX_FILE_BYTES=8388608
MAX_FILES=100000
MAX_LOG_MIB=100
MAX_LOG_BYTES=104857600
MAX_LOGS=100
RECENT_DAYS=0
CROSS_FILESYSTEMS=0
ANALYSE_LOGS=1
ANALYSE_PROCESSES=1
ANALYSE_PERSISTENCE=1
USE_CLAMAV=0
COLOUR=1
VERBOSE=0

declare -a REQUESTED_PATHS=()
declare -a REQUESTED_EXCLUDES=()
declare -a SCAN_ROOTS=()
declare -a EXCLUDE_PATHS=()
declare -A SEEN_SCAN_ROOTS=()
declare -A SEEN_SERVER_EVIDENCE=()
declare -A SEEN_FINDINGS=()
declare -A SEEN_FILES=()
declare -A SEEN_FS_WARNINGS=()
declare -A IOC_HASHES=()

FILES_VISITED=0
FILES_SCANNED=0
FILES_SKIPPED=0
FINDINGS_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
ERROR_COUNT=0
LIMIT_REACHED=0
YARA_ERROR_REPORTED=0
CLAMAV_ERROR_REPORTED=0
RUN_STARTED_EPOCH=0
RUN_STARTED_UTC=""
RUN_FINISHED_UTC=""

CURRENT_FILE=""
CURRENT_PATH=""
CURRENT_KIND=""
CURRENT_HASH=""
CURRENT_SIZE=""
CURRENT_UID=""
CURRENT_GID=""
CURRENT_MODE=""
CURRENT_MTIME=""
CURRENT_CTIME=""
CURRENT_ATIME=""
CURRENT_INODE=""
CURRENT_DEVICE=""

LOG_FILE=""
FINDINGS_FILE=""
INVENTORY_FILE=""
ROOTS_FILE=""
SERVERS_FILE=""
WEB_LOG_LEADS_FILE=""
MANIFEST_FILE=""
SUMMARY_FILE=""

FIND=""
GREP=""
AWK=""
SED=""
STAT=""
SHA256SUM=""
SORT=""
READLINK=""
DATE=""
HOSTNAME=""
ID=""
UNAME=""
TR=""
PS=""
YARA=""
CLAMSCAN=""
MKDIR=""
RM=""
CHMOD=""

RED=""
YELLOW=""
BLUE=""
CYAN=""
GREEN=""
RESET=""

show_help() {
    cat <<'EOF'
WebShellHuntr 1.0.0 - hunt for web shells on Linux systems and evidence

USE
    sudo ./WebShellHuntr.sh [OPTIONS]

TARGET SELECTION
    -r, --root DIRECTORY       Root of the system to examine (default: /).
                               Use / for a live host, or the read-only mount point
                               of a raw image/extracted Linux filesystem.
    -p, --path PATH            Web content path to scan. Repeatable. Paths are
                               relative to --root; /var/www means TARGET/var/www.
                               If omitted, paths are discovered from web-server
                               configuration and common deployment locations.
    -x, --exclude PATH         Exclude a target-root-relative path. Repeatable.
    --cross-filesystems        Permit traversal into filesystems below a scan root.
                               The default uses find -xdev.

OUTPUT AND CASE DETAILS
    -o, --output DIRECTORY     New output directory. Default:
                               ./webshellhuntr_HOST_UTC/
    --case REFERENCE           Case or incident reference for the audit record.
    --examiner NAME            Examiner/operator name for the audit record.
    --source-id IDENTIFIER     Evidence or host identifier.
    --no-colour, --no-color    Disable terminal colours.
    -v, --verbose              Show extra progress information.

HUNT OPTIONS
    --known-good DIRECTORY     Known-good mirror of --root. Candidate files are
                               compared by target-relative path and SHA-256.
    --hash-list FILE           Local IOC file containing one SHA-256 per line;
                               optional text after the hash is retained as a label.
    --since DAYS               Flag executable web files modified within DAYS.
                               Disabled by default because deployments create noise.
    --max-size MIB             Largest content file to inspect (default: 8 MiB).
    --max-files COUNT          Stop after visiting COUNT files (default: 100000).
    --no-log-analysis          Do not inspect uncompressed Apache/nginx/Caddy/
                               hosting-panel access logs for command-like requests.
    --max-log-size MIB         Largest access log to inspect (default: 100 MiB).
    --max-logs COUNT           Maximum access logs to inspect (default: 100).
    --no-process-analysis      Do not inspect live process ancestry.
    --no-persistence-analysis  Do not inspect cron content for web-file recreation.
    --yara-rules FILE          Run locally installed yara against candidates using
                               this local rule file.
    --clamav                   Run locally installed clamscan against candidates.
    -h, --help                 Show these full instructions and exit.
    -V, --version              Show the version and exit.

DISCOVERY AND COVERAGE
    Configuration and standard layouts are checked for Apache (including RHEL
    httpd), nginx/OpenResty, Lighttpd, Caddy, OpenLiteSpeed, Tomcat, Jetty,
    JBoss/WildFly, GlassFish/Payara, XAMPP, cPanel, Plesk and DirectAdmin.
    Rules cover PHP/PHTML, JSP/JSPX, ASP/ASPX/ASHX, ColdFusion, CGI, Perl,
    Python, Ruby, server-side JavaScript and common server configuration files.
    Files with non-script extensions are also probed for embedded server-side
    code, so image or document masquerading can be reported.

EVIDENCE PRACTICE
    * The target is read only from this tool's perspective. No quarantine,
      deletion, decoding, execution or external upload is performed.
    * Mount forensic images read-only and place --output outside the mount.
      WebShellHuntr refuses to put output inside a non-live target or baseline.
    * Reading may update access times on a writable live filesystem. Capture or
      mount evidence appropriately if access-time preservation is required.
    * Pre-read metadata and SHA-256 hashes are recorded for every candidate.
      Reports receive a final SHA-256 manifest. Findings are investigative leads,
      not proof of compromise; validate provenance and known-good state.

OUTPUTS
    WebShellHuntr.log       Timestamped action/audit log
    findings.tsv            Normalised findings with rule, metadata and SHA-256
    inventory.tsv           Candidate-file inventory and pre-read metadata
    scan_roots.txt          Web content roots examined
    servers.tsv             Server/configuration discovery evidence
    web_log_leads.tsv       Suspicious access-log lines (when enabled)
    summary.txt             Counts, scope and completion state
    SHA256SUMS              SHA-256 manifest for all final report artefacts

EXAMPLES
    sudo ./WebShellHuntr.sh --case IR-2026-041 --source-id web01
    sudo ./WebShellHuntr.sh -r /mnt/case/rootfs -o /cases/IR-041/web01 \
        --case IR-2026-041 --examiner "A Analyst"
    sudo ./WebShellHuntr.sh -r /mnt/evidence -p /srv/site -p /opt/app/webapps \
        --known-good /mnt/baselines/web01 -o /cases/web01_hunt
    sudo ./WebShellHuntr.sh -p /var/www --since 14 --hash-list known_hashes.txt

EXIT STATUS
    0  Hunt completed with no findings.
    1  Hunt completed and one or more findings were recorded.
    2  Invalid use, unmet dependency, unsafe path, or incomplete hunt.
    130 Interrupted by the operator or a termination signal.

Root privileges are required for both live and evidence-root hunts so that
ownership, protected files, logs and process information can be examined
consistently. Help and version output do not require root.
EOF
}

show_version() {
    printf '%s %s\n' "$PROGRAM_NAME" "$VERSION"
}

die_early() {
    printf 'ERROR: %s\n' "$1" >&2
    exit "$EXIT_ERROR"
}

is_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

parse_arguments() {
    while (($# > 0)); do
        case "$1" in
            -h|--help)
                show_help
                exit "$EXIT_CLEAN"
                ;;
            -V|--version)
                show_version
                exit "$EXIT_CLEAN"
                ;;
            -r|--root|-p|--path|-x|--exclude|-o|--output|--case|--examiner|--source-id|--known-good|--hash-list|--since|--max-size|--max-files|--max-log-size|--max-logs|--yara-rules)
                (($# >= 2)) || die_early "Option '$1' requires a value."
                case "$1" in
                    -r|--root) TARGET_ROOT_INPUT="$2" ;;
                    -p|--path) REQUESTED_PATHS+=("$2") ;;
                    -x|--exclude) REQUESTED_EXCLUDES+=("$2") ;;
                    -o|--output) OUTPUT_DIR_INPUT="$2" ;;
                    --case) CASE_REFERENCE="$2" ;;
                    --examiner) EXAMINER="$2" ;;
                    --source-id) SOURCE_IDENTIFIER="$2" ;;
                    --known-good) KNOWN_GOOD_INPUT="$2" ;;
                    --hash-list) HASH_LIST_INPUT="$2" ;;
                    --since) RECENT_DAYS="$2" ;;
                    --max-size) MAX_FILE_MIB="$2" ;;
                    --max-files) MAX_FILES="$2" ;;
                    --max-log-size) MAX_LOG_MIB="$2" ;;
                    --max-logs) MAX_LOGS="$2" ;;
                    --yara-rules) YARA_RULES_INPUT="$2" ;;
                esac
                shift 2
                ;;
            --cross-filesystems) CROSS_FILESYSTEMS=1; shift ;;
            --no-log-analysis) ANALYSE_LOGS=0; shift ;;
            --no-process-analysis) ANALYSE_PROCESSES=0; shift ;;
            --no-persistence-analysis) ANALYSE_PERSISTENCE=0; shift ;;
            --clamav) USE_CLAMAV=1; shift ;;
            --no-colour|--no-color) COLOUR=0; shift ;;
            -v|--verbose) VERBOSE=1; shift ;;
            --) shift; (($# == 0)) || die_early "Unexpected positional argument: '$1'." ;;
            -*) die_early "Unknown option '$1'. Use --help for full instructions." ;;
            *) die_early "Unexpected positional argument '$1'. Use --path to select content." ;;
        esac
    done

    is_positive_integer "$MAX_FILE_MIB" || die_early "--max-size must be a positive whole number."
    is_positive_integer "$MAX_FILES" || die_early "--max-files must be a positive whole number."
    is_positive_integer "$MAX_LOG_MIB" || die_early "--max-log-size must be a positive whole number."
    is_positive_integer "$MAX_LOGS" || die_early "--max-logs must be a positive whole number."
    if [[ "$RECENT_DAYS" != "0" ]] && ! is_positive_integer "$RECENT_DAYS"; then
        die_early "--since must be a positive whole number of days."
    fi
    MAX_FILE_BYTES=$((MAX_FILE_MIB * 1024 * 1024))
    MAX_LOG_BYTES=$((MAX_LOG_MIB * 1024 * 1024))
}

resolve_command() {
    local variable_name="$1"
    local command_name="$2"
    local required="${3:-1}"
    local resolved=""
    resolved=$(command -v -- "$command_name" 2>/dev/null || true)
    if [[ -z "$resolved" ]]; then
        if ((required)); then
            die_early "Required command '$command_name' is not installed or not in PATH."
        fi
        return 1
    fi
    printf -v "$variable_name" '%s' "$resolved"
}

resolve_commands() {
    resolve_command FIND find
    resolve_command GREP grep
    resolve_command AWK awk
    resolve_command SED sed
    resolve_command STAT stat
    resolve_command SHA256SUM sha256sum
    resolve_command SORT sort
    resolve_command READLINK readlink
    resolve_command DATE date
    resolve_command HOSTNAME hostname
    resolve_command ID id
    resolve_command UNAME uname
    resolve_command TR tr
    resolve_command MKDIR mkdir
    resolve_command RM rm
    resolve_command CHMOD chmod
    resolve_command PS ps 0 || true
    resolve_command YARA yara 0 || true
    resolve_command CLAMSCAN clamscan 0 || true
}

initialise_colours() {
    if ((COLOUR)) && [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
        RED=$'\033[0;31m'
        YELLOW=$'\033[1;33m'
        BLUE=$'\033[0;34m'
        CYAN=$'\033[0;36m'
        GREEN=$'\033[0;32m'
        RESET=$'\033[0m'
    fi
}

utc_now() {
    "$DATE" -u '+%Y-%m-%dT%H:%M:%SZ'
}

log_line() {
    local level="$1"
    shift
    local message="$*"
    local colour="$BLUE"
    case "$level" in
        FINDING|ERROR) colour="$RED" ;;
        WARNING) colour="$YELLOW" ;;
        COMPLETE) colour="$GREEN" ;;
        SECTION) colour="$CYAN" ;;
    esac
    printf '%b[%s] %s%b\n' "$colour" "$level" "$message" "$RESET"
    if [[ -n "$LOG_FILE" ]]; then
        printf '[%s] [%s] %s\n' "$(utc_now)" "$level" "$message" >> "$LOG_FILE"
    fi
}

log_info() { log_line INFO "$*"; }
log_warning() { log_line WARNING "$*"; }
log_error() { ((ERROR_COUNT += 1)); log_line ERROR "$*"; }
log_verbose() { ((VERBOSE)) && log_line DETAIL "$*" || true; }
log_section() { log_line SECTION "--- $* ---"; }

sanitise_tsv() {
    local value="$1"
    value=${value//$'\t'/\\t}
    value=${value//$'\r'/\\r}
    value=${value//$'\n'/\\n}
    printf '%s' "$value"
}

format_invocation() {
    local output="" argument="" quoted=""
    printf -v output '%q' "$0"
    for argument in "$@"; do
        printf -v quoted '%q' "$argument"
        output+=" $quoted"
    done
    printf '%s' "$output"
}

canonical_existing_directory() {
    local directory="$1"
    [[ -d "$directory" ]] || return 1
    "$READLINK" -f -- "$directory" 2>/dev/null
}

canonical_future_path() {
    local requested_path="$1"
    local lexical=""
    lexical=$("$READLINK" -m -- "$requested_path" 2>/dev/null || true)
    [[ -n "$lexical" ]] || return 1
    local existing="$lexical"
    local suffix=""
    local component=""
    while [[ ! -e "$existing" ]]; do
        [[ "$existing" != "/" ]] || return 1
        component=${existing##*/}
        suffix="/$component$suffix"
        existing=${existing%/*}
        [[ -n "$existing" ]] || existing="/"
    done
    [[ -d "$existing" ]] || return 1
    existing=$("$READLINK" -f -- "$existing" 2>/dev/null || true)
    [[ -n "$existing" ]] || return 1
    if [[ "$existing" == "/" ]]; then printf '/%s\n' "${suffix#/}"; else printf '%s%s\n' "$existing" "$suffix"; fi
}

path_is_within() {
    local child="$1"
    local parent="$2"
    [[ "$parent" == "/" || "$child" == "$parent" || "$child" == "$parent/"* ]]
}

resolve_target_path() {
    local target_path="$1"
    local candidate=""
    if [[ "$TARGET_ROOT" == "/" ]]; then
        if [[ "$target_path" == /* ]]; then
            candidate="$target_path"
        else
            candidate="/$target_path"
        fi
    else
        candidate="$TARGET_ROOT/${target_path#/}"
    fi
    local resolved=""
    resolved=$(canonical_existing_directory "$candidate" || true)
    [[ -n "$resolved" ]] || return 1
    path_is_within "$resolved" "$TARGET_ROOT" || return 1
    printf '%s\n' "$resolved"
}

target_display_path() {
    local actual_path="$1"
    if [[ "$TARGET_ROOT" == "/" ]]; then
        printf '%s' "$actual_path"
    elif [[ "$actual_path" == "$TARGET_ROOT" ]]; then
        printf '/'
    else
        printf '%s' "${actual_path#"$TARGET_ROOT"}"
    fi
}

prepare_paths() {
    TARGET_ROOT=$(canonical_existing_directory "$TARGET_ROOT_INPUT" || true)
    [[ -n "$TARGET_ROOT" ]] || die_early "Target root is not an accessible directory: '$TARGET_ROOT_INPUT'."

    if [[ -n "$KNOWN_GOOD_INPUT" ]]; then
        KNOWN_GOOD_ROOT=$(canonical_existing_directory "$KNOWN_GOOD_INPUT" || true)
        [[ -n "$KNOWN_GOOD_ROOT" ]] || die_early "Known-good root is not an accessible directory: '$KNOWN_GOOD_INPUT'."
    fi
    if [[ -n "$HASH_LIST_INPUT" ]]; then
        HASH_LIST=$("$READLINK" -f -- "$HASH_LIST_INPUT" 2>/dev/null || true)
        [[ -f "$HASH_LIST" && -r "$HASH_LIST" ]] || die_early "Hash list is not a readable file: '$HASH_LIST_INPUT'."
    fi
    if [[ -n "$YARA_RULES_INPUT" ]]; then
        YARA_RULES=$("$READLINK" -f -- "$YARA_RULES_INPUT" 2>/dev/null || true)
        [[ -f "$YARA_RULES" && -r "$YARA_RULES" ]] || die_early "YARA rules must be a readable file: '$YARA_RULES_INPUT'."
        [[ -n "$YARA" ]] || die_early "--yara-rules was requested but yara is not installed."
    fi
    if ((USE_CLAMAV)) && [[ -z "$CLAMSCAN" ]]; then
        die_early "--clamav was requested but clamscan is not installed."
    fi

    local host_name=""
    host_name=$("$HOSTNAME" -s 2>/dev/null || printf 'unknown-host')
    host_name=${host_name//[^A-Za-z0-9._-]/_}
    local stamp=""
    stamp=$("$DATE" -u '+%Y%m%dT%H%M%SZ')
    [[ -n "$OUTPUT_DIR_INPUT" ]] || OUTPUT_DIR_INPUT="./webshellhuntr_${host_name}_${stamp}"

    local output_candidate=""
    output_candidate=$(canonical_future_path "$OUTPUT_DIR_INPUT" || true)
    [[ -n "$output_candidate" ]] || die_early "Unable to resolve output path '$OUTPUT_DIR_INPUT'."
    [[ ! -e "$output_candidate" ]] || die_early "Output path already exists; choose a new directory: '$output_candidate'."

    if [[ "$TARGET_ROOT" != "/" ]] && path_is_within "$output_candidate" "$TARGET_ROOT"; then
        die_early "Output must be outside the mounted/captured target root."
    fi
    if [[ -n "$KNOWN_GOOD_ROOT" ]] && path_is_within "$output_candidate" "$KNOWN_GOOD_ROOT"; then
        die_early "Output must be outside the known-good baseline."
    fi

    if ! "$MKDIR" -p -- "$output_candidate" 2>/dev/null; then
        die_early "Unable to create output directory '$output_candidate'."
    fi
    OUTPUT_DIR=$(canonical_existing_directory "$output_candidate" || true)
    [[ -n "$OUTPUT_DIR" ]] || die_early "Unable to resolve the new output directory."

    LOG_FILE="$OUTPUT_DIR/WebShellHuntr.log"
    FINDINGS_FILE="$OUTPUT_DIR/findings.tsv"
    INVENTORY_FILE="$OUTPUT_DIR/inventory.tsv"
    ROOTS_FILE="$OUTPUT_DIR/scan_roots.txt"
    SERVERS_FILE="$OUTPUT_DIR/servers.tsv"
    WEB_LOG_LEADS_FILE="$OUTPUT_DIR/web_log_leads.tsv"
    SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
    MANIFEST_FILE="$OUTPUT_DIR/SHA256SUMS"

    : > "$LOG_FILE"
    printf 'timestamp_utc\tseverity\trule_id\ttarget_path\tline\tsha256\tsize_bytes\tuid\tgid\tmode\tmtime_epoch\tctime_epoch\tdetail\n' > "$FINDINGS_FILE"
    printf 'target_path\tkind\tsha256\tsize_bytes\tuid\tgid\tmode\tatime_epoch\tmtime_epoch\tctime_epoch\tinode\tdevice\n' > "$INVENTORY_FILE"
    : > "$ROOTS_FILE"
    printf 'server\tevidence_type\ttarget_path\n' > "$SERVERS_FILE"
    printf 'source_log\tline\tsha256\texcerpt\n' > "$WEB_LOG_LEADS_FILE"
}

record_server_evidence() {
    local server="$1"
    local evidence_type="$2"
    local path="$3"
    local key="$server|$evidence_type|$path"
    [[ -z "${SEEN_SERVER_EVIDENCE[$key]+x}" ]] || return 0
    SEEN_SERVER_EVIDENCE["$key"]=1
    printf '%s\t%s\t%s\n' "$(sanitise_tsv "$server")" "$(sanitise_tsv "$evidence_type")" "$(sanitise_tsv "$path")" >> "$SERVERS_FILE"
}

add_scan_root_actual() {
    local candidate="$1"
    local source="$2"
    local resolved=""
    resolved=$(canonical_existing_directory "$candidate" || true)
    if [[ -z "$resolved" ]]; then
        log_verbose "Ignoring absent web root candidate: $candidate"
        return 0
    fi
    if ! path_is_within "$resolved" "$TARGET_ROOT"; then
        log_warning "Skipping web root that resolves outside the target: $candidate -> $resolved"
        return 0
    fi
    [[ -z "${SEEN_SCAN_ROOTS[$resolved]+x}" ]] || return 0
    SEEN_SCAN_ROOTS["$resolved"]=1
    SCAN_ROOTS+=("$resolved")
    local display=""
    display=$(target_display_path "$resolved")
    printf '%s\t%s\n' "$display" "$source" >> "$ROOTS_FILE"
    record_server_evidence "$source" "web_root" "$display"
    log_info "Selected web root $display ($source)."
}

add_scan_root_target_path() {
    local target_path="$1"
    local source="$2"
    local resolved=""
    resolved=$(resolve_target_path "$target_path" || true)
    if [[ -z "$resolved" ]]; then
        log_verbose "Target path is absent or unsafe: $target_path"
        return 0
    fi
    add_scan_root_actual "$resolved" "$source"
}

clean_config_value() {
    local value="$1"
    value=${value%;}
    value=${value#\"}; value=${value%\"}
    value=${value#\'}; value=${value%\'}
    value=${value#\(}; value=${value%\)}
    printf '%s' "$value"
}

parse_web_config() {
    local file="$1"
    local server="$2"
    local display=""
    display=$(target_display_path "$file")
    record_server_evidence "$server" "configuration" "$display"

    local raw_line="" line="" directive="" value="" lowered=""
    local -a fields=()
    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        line=${raw_line%%#*}
        line=${line//$'\r'/}
        read -r -a fields <<< "$line"
        ((${#fields[@]} >= 2)) || continue
        directive=${fields[0]}
        lowered=$(printf '%s' "$directive" | "$TR" '[:upper:]' '[:lower:]')
        value=""
        case "$server:$lowered" in
            Apache:documentroot)
                value=${fields[1]}
                ;;
            Apache:scriptalias|Apache:alias)
                ((${#fields[@]} >= 3)) && value=${fields[2]}
                ;;
            nginx:root|nginx:alias)
                value=${fields[1]}
                ;;
            Lighttpd:server.document-root)
                ((${#fields[@]} >= 3)) && value=${fields[2]}
                ;;
            Caddy:root)
                if ((${#fields[@]} >= 3)) && [[ "${fields[1]}" == "*" ]]; then value=${fields[2]}; else value=${fields[1]}; fi
                ;;
            OpenLiteSpeed:docroot|OpenLiteSpeed:vhroot)
                value=${fields[1]}
                ;;
        esac
        [[ -n "$value" ]] || continue
        value=$(clean_config_value "$value")
        [[ "$value" == /* && "$value" != *'$'* && "$value" != *'{'* ]] || continue
        add_scan_root_target_path "$value" "$server configuration"
    done < "$file"
}

scan_config_tree() {
    local target_path="$1"
    local server="$2"
    local base=""
    base=$(resolve_target_path "$target_path" || true)
    [[ -n "$base" ]] || return 0
    local list_file="$OUTPUT_DIR/.config_files_$RANDOM.nul"
    if ! "$FIND" -P "$base" -xdev -type f \( -name '*.conf' -o -name 'Caddyfile' -o -name 'httpd_config.xml' \) -print0 > "$list_file" 2>> "$LOG_FILE"; then
        log_warning "Some $server configuration files could not be enumerated."
    fi
    local config_file=""
    while IFS= read -r -d '' config_file; do
        parse_web_config "$config_file" "$server"
    done < "$list_file"
    "$RM" -f -- "$list_file"
}

discover_web_roots() {
    log_section "Discovering web servers and content roots"

    scan_config_tree /etc/apache2 Apache
    scan_config_tree /etc/httpd Apache
    scan_config_tree /usr/local/apache2/conf Apache
    scan_config_tree /etc/nginx nginx
    scan_config_tree /usr/local/nginx/conf nginx
    scan_config_tree /usr/local/openresty/nginx/conf nginx
    scan_config_tree /etc/lighttpd Lighttpd
    scan_config_tree /etc/caddy Caddy
    scan_config_tree /usr/local/lsws/conf OpenLiteSpeed

    local pair="" path="" label=""
    local -a standard_roots=(
        "/var/www/html|Apache/httpd default"
        "/var/www|Apache/httpd"
        "/srv/www|Apache/nginx"
        "/srv/http|Apache/nginx"
        "/usr/share/nginx/html|nginx default"
        "/usr/local/nginx/html|nginx"
        "/usr/local/openresty/nginx/html|OpenResty"
        "/usr/local/www|BSD-style deployment"
        "/usr/local/lsws/Example/html|OpenLiteSpeed"
        "/opt/lampp/htdocs|XAMPP"
        "/var/lib/jetty/webapps|Jetty"
        "/var/lib/jetty9/webapps|Jetty"
        "/var/lib/jetty10/webapps|Jetty"
        "/var/lib/jetty11/webapps|Jetty"
        "/opt/wildfly/standalone/deployments|WildFly"
        "/opt/jboss/standalone/deployments|JBoss"
        "/opt/glassfish/glassfish/domains|GlassFish"
        "/opt/payara/glassfish/domains|Payara"
    )
    for pair in "${standard_roots[@]}"; do
        path=${pair%%|*}; label=${pair#*|}
        add_scan_root_target_path "$path" "$label"
    done

    local glob_path=""
    shopt -s nullglob
    local -a glob_roots=(
        "$TARGET_ROOT"/var/lib/tomcat*/webapps
        "$TARGET_ROOT"/usr/share/tomcat*/webapps
        "$TARGET_ROOT"/opt/tomcat*/webapps
        "$TARGET_ROOT"/opt/jetty*/webapps
        "$TARGET_ROOT"/opt/wildfly*/standalone/deployments
        "$TARGET_ROOT"/opt/jboss*/standalone/deployments
        "$TARGET_ROOT"/home/*/public_html
        "$TARGET_ROOT"/home/*/domains/*/public_html
        "$TARGET_ROOT"/var/www/vhosts/*/httpdocs
    )
    for glob_path in "${glob_roots[@]}"; do
        case "$glob_path" in
            */tomcat*/webapps) label="Tomcat" ;;
            */jetty*/webapps) label="Jetty" ;;
            */wildfly*/standalone/deployments) label="WildFly" ;;
            */jboss*/standalone/deployments) label="JBoss" ;;
            */public_html) label="cPanel/DirectAdmin hosting" ;;
            */httpdocs) label="Plesk hosting" ;;
            *) label="common deployment" ;;
        esac
        add_scan_root_actual "$glob_path" "$label"
    done
    shopt -u nullglob

    if [[ "$TARGET_ROOT" == "/" && -n "$PS" ]]; then
        local process_line=""
        while IFS= read -r process_line; do
            [[ -n "$process_line" ]] || continue
            record_server_evidence "live process" "process" "$(sanitise_tsv "$process_line")"
        done < <("$PS" -eo comm=,args= 2>/dev/null | "$GREP" -Ei '(^|/)(apache2|httpd|nginx|openresty|lighttpd|caddy|lshttpd|tomcat|jetty|wildfly|jboss|glassfish|payara|php-fpm|gunicorn|uwsgi)([[:space:]]|$)' | "$AWK" '!seen[$0]++' || true)
    fi
}

prepare_requested_scope() {
    local requested="" resolved=""
    # Never allow report files or a baseline stored on the live root to enter
    # the evidence population being examined.
    EXCLUDE_PATHS+=("$OUTPUT_DIR")
    if [[ -n "$KNOWN_GOOD_ROOT" ]] && path_is_within "$KNOWN_GOOD_ROOT" "$TARGET_ROOT"; then
        EXCLUDE_PATHS+=("$KNOWN_GOOD_ROOT")
    fi
    if ((${#REQUESTED_PATHS[@]} > 0)); then
        for requested in "${REQUESTED_PATHS[@]}"; do
            resolved=$(resolve_target_path "$requested" || true)
            [[ -n "$resolved" ]] || die_early "Requested scan path is absent or resolves outside the target: '$requested'."
            add_scan_root_actual "$resolved" "operator supplied"
        done
    else
        discover_web_roots
    fi

    if ((${#SCAN_ROOTS[@]} == 0)); then
        if [[ "$TARGET_ROOT" != "/" ]]; then
            log_warning "No web root was discovered; treating the supplied evidence root as captured web content."
            add_scan_root_actual "$TARGET_ROOT" "captured-content fallback"
        else
            die_early "No web root was discovered. Supply at least one --path."
        fi
    fi

    for requested in "${REQUESTED_EXCLUDES[@]}"; do
        resolved=$(resolve_target_path "$requested" || true)
        [[ -n "$resolved" ]] || die_early "Excluded path is absent or unsafe: '$requested'."
        EXCLUDE_PATHS+=("$resolved")
        log_info "Excluding $(target_display_path "$resolved")."
    done
}

load_hash_list() {
    [[ -n "$HASH_LIST" ]] || return 0
    log_info "Loading local SHA-256 indicators from $HASH_LIST."
    local line="" hash="" label=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line//$'\r'/}
        [[ -n "$line" && "$line" != '#'* ]] || continue
        hash=${line%%[[:space:]]*}
        label=${line#"$hash"}
        label=${label#${label%%[![:space:]]*}}
        hash=$(printf '%s' "$hash" | "$TR" '[:upper:]' '[:lower:]')
        if [[ "$hash" =~ ^[0-9a-f]{64}$ ]]; then
            IOC_HASHES["$hash"]="${label:-local hash-list match}"
        else
            log_warning "Ignoring malformed hash-list entry: $(sanitise_tsv "$line")"
        fi
    done < "$HASH_LIST"
    log_info "Loaded ${#IOC_HASHES[@]} valid SHA-256 indicator(s)."
}

should_exclude() {
    local file="$1"
    local excluded=""
    for excluded in "${EXCLUDE_PATHS[@]}"; do
        if path_is_within "$file" "$excluded"; then return 0; fi
    done
    return 1
}

lowercase() {
    printf '%s' "$1" | "$TR" '[:upper:]' '[:lower:]'
}

looks_like_known_shell_name() {
    local name="$1"
    [[ "$name" =~ (^|[._-])(accept_language|azrailphp|b1n4ry|c99|c100|r57|wso|wsoshell|b374k|b374k2|weevely|webacoo|filesman|indishell|iranshell|ironshell|sqlshell|simshell|g6shell|g6sshell|gazashell|syrianshell|zehir4shell|zehirshell|commandshell|cwshell|kacak|locus7shell|lostdcshell|mailershell|saudishell|sosyeteshell|tryagshell|uploadshell|webadmin|up\.php|cmd)([._-]|$) ]]
}

has_script_extension() {
    local name="$1"
    case "$name" in
        *.php|*.php[3-8]|*.phtml|*.pht|*.phar|*.inc|*.module|*.jsp|*.jspx|*.jspf|*.asp|*.aspx|*.ashx|*.asmx|*.asax|*.cfm|*.cfc|*.cgi|*.pl|*.pm|*.py|*.pyw|*.rb|*.erb|*.js|*.mjs|*.cjs|*.lua|*.sh|*.shtml|*.stm) return 0 ;;
        *) return 1 ;;
    esac
}

has_deployment_extension() {
    case "$1" in *.war|*.jar) return 0 ;; *) return 1 ;; esac
}

file_contains() {
    local file="$1"
    local pattern="$2"
    "$GREP" -aEiqm1 -- "$pattern" "$file" 2>/dev/null
}

first_match_line() {
    local file="$1"
    local pattern="$2"
    local match=""
    match=$("$GREP" -aEinm1 -- "$pattern" "$file" 2>/dev/null || true)
    if [[ "$match" =~ ^([0-9]+): ]]; then printf '%s' "${BASH_REMATCH[1]}"; else printf '0'; fi
}

classify_candidate() {
    local file="$1"
    local base="${file##*/}"
    local name=""
    name=$(lowercase "$base")
    CURRENT_KIND=""
    if has_script_extension "$name"; then
        case "$name" in
            *.php|*.php[3-8]|*.phtml|*.pht|*.phar|*.inc|*.module) CURRENT_KIND="PHP" ;;
            *.jsp|*.jspx|*.jspf) CURRENT_KIND="JSP" ;;
            *.asp|*.aspx|*.ashx|*.asmx|*.asax) CURRENT_KIND="ASP.NET" ;;
            *.cfm|*.cfc) CURRENT_KIND="ColdFusion" ;;
            *.js|*.mjs|*.cjs) CURRENT_KIND="JavaScript" ;;
            *.py|*.pyw) CURRENT_KIND="Python" ;;
            *.pl|*.pm|*.cgi) CURRENT_KIND="CGI/Perl" ;;
            *.rb|*.erb) CURRENT_KIND="Ruby" ;;
            *) CURRENT_KIND="server-side script" ;;
        esac
        return 0
    fi
    if has_deployment_extension "$name"; then CURRENT_KIND="deployment archive"; return 0; fi
    case "$name" in
        .htaccess|.user.ini|web.config) CURRENT_KIND="web configuration"; return 0 ;;
    esac
    if looks_like_known_shell_name "$name"; then CURRENT_KIND="suspicious filename"; return 0; fi
    if file_contains "$file" '(<\?php|<%[@=]?|<cf(execute|script)|#!/(usr/)?bin/(env[[:space:]]+)?(python|perl|ruby|sh|bash))'; then
        CURRENT_KIND="embedded server-side code"
        return 0
    fi
    return 1
}

load_current_metadata() {
    local file="$1"
    local metadata=""
    metadata=$("$STAT" -c '%s|%u|%g|%a|%X|%Y|%Z|%i|%d' -- "$file" 2>/dev/null || true)
    [[ -n "$metadata" ]] || return 1
    IFS='|' read -r CURRENT_SIZE CURRENT_UID CURRENT_GID CURRENT_MODE CURRENT_ATIME CURRENT_MTIME CURRENT_CTIME CURRENT_INODE CURRENT_DEVICE <<< "$metadata"
    return 0
}

hash_current_file() {
    local result=""
    result=$("$SHA256SUM" -- "$CURRENT_FILE" 2>/dev/null || true)
    CURRENT_HASH=${result%%[[:space:]]*}
    [[ "$CURRENT_HASH" =~ ^[0-9a-fA-F]{64}$ ]]
}

write_inventory_row() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(sanitise_tsv "$CURRENT_PATH")" "$(sanitise_tsv "$CURRENT_KIND")" "$CURRENT_HASH" \
        "$CURRENT_SIZE" "$CURRENT_UID" "$CURRENT_GID" "$CURRENT_MODE" "$CURRENT_ATIME" \
        "$CURRENT_MTIME" "$CURRENT_CTIME" "$CURRENT_INODE" "$CURRENT_DEVICE" >> "$INVENTORY_FILE"
}

record_finding_values() {
    local severity="$1" rule_id="$2" path="$3" line="$4" hash="$5" size="$6"
    local uid="$7" gid="$8" mode="$9" mtime="${10}" ctime="${11}" detail="${12}"
    local key="$rule_id|$path"
    [[ -z "${SEEN_FINDINGS[$key]+x}" ]] || return 0
    SEEN_FINDINGS["$key"]=1
    ((FINDINGS_COUNT += 1))
    case "$severity" in
        HIGH) ((HIGH_COUNT += 1)) ;;
        MEDIUM) ((MEDIUM_COUNT += 1)) ;;
        LOW) ((LOW_COUNT += 1)) ;;
        *) ((INFO_COUNT += 1)) ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(utc_now)" "$severity" "$rule_id" "$(sanitise_tsv "$path")" "$line" "$hash" \
        "$size" "$uid" "$gid" "$mode" "$mtime" "$ctime" "$(sanitise_tsv "$detail")" >> "$FINDINGS_FILE"
    log_line FINDING "$severity $rule_id: $path${line:+:$line} - $detail"
}

record_file_finding() {
    record_finding_values "$1" "$2" "$CURRENT_PATH" "$3" "$CURRENT_HASH" "$CURRENT_SIZE" \
        "$CURRENT_UID" "$CURRENT_GID" "$CURRENT_MODE" "$CURRENT_MTIME" "$CURRENT_CTIME" "$4"
}

apply_content_rule() {
    local severity="$1" rule_id="$2" detail="$3" pattern="$4"
    local line=""
    line=$(first_match_line "$CURRENT_FILE" "$pattern")
    [[ "$line" != "0" ]] || return 0
    record_file_finding "$severity" "$rule_id" "$line" "$detail"
}

check_metadata_rules() {
    local base="${CURRENT_FILE##*/}"
    local name=""
    name=$(lowercase "$base")
    local script=0
    has_script_extension "$name" && script=1

    if looks_like_known_shell_name "$name"; then
        record_file_finding HIGH WSH001 0 "Filename resembles a known web-shell family or command endpoint."
    fi
    if ((script)) && [[ "$name" == .* ]]; then
        record_file_finding MEDIUM WSH002 0 "Hidden file has an executable web-script extension."
    fi
    if [[ "$name" =~ \.(jpg|jpeg|png|gif|svg|ico|txt|pdf|doc|zip|tar|bak|old)\.(php[3-8]?|phtml|jsp|jspx|asp|aspx|ashx|cfm|cgi|pl|py|rb|sh)$ ]]; then
        record_file_finding HIGH WSH003 0 "Double extension may disguise executable web content."
    fi
    if ((script)) && [[ "$CURRENT_PATH" =~ /(^|/)?(upload|uploads|uploaded|images|img|media|cache|tmp|temp|sessions?)(/|$) ]]; then
        record_file_finding HIGH WSH004 0 "Executable web content is present in an upload, media, cache or temporary path."
    fi
    local filesystem_type=""
    filesystem_type=$("$STAT" -f -c '%T' -- "$CURRENT_FILE" 2>/dev/null || true)
    local permission_metadata_reliable=1
    case "$filesystem_type" in
        9p|v9fs|drvfs|fuseblk|vfat|msdos|exfat|ntfs|cifs|smb2)
            permission_metadata_reliable=0
            if [[ -z "${SEEN_FS_WARNINGS[$filesystem_type]+x}" ]]; then
                SEEN_FS_WARNINGS["$filesystem_type"]=1
                log_warning "Permission heuristics are disabled on '$filesystem_type' because Unix mode bits may be synthetic."
            fi
            ;;
    esac
    if ((permission_metadata_reliable)) && [[ "$CURRENT_MODE" =~ ^[0-7]{3,4}$ ]]; then
        local permission_value=$((8#$CURRENT_MODE))
        if ((permission_value & 2)); then
            record_file_finding HIGH WSH005 0 "Candidate is world-writable (mode $CURRENT_MODE)."
        elif ((permission_value & 16)); then
            record_file_finding MEDIUM WSH006 0 "Candidate is group-writable (mode $CURRENT_MODE)."
        fi
    fi
    if ((script)) && [[ "$CURRENT_UID" =~ ^[0-9]+$ ]]; then
        local owner_name=""
        if [[ -r "$TARGET_ROOT/etc/passwd" ]]; then
            owner_name=$("$AWK" -F: -v wanted_uid="$CURRENT_UID" '$3 == wanted_uid {print $1; exit}' "$TARGET_ROOT/etc/passwd" 2>/dev/null || true)
        elif [[ "$TARGET_ROOT" == "/" ]]; then
            owner_name=$("$ID" -nu "$CURRENT_UID" 2>/dev/null || true)
        fi
        if [[ "$owner_name" =~ ^(www-data|apache|nginx|httpd|tomcat|lighttpd|caddy)$ ]]; then
            record_file_finding MEDIUM WSH007 0 "Executable web content is owned by service account '$owner_name'."
        fi
    fi
    if ((RECENT_DAYS > 0)) && ((script)) && [[ "$CURRENT_MTIME" =~ ^[0-9]+$ ]]; then
        local cutoff=$((RUN_STARTED_EPOCH - RECENT_DAYS * 86400))
        if ((CURRENT_MTIME >= cutoff)); then
            record_file_finding LOW WSH008 0 "Executable web content was modified within the requested $RECENT_DAYS-day window."
        fi
    fi
    if [[ "$TARGET_ROOT" == "/" ]] && [[ "$CURRENT_MTIME" =~ ^[0-9]+$ && "$CURRENT_CTIME" =~ ^[0-9]+$ ]] && ((CURRENT_CTIME - CURRENT_MTIME > 604800)); then
        record_file_finding LOW WSH009 0 "Modification time is over seven days older than inode-change time; review for copying or timestomping."
    fi
    if [[ "$CURRENT_KIND" == "embedded server-side code" ]]; then
        record_file_finding HIGH WSH010 "$(first_match_line "$CURRENT_FILE" '(<\?php|<%[@=]?|<cf(execute|script)|#!/(usr/)?bin/)')" "Server-side code was found in a file without a recognised script extension."
    fi
}

check_baseline_and_hash_iocs() {
    if [[ -n "${IOC_HASHES[$CURRENT_HASH]+x}" ]]; then
        record_file_finding HIGH WSH020 0 "SHA-256 matches local IOC list: ${IOC_HASHES[$CURRENT_HASH]}"
    fi
    [[ -n "$KNOWN_GOOD_ROOT" ]] || return 0
    local baseline_candidate="$KNOWN_GOOD_ROOT$CURRENT_PATH"
    if [[ ! -e "$baseline_candidate" ]]; then
        record_file_finding MEDIUM WSH021 0 "Candidate is absent from the known-good mirror."
        return 0
    fi
    local baseline_resolved=""
    baseline_resolved=$("$READLINK" -f -- "$baseline_candidate" 2>/dev/null || true)
    if [[ -z "$baseline_resolved" ]] || ! path_is_within "$baseline_resolved" "$KNOWN_GOOD_ROOT" || [[ ! -f "$baseline_resolved" ]]; then
        record_file_finding MEDIUM WSH022 0 "Known-good counterpart is not a safe regular file."
        return 0
    fi
    local baseline_hash=""
    baseline_hash=$("$SHA256SUM" -- "$baseline_resolved" 2>/dev/null || true)
    baseline_hash=${baseline_hash%%[[:space:]]*}
    if [[ -z "$baseline_hash" ]]; then
        log_warning "Could not hash known-good counterpart for $CURRENT_PATH."
    elif [[ "$baseline_hash" != "$CURRENT_HASH" ]]; then
        record_file_finding HIGH WSH023 0 "SHA-256 differs from the known-good counterpart ($baseline_hash)."
    fi
}

check_language_rules() {
    apply_content_rule HIGH WSH100 "Content contains a recognisable web-shell family signature." '(c99shcook\[|WSOsetcookie|FilesMan|SelfRemove|<title[^>]*>[^<]*(c99|r57|b374k|wso)|b374k[[:space:]_-]*shell|china[[:space:]_-]*chopper)'
    apply_content_rule MEDIUM WSH101 "Long base64-like content may contain an embedded payload." '[A-Za-z0-9+/]{400,}={0,2}'

    local is_php=0 is_jsp=0 is_asp=0 is_cf=0 is_js=0 is_python=0 is_perl=0 is_ruby=0
    [[ "$CURRENT_KIND" == "PHP" ]] && is_php=1
    [[ "$CURRENT_KIND" == "JSP" ]] && is_jsp=1
    [[ "$CURRENT_KIND" == "ASP.NET" ]] && is_asp=1
    [[ "$CURRENT_KIND" == "ColdFusion" ]] && is_cf=1
    [[ "$CURRENT_KIND" == "JavaScript" ]] && is_js=1
    [[ "$CURRENT_KIND" == "Python" ]] && is_python=1
    [[ "$CURRENT_KIND" == "CGI/Perl" ]] && is_perl=1
    [[ "$CURRENT_KIND" == "Ruby" ]] && is_ruby=1
    if [[ "$CURRENT_KIND" == "embedded server-side code" ]]; then
        file_contains "$CURRENT_FILE" '<\?php' && is_php=1
        file_contains "$CURRENT_FILE" '<%@?[[:space:]]*(page|include)|Runtime\.getRuntime' && is_jsp=1
        file_contains "$CURRENT_FILE" '<%|System\.Diagnostics\.Process|WScript\.Shell' && is_asp=1
        file_contains "$CURRENT_FILE" '<cf(execute|script)' && is_cf=1
    fi

    if ((is_php)); then
        apply_content_rule MEDIUM WSH110 "PHP command/process execution primitive is present." '(^|[^[:alnum:]_])(assert|passthru|shell_exec|exec|system|popen|proc_open|pcntl_exec)[[:space:]]*\('
        apply_content_rule HIGH WSH111 "PHP evaluation is combined with decoding or decompression." '(eval|assert)[[:space:]]*\([^;]*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|urldecode)'
        apply_content_rule HIGH WSH112 "PHP preg_replace /e execution modifier is present." 'preg_replace[[:space:]]*\([^;]*\/[^/\r\n]*\/[a-zA-Z]*e[a-zA-Z]*[[:space:]]*[,)]'
        apply_content_rule HIGH WSH113 "PHP request input appears to be invoked as a function." '\$_(GET|POST|REQUEST|COOKIE)[[:space:]]*\[[^]]+\][[:space:]]*\('
        apply_content_rule MEDIUM WSH114 "PHP variable-variable or dynamic function invocation is present." '(\$\{[^}]+\}|\$\$[A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\('
        apply_content_rule HIGH WSH115 "Reversed base64 decoder name is a common obfuscation signal." 'edoced_46esab'
        apply_content_rule MEDIUM WSH116 "Repeated chr() concatenation may construct hidden function names or payloads." '(chr[[:space:]]*\([^)]{1,8}\)[[:space:]]*\.[[:space:]]*){4,}'
        apply_content_rule MEDIUM WSH117 "Dense hexadecimal escape construction may conceal executable PHP." '(\\x[0-9a-fA-F]{2}){8,}'
        apply_content_rule HIGH WSH118 "Deprecated PHP create_function construct is present." 'create_function[[:space:]]*\('
        apply_content_rule MEDIUM WSH119 "PHP backtick command-execution operator is present." '`[^`]{1,500}`'

        if file_contains "$CURRENT_FILE" '\$_(GET|POST|REQUEST|COOKIE|FILES)|php://input' && file_contains "$CURRENT_FILE" '(eval|assert|passthru|shell_exec|exec|system|popen|proc_open|pcntl_exec)[[:space:]]*\('; then
            record_file_finding HIGH WSH120 "$(first_match_line "$CURRENT_FILE" '\$_(GET|POST|REQUEST|COOKIE|FILES)|php://input')" "Attacker-controllable request input and a command/evaluation primitive occur in the same PHP file."
        fi
        if file_contains "$CURRENT_FILE" '\$_COOKIE' && file_contains "$CURRENT_FILE" '(eval|assert|include|require|file_put_contents|fwrite|base64_decode|call_user_func|shell_exec|system|exec)[[:space:]]*\(?'; then
            record_file_finding HIGH WSH121 "$(first_match_line "$CURRENT_FILE" '\$_COOKIE')" "Cookie-controlled execution, staging or dynamic loading signals occur in the PHP file."
        fi
        if file_contains "$CURRENT_FILE" '(file_put_contents|fwrite|move_uploaded_file)[[:space:]]*\(' && file_contains "$CURRENT_FILE" '\$_(GET|POST|REQUEST|COOKIE|FILES)|php://input'; then
            record_file_finding HIGH WSH122 "$(first_match_line "$CURRENT_FILE" '(file_put_contents|fwrite|move_uploaded_file)[[:space:]]*\(')" "Request-controlled data may be written or moved by PHP."
        fi
    fi

    if [[ "$CURRENT_KIND" == "web configuration" ]]; then
        apply_content_rule HIGH WSH130 "Configuration redirects PHP startup to an additional file." '(php_value|php_admin_value|=)[[:space:]]*auto_(pre|ap)pend_file|auto_(pre|ap)pend_file[[:space:]]*='
        apply_content_rule MEDIUM WSH131 "Configuration adds an executable handler for an unusual extension." '(AddHandler|AddType|SetHandler)[^#]*(php|cgi|fcgi|proxy:unix)'
    fi

    if ((is_jsp)); then
        apply_content_rule HIGH WSH140 "JSP/Java launches an operating-system process." '(Runtime\.getRuntime[[:space:]]*\(\)[[:space:]]*\.exec|new[[:space:]]+ProcessBuilder|ProcessBuilder[[:space:]]*\()'
        apply_content_rule MEDIUM WSH141 "JSP/Java dynamically defines code or uses a script engine." '(defineClass[[:space:]]*\(|ScriptEngineManager|URLClassLoader)'
        if file_contains "$CURRENT_FILE" '(getParameter|getInputStream|getHeader|Cookie)' && file_contains "$CURRENT_FILE" '(Runtime\.getRuntime|ProcessBuilder|\.exec[[:space:]]*\()'; then
            record_file_finding HIGH WSH142 "$(first_match_line "$CURRENT_FILE" '(getParameter|getInputStream|getHeader|Cookie)')" "Request input and operating-system execution occur in the same JSP/Java file."
        fi
    fi

    if ((is_asp)); then
        apply_content_rule HIGH WSH150 "ASP/ASP.NET invokes a shell or starts a process." '(System\.Diagnostics\.Process|Process\.Start|WScript\.Shell|ShellExecute|cmd\.exe|powershell(\.exe)?)'
        if file_contains "$CURRENT_FILE" '(Request\[|Request\.(Form|QueryString|Cookies))' && file_contains "$CURRENT_FILE" '(Process\.Start|WScript\.Shell|ShellExecute|cmd\.exe)'; then
            record_file_finding HIGH WSH151 "$(first_match_line "$CURRENT_FILE" '(Request\[|Request\.(Form|QueryString|Cookies))')" "Request input and process execution occur in the same ASP/ASP.NET file."
        fi
    fi

    ((is_cf)) && apply_content_rule HIGH WSH160 "ColdFusion executes an operating-system command." '<cfexecute|createObject[[:space:]]*\([[:space:]]*["'\'' ]*java["'\'' ]*[[:space:]]*,[[:space:]]*["'\'' ]*java\.lang\.Runtime'

    if ((is_js)); then
        apply_content_rule MEDIUM WSH170 "Server-side JavaScript imports or uses child_process execution." '(require[[:space:]]*\([[:space:]]*["'\'']child_process["'\'']|from[[:space:]]+["'\'']child_process["'\'']|child_process\.(exec|execFile|spawn|fork))'
        if file_contains "$CURRENT_FILE" '(req\.(query|body|params|headers|cookies)|request\.)' && file_contains "$CURRENT_FILE" '(child_process|execSync|spawnSync|\.exec[[:space:]]*\()'; then
            record_file_finding HIGH WSH171 "$(first_match_line "$CURRENT_FILE" '(req\.(query|body|params|headers|cookies)|request\.)')" "Web request input and child-process execution occur in the same JavaScript file."
        fi
    fi

    if ((is_python)); then
        apply_content_rule MEDIUM WSH180 "Python launches a process or shell." '(subprocess\.(Popen|run|call|check_output|check_call)|os\.(system|popen)|pty\.spawn)[[:space:]]*\('
        if file_contains "$CURRENT_FILE" '(request\.(args|form|values|cookies|data)|QUERY_STRING|cgi\.FieldStorage)' && file_contains "$CURRENT_FILE" '(subprocess\.|os\.(system|popen)|pty\.spawn)'; then
            record_file_finding HIGH WSH181 "$(first_match_line "$CURRENT_FILE" '(request\.(args|form|values|cookies|data)|QUERY_STRING|cgi\.FieldStorage)')" "Web request input and process execution occur in the same Python file."
        fi
    fi

    if ((is_perl)); then
        apply_content_rule MEDIUM WSH190 "CGI/Perl contains a command-execution primitive." '(system|exec|qx)[[:space:]]*[({]|`[^`]+`'
        if file_contains "$CURRENT_FILE" '(param[[:space:]]*\(|QUERY_STRING|HTTP_COOKIE)' && file_contains "$CURRENT_FILE" '(system|exec|qx)[[:space:]]*[({]|`[^`]+`'; then
            record_file_finding HIGH WSH191 "$(first_match_line "$CURRENT_FILE" '(param[[:space:]]*\(|QUERY_STRING|HTTP_COOKIE)')" "CGI request input and command execution occur in the same file."
        fi
    fi

    if ((is_ruby)); then
        apply_content_rule MEDIUM WSH200 "Ruby launches a command or process." '(Kernel\.(system|exec)|Open3\.(capture|popen)|IO\.popen|`[^`]+`)'
        if file_contains "$CURRENT_FILE" '(params\[|cookies\[|request\.)' && file_contains "$CURRENT_FILE" '(Kernel\.(system|exec)|Open3\.|IO\.popen|`[^`]+`)'; then
            record_file_finding HIGH WSH201 "$(first_match_line "$CURRENT_FILE" '(params\[|cookies\[|request\.)')" "Web request input and command execution occur in the same Ruby file."
        fi
    fi
}

run_optional_scanners() {
    if [[ -n "$YARA_RULES" ]]; then
        local yara_result=""
        local yara_status=0
        yara_result=$("$YARA" -w "$YARA_RULES" "$CURRENT_FILE" 2>> "$LOG_FILE")
        yara_status=$?
        if ((yara_status == 0)) && [[ -n "$yara_result" ]]; then
            record_file_finding HIGH WSH900 0 "Local YARA match: $(sanitise_tsv "${yara_result%%$'\n'*}")"
        elif ((yara_status > 1 && YARA_ERROR_REPORTED == 0)); then
            YARA_ERROR_REPORTED=1
            log_error "YARA returned an execution error; see the action log."
        fi
    fi
    if ((USE_CLAMAV)); then
        local clam_result=""
        local clam_status=0
        clam_result=$("$CLAMSCAN" --infected --no-summary -- "$CURRENT_FILE" 2>> "$LOG_FILE")
        clam_status=$?
        if ((clam_status == 1)) && [[ "$clam_result" == *" FOUND"* ]]; then
            record_file_finding HIGH WSH901 0 "Local ClamAV detection: $(sanitise_tsv "$clam_result")"
        elif ((clam_status > 1 && CLAMAV_ERROR_REPORTED == 0)); then
            CLAMAV_ERROR_REPORTED=1
            log_error "ClamAV returned an execution error; see the action log."
        fi
    fi
}

scan_candidate() {
    local file="$1"
    CURRENT_FILE="$file"
    CURRENT_PATH=$(target_display_path "$file")
    if ! load_current_metadata "$file"; then
        ((FILES_SKIPPED += 1))
        log_warning "File disappeared or metadata was unreadable: $CURRENT_PATH"
        return 0
    fi
    if ((CURRENT_SIZE > MAX_FILE_BYTES)); then
        ((FILES_SKIPPED += 1))
        log_verbose "Skipping oversized candidate ($CURRENT_SIZE bytes): $CURRENT_PATH"
        return 0
    fi
    if ! classify_candidate "$file"; then return 0; fi
    if ! hash_current_file; then
        ((FILES_SKIPPED += 1))
        log_warning "Could not read or hash candidate: $CURRENT_PATH"
        return 0
    fi
    ((FILES_SCANNED += 1))
    write_inventory_row
    check_metadata_rules
    check_baseline_and_hash_iocs
    [[ "$CURRENT_KIND" == "deployment archive" ]] || check_language_rules
    run_optional_scanners
}

scan_web_roots() {
    log_section "Scanning web content"
    local root="" list_file="" file="" root_index=0
    for root in "${SCAN_ROOTS[@]}"; do
        ((LIMIT_REACHED)) && break
        ((root_index += 1))
        log_info "Enumerating $(target_display_path "$root")."
        list_file="$OUTPUT_DIR/.files_${root_index}.nul"
        if ((CROSS_FILESYSTEMS)); then
            "$FIND" -P "$root" -type f -print0 > "$list_file" 2>> "$LOG_FILE" || log_error "File enumeration was incomplete below $(target_display_path "$root")."
        else
            "$FIND" -P "$root" -xdev -type f -print0 > "$list_file" 2>> "$LOG_FILE" || log_error "File enumeration was incomplete below $(target_display_path "$root")."
        fi
        while IFS= read -r -d '' file; do
            if ((FILES_VISITED >= MAX_FILES)); then
                LIMIT_REACHED=1
                log_error "The --max-files limit ($MAX_FILES) was reached; the hunt is incomplete."
                break
            fi
            should_exclude "$file" && continue
            [[ -z "${SEEN_FILES[$file]+x}" ]] || continue
            SEEN_FILES["$file"]=1
            ((FILES_VISITED += 1))
            scan_candidate "$file"
        done < "$list_file"
        "$RM" -f -- "$list_file"
    done
    log_info "Visited $FILES_VISITED file(s) and content-scanned $FILES_SCANNED candidate(s)."
}

find_standard_files() {
    local result_file="$1"
    shift
    : > "$result_file"
    local target_path="" base=""
    for target_path in "$@"; do
        base=$(resolve_target_path "$target_path" || true)
        [[ -n "$base" ]] || continue
        "$FIND" -P "$base" -xdev -type f -print0 >> "$result_file" 2>> "$LOG_FILE" || true
    done
}

analyse_persistence() {
    ((ANALYSE_PERSISTENCE)) || return 0
    log_section "Checking scheduled-task persistence"
    local list_file="$OUTPUT_DIR/.cron_files.nul"
    find_standard_files "$list_file" /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs
    local file="" line="" hash_result="" display="" size=""
    local pattern='(base64[[:space:]]+(-d|--decode)|curl|wget|printf|echo).*(\.php[3-8]?|\.phtml|\.jsp|\.jspx|\.asp|\.aspx|/var/www|/srv/(www|http)|public_html|httpdocs)'
    while IFS= read -r -d '' file; do
        size=$("$STAT" -c '%s' -- "$file" 2>/dev/null || printf '0')
        ((size <= MAX_FILE_BYTES)) || continue
        line=$(first_match_line "$file" "$pattern")
        [[ "$line" != "0" ]] || continue
        hash_result=$("$SHA256SUM" -- "$file" 2>/dev/null || true)
        hash_result=${hash_result%%[[:space:]]*}
        display=$(target_display_path "$file")
        record_finding_values MEDIUM WSH300 "$display" "$line" "$hash_result" "$size" "-" "-" "-" "-" "-" "Scheduled task may download, decode or recreate executable web content."
    done < "$list_file"
    "$RM" -f -- "$list_file"
}

analyse_access_logs() {
    ((ANALYSE_LOGS)) || return 0
    log_section "Analysing web access logs"
    local list_file="$OUTPUT_DIR/.web_logs.nul"
    : > "$list_file"
    local target_path="" base=""
    local -a log_paths=(/var/log/apache2 /var/log/httpd /var/log/nginx /usr/local/apache2/logs /usr/local/lsws/logs /var/log/caddy /var/www/vhosts/system)
    for target_path in "${log_paths[@]}"; do
        base=$(resolve_target_path "$target_path" || true)
        [[ -n "$base" ]] || continue
        "$FIND" -P "$base" -xdev -type f \( -iname '*access*.log' -o -iname 'access_log' -o -iname '*access.log.[0-9]*' \) -print0 >> "$list_file" 2>> "$LOG_FILE" || true
    done

    local pattern='((cmd|exec|command|shell|passthru|system|download|upload|file)=|/etc/(passwd|shadow)|base64(_decode|%5[fF]decode)|c99|r57|b374k|wso|china[+%20_-]*chopper|(%2[fF]|/)(bin|usr)(%2[fF]|/)(ba)?sh)'
    local file="" size="" display="" hash_result="" match="" line="" excerpt="" matches=0 logs_seen=0
    while IFS= read -r -d '' file; do
        ((logs_seen >= MAX_LOGS)) && { log_warning "Access-log limit ($MAX_LOGS) reached; remaining logs were not analysed."; break; }
        ((logs_seen += 1))
        size=$("$STAT" -c '%s' -- "$file" 2>/dev/null || printf '0')
        if ((size > MAX_LOG_BYTES)); then
            log_verbose "Skipping oversized access log: $(target_display_path "$file")"
            continue
        fi
        matches=0
        display=$(target_display_path "$file")
        hash_result=""
        while IFS= read -r match; do
            ((matches += 1))
            line=${match%%:*}
            excerpt=${match#*:}
            excerpt=${excerpt:0:500}
            if [[ -z "$hash_result" ]]; then
                hash_result=$("$SHA256SUM" -- "$file" 2>/dev/null || true)
                hash_result=${hash_result%%[[:space:]]*}
            fi
            printf '%s\t%s\t%s\t%s\n' "$(sanitise_tsv "$display")" "$line" "$hash_result" "$(sanitise_tsv "$excerpt")" >> "$WEB_LOG_LEADS_FILE"
            ((matches >= 200)) && break
        done < <("$GREP" -aEin -- "$pattern" "$file" 2>/dev/null || true)
        if ((matches > 0)); then
            record_finding_values MEDIUM WSH400 "$display" "0" "$hash_result" "$size" "-" "-" "-" "-" "-" "$matches command-like request lead(s) were written to web_log_leads.tsv."
        fi
    done < "$list_file"
    "$RM" -f -- "$list_file"
    log_info "Analysed $logs_seen uncompressed access log(s)."
}

proc_comm() {
    local pid="$1"
    local value=""
    IFS= read -r value < "/proc/$pid/comm" 2>/dev/null || return 1
    printf '%s' "$value"
}

proc_ppid() {
    local pid="$1"
    "$AWK" '/^PPid:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null
}

analyse_live_processes() {
    ((ANALYSE_PROCESSES)) || return 0
    [[ "$TARGET_ROOT" == "/" && -d /proc ]] || { log_info "Skipping process ancestry because the target is not the live root."; return 0; }
    log_section "Checking live web-worker descendants"
    local proc_dir="" pid="" comm="" parent="" parent_comm="" depth=0 ancestor="" cmdline=""
    local suspicious_re='^(sh|bash|dash|zsh|ksh|curl|wget|nc|ncat|socat|whoami|id|uname|hostname|ifconfig|netstat|python[0-9.]*|perl)$'
    local web_re='^(apache2|httpd|nginx|openresty|lighttpd|caddy|lshttpd|php-fpm.*|java|tomcat.*|jetty.*|wildfly.*|jboss.*|glassfish.*|payara.*|node|gunicorn|uwsgi)$'
    for proc_dir in /proc/[0-9]*; do
        [[ -d "$proc_dir" ]] || continue
        pid=${proc_dir##*/}
        comm=$(proc_comm "$pid" || true)
        [[ "$comm" =~ $suspicious_re ]] || continue
        parent=$(proc_ppid "$pid" || true)
        ancestor=""
        depth=0
        while [[ "$parent" =~ ^[0-9]+$ ]] && ((parent > 1 && depth < 6)); do
            parent_comm=$(proc_comm "$parent" || true)
            if [[ "$parent_comm" =~ $web_re ]]; then ancestor="$parent_comm (PID $parent)"; break; fi
            parent=$(proc_ppid "$parent" || true)
            ((depth += 1))
        done
        [[ -n "$ancestor" ]] || continue
        cmdline=$("$TR" '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
        cmdline=${cmdline:0:500}
        record_finding_values HIGH WSH500 "/proc/$pid" "0" "-" "-" "-" "-" "-" "-" "-" "Process '$comm' descends from web worker $ancestor; command: $cmdline"
    done
}

write_summary() {
    RUN_FINISHED_UTC=$(utc_now)
    local elapsed=$(( $("$DATE" -u '+%s') - RUN_STARTED_EPOCH ))
    {
        printf '%s %s hunt summary\n' "$PROGRAM_NAME" "$VERSION"
        printf 'Started (UTC): %s\n' "$RUN_STARTED_UTC"
        printf 'Finished (UTC): %s\n' "$RUN_FINISHED_UTC"
        printf 'Elapsed seconds: %s\n' "$elapsed"
        printf 'Case reference: %s\n' "$CASE_REFERENCE"
        printf 'Examiner: %s\n' "$EXAMINER"
        printf 'Source identifier: %s\n' "$SOURCE_IDENTIFIER"
        printf 'Target root: %s\n' "$TARGET_ROOT"
        printf 'Known-good root: %s\n' "${KNOWN_GOOD_ROOT:-Not supplied}"
        printf 'Web roots: %s\n' "${#SCAN_ROOTS[@]}"
        printf 'Files visited: %s\n' "$FILES_VISITED"
        printf 'Candidates scanned: %s\n' "$FILES_SCANNED"
        printf 'Candidates skipped: %s\n' "$FILES_SKIPPED"
        printf 'Findings: %s (high=%s medium=%s low=%s informational=%s)\n' "$FINDINGS_COUNT" "$HIGH_COUNT" "$MEDIUM_COUNT" "$LOW_COUNT" "$INFO_COUNT"
        printf 'Operational errors: %s\n' "$ERROR_COUNT"
        printf 'File limit reached: %s\n' "$LIMIT_REACHED"
        printf 'Interpretation: Findings are leads requiring analyst validation; absence of findings is not proof of absence.\n'
    } > "$SUMMARY_FILE"
}

finalise_reports() {
    write_summary
    log_section "Finalising report"
    log_info "Findings: $FINDINGS_COUNT (high $HIGH_COUNT, medium $MEDIUM_COUNT, low $LOW_COUNT)."
    log_info "Operational errors: $ERROR_COUNT."
    log_line COMPLETE "Hunt finished at $RUN_FINISHED_UTC."

    local artefact=""
    : > "$MANIFEST_FILE"
    for artefact in "$LOG_FILE" "$FINDINGS_FILE" "$INVENTORY_FILE" "$ROOTS_FILE" "$SERVERS_FILE" "$WEB_LOG_LEADS_FILE" "$SUMMARY_FILE"; do
        (cd "$OUTPUT_DIR" && "$SHA256SUM" -- "${artefact##*/}") >> "$MANIFEST_FILE"
    done
    "$CHMOD" 0600 -- "$OUTPUT_DIR"/* 2>/dev/null || true
}

handle_signal() {
    local signal_name="$1"
    trap - INT TERM
    if [[ -n "$LOG_FILE" && -d "$OUTPUT_DIR" ]]; then
        log_warning "Received $signal_name; results are partial."
        ERROR_COUNT=$((ERROR_COUNT + 1))
        finalise_reports
        printf 'Partial results: %s\n' "$OUTPUT_DIR"
    fi
    exit "$EXIT_INTERRUPTED"
}

main() {
    local invocation=""
    invocation=$(format_invocation "$@")
    parse_arguments "$@"

    # Root is checked before dependency discovery or target reads. Help/version
    # have already returned so every actual hunt is privileged consistently.
    if ((EUID != 0)); then
        die_early "This script must be run as root. Use sudo $0 --help for instructions."
    fi

    resolve_commands
    initialise_colours
    prepare_paths
    trap 'handle_signal INT' INT
    trap 'handle_signal TERM' TERM

    RUN_STARTED_EPOCH=$("$DATE" -u '+%s')
    RUN_STARTED_UTC=$(utc_now)
    log_section "$PROGRAM_NAME $VERSION"
    log_info "Hunt started at $RUN_STARTED_UTC."
    log_info "Invocation: $invocation"
    local script_path="" script_hash=""
    script_path=$("$READLINK" -f -- "$0" 2>/dev/null || true)
    if [[ -n "$script_path" && -f "$script_path" ]]; then
        script_hash=$("$SHA256SUM" -- "$script_path" 2>/dev/null || true)
        script_hash=${script_hash%%[[:space:]]*}
        log_info "Hunter script SHA-256: ${script_hash:-unavailable} ($script_path)"
    fi
    log_info "Case reference: $CASE_REFERENCE"
    log_info "Examiner: $EXAMINER"
    log_info "Source identifier: $SOURCE_IDENTIFIER"
    log_info "Target root: $TARGET_ROOT"
    log_info "Output directory: $OUTPUT_DIR"
    log_info "Host kernel: $("$UNAME" -srmo 2>/dev/null || printf 'unavailable')"
    if [[ -r "$TARGET_ROOT/etc/os-release" ]]; then
        local os_description=""
        os_description=$("$GREP" -m1 '^PRETTY_NAME=' "$TARGET_ROOT/etc/os-release" 2>/dev/null || true)
        log_info "Target operating system: ${os_description#PRETTY_NAME=}"
    fi
    log_warning "This tool reports leads and can produce false positives; validate every finding."

    load_hash_list
    prepare_requested_scope
    scan_web_roots
    analyse_persistence
    analyse_access_logs
    analyse_live_processes
    finalise_reports

    printf '\nResults: %s\n' "$OUTPUT_DIR"
    printf 'Findings: %s (high %s, medium %s, low %s)\n' "$FINDINGS_COUNT" "$HIGH_COUNT" "$MEDIUM_COUNT" "$LOW_COUNT"
    printf 'Manifest: %s\n' "$MANIFEST_FILE"

    if ((ERROR_COUNT > 0)); then return "$EXIT_ERROR"; fi
    if ((FINDINGS_COUNT > 0)); then return "$EXIT_FINDINGS"; fi
    return "$EXIT_CLEAN"
}

main "$@"
