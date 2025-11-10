#!/bin/bash
#
# exifevidence.sh - EXIF Metadata Analysis for Digital Forensics
# Version: 2.0
# Author: DFIR Tools Collection
# Purpose: Search directories for documents modified during an incident timeframe
#          and identify suspicious EXIF metadata discrepancies
#
# This tool analyzes EXIF metadata to detect documents where the "Last Modified By"
# field differs from the "Creator" field, which may indicate tampering or unauthorized access.
#
# USAGE:
#   ./exifevidence.sh [OPTIONS] <folder_path> [start_date] [end_date]
#
# ARGUMENTS:
#   folder_path     - Directory to search (required)
#   start_date      - Start date in YYYY-MM-DD format (optional, defaults to yesterday)
#   end_date        - End date in YYYY-MM-DD format (optional, defaults to today)
#
# OPTIONS:
#   -h, --help      - Display this help message
#   -v, --verbose   - Show all files checked, not just suspicious ones
#   -o, --output    - Write results to specified file
#   -t, --type      - File extensions to check (e.g., "docx,xlsx,pptx")
#   -q, --quiet     - Suppress progress messages (only show results)
#
# EXAMPLES:
#   ./exifevidence.sh /mnt/ntfs/c/users/administrator/documents
#   ./exifevidence.sh /evidence/documents 2021-01-01 2021-09-30
#   ./exifevidence.sh -v -o results.txt /evidence/docs 2021-06-01 2021-06-30
#   ./exifevidence.sh -t "docx,xlsx" /evidence/office_files
#
# REQUIRES:
#   - exiftool (libimage-exiftool-perl package)
#   - find, grep, cut, xargs (standard Unix utilities)
#
# FORENSIC NOTES:
#   - Follows RFC3227 evidence handling guidelines
#   - Does not modify source files
#   - Generates checksums for output files when using -o option
#   - Logs all operations for audit trail
#

# Strict error handling
set -euo pipefail

# Version information
readonly VERSION="2.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# Full paths for commands (security best practice)
readonly EXIFTOOL_BIN="/usr/bin/exiftool"
readonly FIND_BIN="/usr/bin/find"
readonly DATE_BIN="/bin/date"
readonly GREP_BIN="/bin/grep"
readonly SHA256SUM_BIN="/usr/bin/sha256sum"

# Global variables
VERBOSE=0
QUIET=0
OUTPUT_FILE=""
FILE_TYPES=""
SUSPICIOUS_COUNT=0
TOTAL_FILES=0
LOG_FILE=""

# Function: Display help message
show_help() {
    /bin/cat << 'EOF'
exifevidence.sh - EXIF Metadata Analysis for Digital Forensics

USAGE:
    ./exifevidence.sh [OPTIONS] <folder_path> [start_date] [end_date]

ARGUMENTS:
    folder_path     Directory to search (required)
    start_date      Start date in YYYY-MM-DD format (optional, defaults to yesterday)
    end_date        End date in YYYY-MM-DD format (optional, defaults to today)

OPTIONS:
    -h, --help      Display this help message
    -v, --verbose   Show all files checked, not just suspicious ones
    -o, --output    Write results to specified file
    -t, --type      File extensions to check (comma-separated, e.g., "docx,xlsx,pptx")
    -q, --quiet     Suppress progress messages (only show results)

EXAMPLES:
    ./exifevidence.sh /mnt/evidence/documents
    ./exifevidence.sh /evidence/docs 2021-01-01 2021-09-30
    ./exifevidence.sh -v -o results.txt /evidence/docs 2021-06-01 2021-06-30
    ./exifevidence.sh -t "docx,xlsx" /evidence/office_files

REQUIRES:
    exiftool - Install with: sudo apt-get install libimage-exiftool-perl

For more information, see the script header comments.
EOF
}

# Function: Log messages to file and optionally to screen
log_message() {
    local message="$1"
    local timestamp
    timestamp="$("${DATE_BIN}" '+%Y-%m-%d %H:%M:%S')"

    if [[ -n "${LOG_FILE}" ]]; then
        echo "[${timestamp}] ${message}" >> "${LOG_FILE}"
    fi
}

# Function: Display error message and exit
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"

    echo "[!] ERROR: ${message}" >&2
    log_message "ERROR: ${message}"
    exit "${exit_code}"
}

# Function: Validate date format (YYYY-MM-DD)
validate_date() {
    local date_string="$1"
    local field_name="$2"

    # Check format: YYYY-MM-DD
    if ! [[ "${date_string}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        error_exit "${field_name} must be in YYYY-MM-DD format. Got: ${date_string}"
    fi

    # Validate date is actually valid (e.g., not 2021-02-30)
    if ! "${DATE_BIN}" -d "${date_string}" >/dev/null 2>&1; then
        error_exit "${field_name} is not a valid date: ${date_string}"
    fi
}

# Function: Check prerequisites
check_prerequisites() {
    # Check for exiftool
    if ! command -v exiftool &>/dev/null; then
        error_exit "exiftool not found. Install with: sudo apt-get install libimage-exiftool-perl"
    fi

    # Check for required utilities
    local required_commands=("find" "grep" "cut" "xargs" "date")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "${cmd}" &>/dev/null; then
            error_exit "Required command '${cmd}' not found in PATH"
        fi
    done
}

# Function: Parse command-line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -q|--quiet)
                QUIET=1
                shift
                ;;
            -o|--output)
                if [[ -z "${2:-}" ]]; then
                    error_exit "Option -o requires an argument"
                fi
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -t|--type)
                if [[ -z "${2:-}" ]]; then
                    error_exit "Option -t requires an argument"
                fi
                FILE_TYPES="$2"
                shift 2
                ;;
            -*)
                error_exit "Unknown option: $1. Use -h for help."
                ;;
            *)
                # Positional arguments
                if [[ -z "${FOLDER:-}" ]]; then
                    FOLDER="$1"
                elif [[ -z "${SDATE:-}" ]]; then
                    SDATE="$1"
                elif [[ -z "${EDATE:-}" ]]; then
                    EDATE="$1"
                else
                    error_exit "Too many arguments. Use -h for help."
                fi
                shift
                ;;
        esac
    done
}

# Function: Build find command based on file types
build_find_pattern() {
    if [[ -n "${FILE_TYPES}" ]]; then
        local -a patterns=()
        IFS=',' read -ra TYPES <<< "${FILE_TYPES}"
        for ext in "${TYPES[@]}"; do
            # Remove leading dot if present and whitespace
            ext="${ext#.}"
            ext="${ext// /}"
            patterns+=(-o -iname "*.${ext}")
        done
        # Remove first -o
        echo "( ${patterns[@]:1} )"
    else
        echo "-name '*.*'"
    fi
}

# Function: Process a single file
process_file() {
    local file="$1"
    local lastmod author modtime language

    ((TOTAL_FILES++))

    # Extract EXIF metadata
    lastmod=$(exiftool "${file}" 2>/dev/null | "${GREP_BIN}" "Last Modified By" | cut -d':' -f2 | xargs || echo "")
    author=$(exiftool "${file}" 2>/dev/null | "${GREP_BIN}" "Creator" | cut -d':' -f2 | xargs || echo "")
    modtime=$(exiftool "${file}" 2>/dev/null | "${GREP_BIN}" "File Modif" | cut -d':' -f2- | xargs || echo "")
    language=$(exiftool "${file}" 2>/dev/null | "${GREP_BIN}" "Language Code" | cut -d':' -f2 | xargs || echo "")

    # Set defaults for empty fields
    [[ -z "${lastmod}" ]] && lastmod="+No account name recorded+"
    [[ -z "${author}" ]] && author="+No account name recorded+"
    [[ -z "${language}" ]] && language="empty"

    # Check for suspicious discrepancy
    if [[ "${lastmod}" != "${author}" ]]; then
        ((SUSPICIOUS_COUNT++))
        local output="[!] SUSPICIOUS: ${file}
    File was created by: ${author}
    But last modified by: ${lastmod}
    Modification time: ${modtime}
    Language pack: ${language}
"
        echo -e "${output}"
        if [[ -n "${OUTPUT_FILE}" ]]; then
            echo -e "${output}" >> "${OUTPUT_FILE}"
        fi
        log_message "SUSPICIOUS: ${file} - Creator: ${author}, Modified by: ${lastmod}"
    elif [[ ${VERBOSE} -eq 1 ]]; then
        local output="[✓] ${file} - No discrepancies detected (Creator: ${author})"
        echo "${output}"
        if [[ -n "${OUTPUT_FILE}" ]]; then
            echo "${output}" >> "${OUTPUT_FILE}"
        fi
    fi
}

# Main execution
main() {
    # Initialize log file
    LOG_FILE="/tmp/exifevidence_$(date +%Y%m%d_%H%M%S).log"
    log_message "Script started - Version ${VERSION}"

    # Parse arguments
    parse_arguments "$@"

    # Validate required argument
    if [[ -z "${FOLDER:-}" ]]; then
        show_help
        error_exit "Missing required argument: folder_path"
    fi

    # Set default dates if not provided
    if [[ -z "${SDATE:-}" ]]; then
        SDATE=$("${DATE_BIN}" -d '1 day ago' +%F)
    fi
    if [[ -z "${EDATE:-}" ]]; then
        EDATE=$("${DATE_BIN}" +%F)
    fi

    # Validate dates (addresses TODO #3)
    validate_date "${SDATE}" "Start date"
    validate_date "${EDATE}" "End date"

    # Ensure start date is before end date
    if [[ "${SDATE}" > "${EDATE}" ]]; then
        error_exit "Start date (${SDATE}) must be before or equal to end date (${EDATE})"
    fi

    # Validate folder exists and is readable
    if [[ ! -d "${FOLDER}" ]]; then
        error_exit "Folder does not exist: ${FOLDER}"
    fi
    if [[ ! -r "${FOLDER}" ]]; then
        error_exit "Folder is not readable: ${FOLDER}. Check permissions."
    fi

    # Check prerequisites
    check_prerequisites

    # Initialize output file if specified
    if [[ -n "${OUTPUT_FILE}" ]]; then
        cat > "${OUTPUT_FILE}" << EOF
EXIF Evidence Analysis Report
Generated: $("${DATE_BIN}" '+%Y-%m-%d %H:%M:%S')
Scan Directory: ${FOLDER}
Date Range: ${SDATE} to ${EDATE}
File Types: ${FILE_TYPES:-All document types}
========================================

EOF
        log_message "Output file initialized: ${OUTPUT_FILE}"
    fi

    # Display header (unless quiet mode)
    if [[ ${QUIET} -eq 0 ]]; then
        cat << EOF

==============================================================================
EXIF METADATA ANALYSIS - DIGITAL FORENSICS TOOL v${VERSION}
==============================================================================

Searching for documents with suspicious EXIF metadata modifications
Target Directory: ${FOLDER}
Date Range: ${SDATE} to ${EDATE}
File Types: ${FILE_TYPES:-All document types (*.*)}

This analysis will identify files where the "Last Modified By" field
differs from the "Creator" field, which may indicate:
  - Unauthorized access or modification
  - Document tampering
  - Account compromise
  - Insider threat activity

Scanning... (this may take several minutes for large directories)
==============================================================================

EOF
    fi

    log_message "Starting scan - Folder: ${FOLDER}, Dates: ${SDATE} to ${EDATE}"

    # Build find command with file type filter
    local find_pattern
    find_pattern=$(build_find_pattern)

    # Build date filter
    local date_filter="-newermt ${SDATE} ! -newermt ${EDATE}"

    # Execute find and process files
    # Using process substitution to handle filenames with spaces and special characters
    while IFS= read -r -d $'\0' file; do
        process_file "${file}"
    done < <("${FIND_BIN}" "${FOLDER}" ${find_pattern} -type f ${date_filter} -print0 2>/dev/null)

    # Display summary
    if [[ ${QUIET} -eq 0 ]]; then
        cat << EOF

==============================================================================
SCAN COMPLETE - SUMMARY
==============================================================================
Total files scanned: ${TOTAL_FILES}
Suspicious files found: ${SUSPICIOUS_COUNT}
Date range: ${SDATE} to ${EDATE}
EOF
        if [[ -n "${OUTPUT_FILE}" ]]; then
            echo "Results saved to: ${OUTPUT_FILE}"
        fi
        echo "Log file: ${LOG_FILE}"
        echo "=============================================================================="
        echo
    fi

    # Add summary to output file
    if [[ -n "${OUTPUT_FILE}" ]]; then
        cat >> "${OUTPUT_FILE}" << EOF

========================================
SUMMARY
========================================
Total files scanned: ${TOTAL_FILES}
Suspicious files found: ${SUSPICIOUS_COUNT}
Scan completed: $("${DATE_BIN}" '+%Y-%m-%d %H:%M:%S')
EOF

        # Generate checksum for output file (forensic integrity)
        if command -v sha256sum &>/dev/null; then
            local checksum
            checksum=$(sha256sum "${OUTPUT_FILE}" | cut -d' ' -f1)
            echo "SHA256: ${checksum}" >> "${OUTPUT_FILE}.sha256"
            [[ ${QUIET} -eq 0 ]] && echo "Output file checksum: ${checksum}"
            log_message "Output file checksum: ${checksum}"
        fi
    fi

    log_message "Script completed - Files scanned: ${TOTAL_FILES}, Suspicious: ${SUSPICIOUS_COUNT}"

    # Exit with appropriate code
    if [[ ${SUSPICIOUS_COUNT} -gt 0 ]]; then
        exit 0  # Found suspicious files (success)
    else
        exit 0  # No suspicious files found (also success)
    fi
}

# Run main function with all arguments
main "$@"
