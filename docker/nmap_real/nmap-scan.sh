#!/bin/bash

# Nmap Container Scanner - Bash Wrapper
# Simple wrapper script for Linux/macOS users

set -e

# Configuration
IMAGE_NAME="nmap-scanner:latest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to show usage
show_usage() {
    print_color $CYAN "Nmap Container Scanner - Usage Examples"
    print_color $CYAN "======================================"
    echo
    print_color $YELLOW "Basic Usage:"
    echo "  ./nmap-scan.sh 192.168.1.0/24                    # Default comprehensive scan"
    echo "  ./nmap-scan.sh -q 192.168.1.1                    # Quick scan (top 1000 ports)"
    echo
    print_color $YELLOW "Custom Arguments:"
    echo "  ./nmap-scan.sh -sS -p 80,443 192.168.1.0/24      # Custom SYN scan"
    echo "  ./nmap-scan.sh --top-ports 100 -sV 192.168.1.1   # Top ports with version detection"
    echo
    print_color $YELLOW "Options:"
    echo "  -q, --quick     Use quick scan profile (top 1000 ports)"
    echo "  -b, --build     Force rebuild of Docker image"
    echo "  -h, --help      Show this help message"
    echo
    print_color $YELLOW "Output Location:"
    echo "  All scan results are saved to: ${OUTPUT_DIR}"
    echo
    print_color $YELLOW "Default Scan Options:"
    echo "  -Pn -sC -sV -oA scan_tcp -vvvvvvvvv --reason -T4 -p-"
    echo
}

# Function to check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_color $RED "✗ Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_color $RED "✗ Docker daemon is not running"
        exit 1
    fi
}

# Function to check if image exists
image_exists() {
    docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "^${IMAGE_NAME}$"
}

# Function to build the image
build_image() {
    print_color $YELLOW "Building nmap scanner Docker image..."
    
    if docker build -t "${IMAGE_NAME}" "${SCRIPT_DIR}"; then
        print_color $GREEN "✓ Docker image built successfully"
    else
        print_color $RED "✗ Failed to build Docker image"
        exit 1
    fi
}

# Function to create output directory
create_output_dir() {
    if [[ ! -d "${OUTPUT_DIR}" ]]; then
        mkdir -p "${OUTPUT_DIR}"
        print_color $GREEN "✓ Created output directory: ${OUTPUT_DIR}"
    fi
}

# Function to run nmap scan
run_scan() {
    local args=("$@")
    
    create_output_dir
    
    print_color $CYAN "Starting nmap scan..."
    print_color $GRAY "Output directory: ${OUTPUT_DIR}"
    print_color $GRAY "$(printf '%*s' 60 '' | tr ' ' '-')"
    
    # Run the container
    docker run \
        --rm \
        --network=host \
        -v "${OUTPUT_DIR}:/output" \
        --name "nmap-scanner_$(date +%Y%m%d_%H%M%S)" \
        "${IMAGE_NAME}" \
        "${args[@]}"
    
    local exit_code=$?
    
    print_color $GRAY "$(printf '%*s' 60 '' | tr ' ' '-')"
    
    if [[ $exit_code -eq 0 ]]; then
        print_color $GREEN "✓ Scan completed successfully"
        
        # List recent output files
        local recent_files
        recent_files=$(find "${OUTPUT_DIR}" -type f -newermt "5 minutes ago" 2>/dev/null || true)
        
        if [[ -n "$recent_files" ]]; then
            print_color $GREEN "Output files created:"
            echo "$recent_files" | while read -r file; do
                print_color $GRAY "  - $(basename "$file")"
            done
        fi
    else
        print_color $RED "✗ Scan failed with exit code: $exit_code"
        exit $exit_code
    fi
}

# Main function
main() {
    local quick_scan=false
    local force_build=false
    local args=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -q|--quick)
                quick_scan=true
                shift
                ;;
            -b|--build)
                force_build=true
                shift
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done
    
    print_color $CYAN "Nmap Container Scanner"
    print_color $CYAN "====================="
    
    # Check prerequisites
    check_docker
    
    # Build image if needed
    if [[ "$force_build" == true ]] || ! image_exists; then
        build_image
    fi
    
    # Handle quick scan
    if [[ "$quick_scan" == true ]]; then
        if [[ ${#args[@]} -eq 0 ]]; then
            print_color $RED "✗ Quick scan requires a target"
            show_usage
            exit 1
        fi
        
        # Add quick scan options before the target
        local target="${args[-1]}"
        unset 'args[-1]'
        args=("-T4" "--top-ports" "1000" "-sV" "--version-light" "${args[@]}" "$target")
    fi
    
    # Run the scan
    if [[ ${#args[@]} -eq 0 ]]; then
        show_usage
    else
        run_scan "${args[@]}"
    fi
}

# Execute main function with all arguments
main "$@"