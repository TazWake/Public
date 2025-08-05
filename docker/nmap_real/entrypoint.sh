#!/bin/bash

# Entrypoint script for nmap container
# Handles default arguments and allows customization

set -e

# Default nmap arguments as specified
DEFAULT_NMAP_ARGS="-Pn -sC -sV -oA scan_tcp -vvvvvvvvv --reason -T4 -p-"

# Function to display usage information
show_usage() {
    echo "Nmap Container Usage:"
    echo ""
    echo "Basic usage with default scan:"
    echo "  docker run --rm -v \$(pwd)/output:/output nmap-scanner <target>"
    echo ""
    echo "Custom nmap arguments:"
    echo "  docker run --rm -v \$(pwd)/output:/output nmap-scanner [nmap-options] <target>"
    echo ""
    echo "Default scan options: ${DEFAULT_NMAP_ARGS}"
    echo ""
    echo "Examples:"
    echo "  docker run --rm -v \$(pwd)/output:/output nmap-scanner 192.168.1.0/24"
    echo "  docker run --rm -v \$(pwd)/output:/output nmap-scanner -sS -p 80,443 192.168.1.1"
    echo "  docker run --rm -v \$(pwd)/output:/output nmap-scanner --top-ports 1000 192.168.1.0/24"
    echo ""
    echo "Output files will be saved to your local ./output directory"
}

# Function to detect if arguments are nmap options or just a target
is_target_only() {
    local arg="$1"
    # Check if argument looks like an IP address, hostname, or CIDR notation
    if [[ "$arg" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]] || \
       [[ "$arg" =~ ^[a-zA-Z0-9.-]+$ ]] || \
       [[ "$arg" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

# Function to validate target format
validate_target() {
    local target="$1"
    
    # Basic validation - check if it looks like a valid target
    if [[ -z "$target" ]]; then
        echo "Error: No target specified"
        return 1
    fi
    
    # Check for obviously invalid characters that could indicate command injection
    if [[ "$target" =~ [';|&`$(){}] ]]; then
        echo "Error: Invalid characters in target specification"
        return 1
    fi
    
    return 0
}

# Function to set up output file naming with timestamp
setup_output_files() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local target_clean=$(echo "$1" | sed 's/[^a-zA-Z0-9._-]/_/g')
    
    # Update output file names to include timestamp and target
    export OUTPUT_PREFIX="nmap_${target_clean}_${timestamp}"
}

# Main execution logic
main() {
    # Handle help requests
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]] || [[ $# -eq 0 ]]; then
        show_usage
        exit 0
    fi
    
    # Check if only a target is provided (use default scan)
    if [[ $# -eq 1 ]] && is_target_only "$1"; then
        local target="$1"
        
        # Validate target
        if ! validate_target "$target"; then
            exit 1
        fi
        
        # Set up output files
        setup_output_files "$target"
        
        echo "Running default nmap scan against: $target"
        echo "Scan options: $DEFAULT_NMAP_ARGS"
        echo "Output files will be prefixed with: $OUTPUT_PREFIX"
        echo ""
        
        # Execute nmap with default arguments
        # Replace -oA scan_tcp with our dynamic output prefix
        local modified_args=$(echo "$DEFAULT_NMAP_ARGS" | sed "s/-oA scan_tcp/-oA $OUTPUT_PREFIX/")
        
        # Execute the scan
        exec nmap $modified_args "$target"
        
    else
        # Custom arguments provided - pass them directly to nmap
        echo "Running custom nmap scan with provided arguments"
        echo "Arguments: $*"
        echo ""
        
        # Basic validation of arguments
        for arg in "$@"; do
            if [[ "$arg" =~ [';|&`] ]]; then
                echo "Error: Potentially unsafe characters detected in arguments"
                exit 1
            fi
        done
        
        # Execute nmap with custom arguments
        exec nmap "$@"
    fi
}

# Ensure we're running as the correct user
if [[ "$(id -u)" -eq 0 ]]; then
    echo "Warning: Running as root. Consider using --user flag with docker run."
fi

# Create timestamp for logging
echo "Nmap scan started at: $(date)"
echo "Working directory: $(pwd)"
echo "User: $(whoami)"
echo ""

# Execute main function with all arguments
main "$@"