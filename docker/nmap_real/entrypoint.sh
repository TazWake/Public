#!/bin/bash

# Entrypoint script for nmap container
# Handles default arguments and allows customization

set -euo pipefail

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

# Enhanced security validation function
validate_target() {
    local target="$1"
    
    # Basic validation - check if it looks like a valid target
    if [[ -z "$target" ]]; then
        echo "Error: No target specified"
        return 1
    fi
    
    # Strict whitelist approach - only allow safe characters
    if [[ ! "$target" =~ ^[a-zA-Z0-9._/-]+$ ]]; then
        echo "Error: Target contains invalid characters. Only alphanumeric, dots, underscores, hyphens, and forward slashes allowed"
        return 1
    fi
    
    # Additional validation for dangerous patterns
    if [[ "$target" == *".."* ]] || [[ "$target" == *"/etc/"* ]] || [[ "$target" == *"/proc/"* ]] || [[ "$target" == *"/sys/"* ]]; then
        echo "Error: Potentially dangerous path detected in target"
        return 1
    fi
    
    # Validate IP address format if it looks like an IP
    if [[ "$target" =~ ^[0-9] ]]; then
        if ! [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]] && \
           ! [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-[0-9]{1,3}$ ]]; then
            echo "Error: Invalid IP address format"
            return 1
        fi
    fi
    
    return 0
}

# Enhanced argument validation function
validate_nmap_arguments() {
    local -a args=("$@")
    
    for arg in "${args[@]}"; do
        # Check for dangerous characters using explicit comparisons
        if [[ "$arg" == *";"* ]] || [[ "$arg" == *"|"* ]] || [[ "$arg" == *"&"* ]] || [[ "$arg" == *'`'* ]] || [[ "$arg" == *'$('* ]] || [[ "$arg" == *")"* ]] || [[ "$arg" == *"{"* ]] || [[ "$arg" == *"}"* ]]; then
            echo "Error: Potentially unsafe characters detected in argument: $arg"
            return 1
        fi
        
        # Check for dangerous commands
        if [[ "$arg" == "rm" ]] || [[ "$arg" == "wget" ]] || [[ "$arg" == "curl" ]] || [[ "$arg" == "nc" ]] || [[ "$arg" == "bash" ]] || [[ "$arg" == "sh" ]] || [[ "$arg" == "sudo" ]] || [[ "$arg" == "su" ]] || [[ "$arg" == "chmod" ]] || [[ "$arg" == "chown" ]]; then
            echo "Error: Dangerous command detected in argument: $arg"
            return 1
        fi
    done
    
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
    
    # Container startup info
    echo "=== Nmap Container Runtime Initialization ==="
    echo "Container started at: $(date)"
    echo "Working directory: $(pwd)"
    echo "Running as user: $(whoami) (UID: $(id -u))"
    echo "Nmap version: $(nmap --version | head -1)"
    echo ""
    
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
        
        # Execute nmap with default arguments using secure array handling
        # Replace -oA scan_tcp with our dynamic output prefix
        local modified_args=$(echo "$DEFAULT_NMAP_ARGS" | sed "s/-oA scan_tcp/-oA $OUTPUT_PREFIX/")
        
        # Convert arguments to array for secure execution
        local -a nmap_cmd_array=(nmap)
        IFS=' ' read -ra args_array <<< "$modified_args"
        nmap_cmd_array+=("${args_array[@]}")
        nmap_cmd_array+=("$target")
        
        # Execute the scan with performance tracking using secure array expansion
        exec "${nmap_cmd_array[@]}"
        
    else
        # Custom arguments provided - validate and pass them securely to nmap
        echo "Running custom nmap scan with provided arguments"
        echo "Arguments: $*"
        echo ""
        
        # Enhanced validation of all arguments
        if ! validate_nmap_arguments "$@"; then
            exit 1
        fi
        
        # Additional check for targets in arguments
        local last_arg="${!#}"
        if is_target_only "$last_arg"; then
            if ! validate_target "$last_arg"; then
                exit 1
            fi
        fi
        
        # Execute nmap with custom arguments using secure array expansion
        local -a nmap_cmd_array=(nmap)
        nmap_cmd_array+=("$@")
        exec "${nmap_cmd_array[@]}"
    fi
}

# Ensure we're running as the correct user
if [[ "$(id -u)" -eq 0 ]]; then
    echo "Warning: Running as root. Consider using --user flag with docker run."
fi

# Execute main function with all arguments
main "$@"