#!/bin/bash

# Entrypoint script for nmap container
# Handles default arguments, performance optimization, and allows customization

set -euo pipefail

# Performance and resource optimization
export NMAP_PRIVILEGED=${NMAP_PRIVILEGED:-0}
export NMAP_TEMP_DIR=${NMAP_TEMP_DIR:-/tmp/nmap-temp}

# Optimize memory usage for container environment
ulimit -n 65536  # Increase file descriptor limit for large scans
ulimit -u 4096   # Reasonable process limit

# Default nmap arguments optimized for containerized environment
DEFAULT_NMAP_ARGS="-Pn -sC -sV -oA scan_tcp -v --reason -T4 -p- --max-retries=1 --host-timeout=30m"

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
    local dangerous_patterns=(
        '\$\(' '\`' '&&' '\|\|' ';' '>' '<' 
        'rm' 'wget' 'curl' 'nc' 'bash' 'sh'
        '../' '/..' '/etc/' '/proc/' '/sys/'
        'sudo' 'su' 'chmod' 'chown'
    )
    
    for pattern in "${dangerous_patterns[@]}"; do
        if [[ "$target" =~ $pattern ]]; then
            echo "Error: Potentially dangerous pattern detected: $pattern"
            return 1
        fi
    done
    
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
        # Check for dangerous characters
        if [[ "$arg" =~ [';|&`$(){}] ]]; then
            echo "Error: Potentially unsafe characters detected in argument: $arg"
            return 1
        fi
        
        # Check for command injection attempts
        if [[ "$arg" =~ (^|[[:space:]])(rm|wget|curl|nc|bash|sh|sudo|su|chmod|chown)([[:space:]]|$) ]]; then
            echo "Error: Dangerous command detected in argument: $arg"
            return 1
        fi
    done
    
    return 0
}

# Function to set up output file naming with timestamp and performance logging
setup_output_files() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local target_clean=$(echo "$1" | sed 's/[^a-zA-Z0-9._-]/_/g')
    
    # Update output file names to include timestamp and target
    export OUTPUT_PREFIX="nmap_${target_clean}_${timestamp}"
    
    # Create performance log file
    export PERF_LOG="/output/${OUTPUT_PREFIX}_performance.log"
    
    # Log system resources at start
    {
        echo "=== Scan Performance Metrics ==="
        echo "Start Time: $(date)"
        echo "Container Hostname: $(hostname)"
        echo "Available Memory: $(free -h | grep '^Mem:' | awk '{print $7}')"
        echo "Available CPU: $(nproc) cores"
        echo "Disk Space: $(df -h /output | tail -1 | awk '{print $4}' | sed 's/G/ GB/')"
        echo "================================"
        echo ""
    } > "$PERF_LOG"
}

# Function to log performance metrics during scan
log_performance_metrics() {
    if [[ -n "${PERF_LOG:-}" ]]; then
        {
            echo "Timestamp: $(date)"
            echo "Memory Usage: $(free -h | grep '^Mem:' | awk '{print $3 "/" $2}')"
            echo "Load Average: $(uptime | awk -F'load average:' '{ print $2 }')"
            echo "Active Connections: $(ss -tuln | wc -l)"
            echo "---"
        } >> "$PERF_LOG" 2>/dev/null &
    fi
}

# Function to optimize nmap arguments based on target and resources
optimize_nmap_args() {
    local target="$1"
    local base_args="$2"
    
    # Detect target size for optimization
    local target_count=1
    if [[ "$target" =~ /[0-9]+$ ]]; then
        local cidr=$(echo "$target" | cut -d'/' -f2)
        target_count=$((2**(32-cidr)))
    fi
    
    # Optimize timing and parallelism based on target size
    if [[ $target_count -gt 1000 ]]; then
        # Large network - use conservative timing
        echo "$base_args" | sed 's/-T4/-T3/g' | sed 's/--max-retries=1/--max-retries=2/g'
    elif [[ $target_count -gt 100 ]]; then
        # Medium network - balanced approach
        echo "$base_args" | sed 's/--host-timeout=30m/--host-timeout=20m/g'
    else
        # Small target - aggressive scanning
        echo "$base_args" | sed 's/-T4/-T5/g' | sed 's/--host-timeout=30m/--host-timeout=10m/g'
    fi
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
        
        # Set up output files and performance monitoring
        setup_output_files "$target"
        
        # Optimize arguments based on target characteristics
        local optimized_args=$(optimize_nmap_args "$target" "$DEFAULT_NMAP_ARGS")
        
        echo "Running optimized nmap scan against: $target"
        echo "Scan options: $optimized_args"
        echo "Output files will be prefixed with: $OUTPUT_PREFIX"
        echo "Performance log: $PERF_LOG"
        echo ""
        
        # Start performance monitoring in background
        (
            while sleep 30; do
                log_performance_metrics
            done
        ) &
        local perf_monitor_pid=$!
        
        # Trap to ensure cleanup on exit
        trap "kill $perf_monitor_pid 2>/dev/null; log_scan_completion" EXIT
        
        # Execute nmap with optimized arguments using secure array handling
        # Replace -oA scan_tcp with our dynamic output prefix
        local modified_args=$(echo "$optimized_args" | sed "s/-oA scan_tcp/-oA $OUTPUT_PREFIX/")
        
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

# Function to log scan completion with metrics
log_scan_completion() {
    if [[ -n "${PERF_LOG:-}" ]]; then
        {
            echo ""
            echo "=== Scan Completion Metrics ==="
            echo "End Time: $(date)"
            echo "Final Memory Usage: $(free -h | grep '^Mem:' | awk '{print $3 "/" $2}')"
            echo "Total Runtime: $SECONDS seconds"
            echo "Output Files Generated:"
            find /output -name "${OUTPUT_PREFIX}*" -type f -exec basename {} \; 2>/dev/null | sort
            echo "==============================="
        } >> "$PERF_LOG" 2>/dev/null
    fi
}

# Ensure proper signal handling and cleanup
cleanup() {
    log_scan_completion
    exit 0
}
trap cleanup SIGTERM SIGINT

# Pre-flight checks and optimizations
echo "=== Nmap Container Runtime Initialization ==="
echo "Container started at: $(date)"
echo "Working directory: $(pwd)"
echo "Running as user: $(whoami) (UID: $(id -u))"
echo "Available memory: $(free -h | grep '^Mem:' | awk '{print $7}')"
echo "Available CPU cores: $(nproc)"

# Ensure we're running as the correct non-root user
if [[ "$(id -u)" -eq 0 ]]; then
    echo "WARNING: Running as root. This reduces security posture."
    echo "Consider using --user flag with docker run."
fi

# Verify nmap installation and capabilities
echo "Nmap version: $(nmap --version 2>/dev/null | head -1 || echo 'ERROR: nmap not found')"

# Initialize temporary directory
if [[ -n "$NMAP_TEMP_DIR" ]] && [[ -d "$NMAP_TEMP_DIR" ]]; then
    echo "Using temporary directory: $NMAP_TEMP_DIR"
else
    echo "WARNING: Temporary directory not properly configured"
fi

echo "=============================================="
echo ""

# Execute main function with all arguments
main "$@"