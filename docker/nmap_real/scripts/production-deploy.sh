#!/bin/bash

# Production Deployment Script for Nmap Scanner
# Handles production deployment with health checks, rollback capability, and monitoring

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILES=("-f" "${PROJECT_DIR}/docker-compose.yml" "-f" "${PROJECT_DIR}/docker-compose.prod.yml")
SERVICES=("nmap-scanner" "nmap-quick" "nmap-deep" "prometheus" "grafana" "loki")
HEALTH_CHECK_TIMEOUT=300
MAX_ROLLBACK_ATTEMPTS=3

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${CYAN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking deployment prerequisites..."
    
    # Check Docker and Docker Compose
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available"
        exit 1
    fi
    
    # Check if running as appropriate user (not root in production)
    if [[ $EUID -eq 0 ]] && [[ "${ALLOW_ROOT:-0}" != "1" ]]; then
        log_error "Running as root is not recommended for production deployment"
        log_info "Set ALLOW_ROOT=1 to override this check"
        exit 1
    fi
    
    # Check required files
    local required_files=(
        "${PROJECT_DIR}/docker-compose.yml"
        "${PROJECT_DIR}/docker-compose.prod.yml"
        "${PROJECT_DIR}/Dockerfile"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "Required file not found: $file"
            exit 1
        fi
    done
    
    # Check disk space
    local available_space
    available_space=$(df "${PROJECT_DIR}" | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 1048576 ]]; then  # Less than 1GB
        log_warning "Low disk space available: $(($available_space / 1024))MB"
    fi
    
    log_success "Prerequisites check completed"
}

# Function to backup current state
backup_current_state() {
    log_info "Creating backup of current deployment state..."
    
    local backup_dir="${PROJECT_DIR}/backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup configuration files
    cp "${PROJECT_DIR}/docker-compose.yml" "$backup_dir/"
    cp "${PROJECT_DIR}/docker-compose.prod.yml" "$backup_dir/"
    
    # Export current container states
    if docker compose "${COMPOSE_FILES[@]}" ps --format json > "$backup_dir/containers_state.json" 2>/dev/null; then
        log_info "Container state backed up"
    fi
    
    # Backup volumes if they exist
    if docker volume ls --format "{{.Name}}" | grep -q "nmap_"; then
        log_info "Creating volume backup..."
        docker run --rm \
            -v nmap_prometheus_data:/data \
            -v "$backup_dir:/backup" \
            alpine tar czf /backup/prometheus_data.tar.gz -C /data . 2>/dev/null || log_warning "Prometheus volume backup failed"
    fi
    
    echo "$backup_dir" > "${PROJECT_DIR}/.last_backup"
    log_success "Backup created: $backup_dir"
}

# Function to validate configuration
validate_configuration() {
    log_info "Validating configuration files..."
    
    # Validate docker-compose files
    if ! docker compose "${COMPOSE_FILES[@]}" config > /dev/null; then
        log_error "Docker Compose configuration is invalid"
        exit 1
    fi
    
    # Check for required environment variables
    local required_vars=("TZ")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_warning "Environment variable $var is not set"
        fi
    done
    
    log_success "Configuration validation completed"
}

# Function to pull latest images
pull_images() {
    log_info "Pulling latest container images..."
    
    # Pull images with retry logic
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if docker compose "${COMPOSE_FILES[@]}" pull; then
            log_success "Images pulled successfully"
            return 0
        else
            log_warning "Image pull attempt $attempt failed"
            if [[ $attempt -eq $max_attempts ]]; then
                log_error "Failed to pull images after $max_attempts attempts"
                exit 1
            fi
            ((attempt++))
            sleep 10
        fi
    done
}

# Function to deploy services with rolling update
deploy_services() {
    log_info "Starting rolling deployment..."
    
    # Deploy monitoring services first
    local monitoring_services=("prometheus" "loki" "grafana")
    for service in "${monitoring_services[@]}"; do
        log_info "Deploying monitoring service: $service"
        docker compose "${COMPOSE_FILES[@]}" up -d "$service"
        
        # Wait for service to be healthy
        wait_for_service_health "$service" 60
    done
    
    # Deploy nmap services
    local nmap_services=("nmap-scanner" "nmap-quick" "nmap-deep")
    for service in "${nmap_services[@]}"; do
        log_info "Deploying nmap service: $service"
        docker compose "${COMPOSE_FILES[@]}" up -d "$service" --force-recreate
        
        # Wait for service to be ready
        wait_for_service_health "$service" 30
    done
    
    log_success "Rolling deployment completed"
}

# Function to wait for service health
wait_for_service_health() {
    local service_name="$1"
    local timeout="${2:-60}"
    local elapsed=0
    
    log_info "Waiting for service $service_name to be healthy (timeout: ${timeout}s)..."
    
    while [[ $elapsed -lt $timeout ]]; do
        # Check if container is running
        if docker compose "${COMPOSE_FILES[@]}" ps "$service_name" --format json | jq -r '.[0].State' | grep -q "running"; then
            # Check health status if health check is configured
            local health_status
            health_status=$(docker compose "${COMPOSE_FILES[@]}" ps "$service_name" --format json | jq -r '.[0].Health // "healthy"')
            
            if [[ "$health_status" == "healthy" ]]; then
                log_success "Service $service_name is healthy"
                return 0
            fi
        fi
        
        sleep 5
        ((elapsed += 5))
        echo -n "."
    done
    
    echo ""
    log_error "Service $service_name failed to become healthy within ${timeout}s"
    return 1
}

# Function to run post-deployment tests
run_post_deployment_tests() {
    log_info "Running post-deployment tests..."
    
    local tests_passed=0
    local total_tests=0
    
    # Test 1: Check if nmap scanner responds to version command
    ((total_tests++))
    if docker compose "${COMPOSE_FILES[@]}" exec -T nmap-scanner nmap --version > /dev/null 2>&1; then
        log_success "Test 1 PASSED: Nmap scanner version check"
        ((tests_passed++))
    else
        log_error "Test 1 FAILED: Nmap scanner version check"
    fi
    
    # Test 2: Check if Prometheus is accessible
    ((total_tests++))
    if curl -sf http://localhost:9090/-/healthy > /dev/null 2>&1; then
        log_success "Test 2 PASSED: Prometheus health check"
        ((tests_passed++))
    else
        log_error "Test 2 FAILED: Prometheus health check"
    fi
    
    # Test 3: Check if Grafana is accessible
    ((total_tests++))
    if curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
        log_success "Test 3 PASSED: Grafana health check"
        ((tests_passed++))
    else
        log_error "Test 3 FAILED: Grafana health check"
    fi
    
    # Test 4: Check if Loki is accessible
    ((total_tests++))
    if curl -sf http://localhost:3100/ready > /dev/null 2>&1; then
        log_success "Test 4 PASSED: Loki health check"
        ((tests_passed++))
    else
        log_error "Test 4 FAILED: Loki health check"
    fi
    
    log_info "Post-deployment tests completed: $tests_passed/$total_tests passed"
    
    if [[ $tests_passed -eq $total_tests ]]; then
        log_success "All post-deployment tests passed"
        return 0
    else
        log_error "Some post-deployment tests failed"
        return 1
    fi
}

# Function to rollback deployment
rollback_deployment() {
    log_warning "Initiating deployment rollback..."
    
    if [[ ! -f "${PROJECT_DIR}/.last_backup" ]]; then
        log_error "No backup information found for rollback"
        exit 1
    fi
    
    local backup_dir
    backup_dir=$(cat "${PROJECT_DIR}/.last_backup")
    
    if [[ ! -d "$backup_dir" ]]; then
        log_error "Backup directory not found: $backup_dir"
        exit 1
    fi
    
    # Stop current services
    log_info "Stopping current services..."
    docker compose "${COMPOSE_FILES[@]}" down
    
    # Restore configuration files
    log_info "Restoring configuration files..."
    cp "$backup_dir/docker-compose.yml" "${PROJECT_DIR}/"
    cp "$backup_dir/docker-compose.prod.yml" "${PROJECT_DIR}/"
    
    # Restore volumes if backup exists
    if [[ -f "$backup_dir/prometheus_data.tar.gz" ]]; then
        log_info "Restoring volume data..."
        docker run --rm \
            -v nmap_prometheus_data:/data \
            -v "$backup_dir:/backup" \
            alpine sh -c "cd /data && tar xzf /backup/prometheus_data.tar.gz" || log_warning "Volume restore failed"
    fi
    
    # Start services with restored configuration
    log_info "Starting services with restored configuration..."
    docker compose "${COMPOSE_FILES[@]}" up -d
    
    log_success "Rollback completed"
}

# Function to show deployment status
show_deployment_status() {
    log_info "Current deployment status:"
    echo ""
    
    # Show service status
    docker compose "${COMPOSE_FILES[@]}" ps
    echo ""
    
    # Show resource usage
    echo "=== Resource Usage ==="
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.PIDs}}"
    echo ""
    
    # Show network information
    echo "=== Network Information ==="
    docker network ls --filter name=nmap
    echo ""
    
    # Show volume information
    echo "=== Volume Information ==="
    docker volume ls --filter name=nmap
    echo ""
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Production deployment script for nmap scanner containers.

COMMANDS:
    deploy      Deploy services to production (default)
    rollback    Rollback to previous deployment
    status      Show current deployment status
    test        Run post-deployment tests only
    cleanup     Clean up old images and containers

OPTIONS:
    --skip-backup       Skip backup creation
    --skip-tests        Skip post-deployment tests
    --allow-root        Allow running as root user
    --timeout SECONDS   Health check timeout (default: 300)
    --help              Show this help message

ENVIRONMENT VARIABLES:
    ALLOW_ROOT         Set to 1 to allow running as root
    TZ                 Timezone setting
    REGISTRY           Container registry URL

EXAMPLES:
    $0 deploy                    # Full production deployment
    $0 deploy --skip-tests       # Deploy without running tests
    $0 rollback                  # Rollback to previous version
    $0 status                    # Show current status
    
EOF
}

# Main execution
main() {
    local command="deploy"
    local skip_backup=0
    local skip_tests=0
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            deploy|rollback|status|test|cleanup)
                command="$1"
                shift
                ;;
            --skip-backup)
                skip_backup=1
                shift
                ;;
            --skip-tests)
                skip_tests=1
                shift
                ;;
            --allow-root)
                export ALLOW_ROOT=1
                shift
                ;;
            --timeout)
                HEALTH_CHECK_TIMEOUT="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "Starting production deployment script"
    log_info "Command: $command"
    log_info "Project directory: $PROJECT_DIR"
    
    case $command in
        deploy)
            check_prerequisites
            validate_configuration
            
            if [[ $skip_backup -eq 0 ]]; then
                backup_current_state
            fi
            
            pull_images
            deploy_services
            
            if [[ $skip_tests -eq 0 ]]; then
                if ! run_post_deployment_tests; then
                    log_error "Post-deployment tests failed"
                    if [[ $skip_backup -eq 0 ]]; then
                        log_info "Rolling back deployment..."
                        rollback_deployment
                    fi
                    exit 1
                fi
            fi
            
            log_success "Production deployment completed successfully!"
            show_deployment_status
            ;;
            
        rollback)
            rollback_deployment
            ;;
            
        status)
            show_deployment_status
            ;;
            
        test)
            run_post_deployment_tests
            ;;
            
        cleanup)
            log_info "Cleaning up unused Docker resources..."
            docker system prune -f
            docker image prune -f
            log_success "Cleanup completed"
            ;;
            
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"