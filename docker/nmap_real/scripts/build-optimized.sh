#!/bin/bash

# Optimized Docker Build Script for Nmap Scanner
# Implements best practices for build performance and caching

set -euo pipefail

# Configuration
IMAGE_NAME="nmap-scanner"
IMAGE_TAG="${IMAGE_TAG:-latest}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"
BUILD_CONTEXT="${BUILD_CONTEXT:-.}"
REGISTRY="${REGISTRY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check if buildkit is available
    if docker buildx version &> /dev/null; then
        log_info "Docker Buildx is available - enabling advanced features"
        export DOCKER_BUILDKIT=1
        export BUILDX_AVAILABLE=1
    else
        log_warning "Docker Buildx not available - using standard build"
        export BUILDX_AVAILABLE=0
    fi
    
    log_success "Prerequisites check completed"
}

# Function to prepare build environment
prepare_build_env() {
    log_info "Preparing build environment..."
    
    # Create buildx builder if not exists
    if [[ "${BUILDX_AVAILABLE}" == "1" ]]; then
        if ! docker buildx ls | grep -q "nmap-builder"; then
            docker buildx create --name nmap-builder --use || true
        else
            docker buildx use nmap-builder
        fi
    fi
    
    # Clean up previous build artifacts if requested
    if [[ "${CLEAN_BUILD:-0}" == "1" ]]; then
        log_info "Cleaning previous build artifacts..."
        docker system prune -f --filter "label=stage=intermediate" || true
    fi
    
    log_success "Build environment prepared"
}

# Function to build image with optimizations
build_image() {
    log_info "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
    
    local build_args=()
    local cache_args=()
    
    # Add build arguments
    build_args+=(
        "--build-arg" "BUILDKIT_INLINE_CACHE=1"
        "--build-arg" "BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
        "--build-arg" "VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
        "--build-arg" "VERSION=${IMAGE_TAG}"
    )
    
    # Configure caching strategy
    if [[ "${BUILDX_AVAILABLE}" == "1" ]]; then
        # Use registry cache if available
        if [[ -n "${REGISTRY}" ]]; then
            cache_args+=(
                "--cache-from" "type=registry,ref=${REGISTRY}/${IMAGE_NAME}:cache"
                "--cache-to" "type=registry,ref=${REGISTRY}/${IMAGE_NAME}:cache,mode=max"
            )
        else
            # Use local cache
            cache_args+=(
                "--cache-from" "type=local,src=/tmp/.buildx-cache"
                "--cache-to" "type=local,dest=/tmp/.buildx-cache-new,mode=max"
            )
        fi
        
        # Build with buildx
        docker buildx build \
            "${build_args[@]}" \
            "${cache_args[@]}" \
            --platform linux/amd64,linux/arm64 \
            --target production \
            --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
            --load \
            --file "${DOCKERFILE}" \
            "${BUILD_CONTEXT}"
            
        # Update cache
        if [[ "${#cache_args[@]}" -gt 0 ]] && [[ -z "${REGISTRY}" ]]; then
            rm -rf /tmp/.buildx-cache
            mv /tmp/.buildx-cache-new /tmp/.buildx-cache || true
        fi
    else
        # Standard docker build with caching
        docker build \
            "${build_args[@]}" \
            --target production \
            --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
            --file "${DOCKERFILE}" \
            "${BUILD_CONTEXT}"
    fi
    
    log_success "Image built successfully: ${IMAGE_NAME}:${IMAGE_TAG}"
}

# Function to verify image
verify_image() {
    log_info "Verifying built image..."
    
    # Check if image exists
    if ! docker images "${IMAGE_NAME}:${IMAGE_TAG}" --format "table {{.Repository}}:{{.Tag}}" | grep -q "${IMAGE_NAME}:${IMAGE_TAG}"; then
        log_error "Image not found after build"
        exit 1
    fi
    
    # Get image size
    local image_size
    image_size=$(docker images "${IMAGE_NAME}:${IMAGE_TAG}" --format "{{.Size}}")
    log_info "Image size: ${image_size}"
    
    # Run basic functionality test
    log_info "Running basic functionality test..."
    if docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" --version &> /dev/null; then
        log_success "Basic functionality test passed"
    else
        log_error "Basic functionality test failed"
        exit 1
    fi
    
    # Security scan if available
    if command -v trivy &> /dev/null; then
        log_info "Running security scan with Trivy..."
        trivy image --exit-code 1 --severity HIGH,CRITICAL "${IMAGE_NAME}:${IMAGE_TAG}" || {
            log_warning "Security scan found issues - please review"
        }
    else
        log_warning "Trivy not available - skipping security scan"
    fi
    
    log_success "Image verification completed"
}

# Function to tag and push image
push_image() {
    if [[ -n "${REGISTRY}" ]]; then
        log_info "Pushing image to registry: ${REGISTRY}"
        
        # Tag for registry
        docker tag "${IMAGE_NAME}:${IMAGE_TAG}" "${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
        docker tag "${IMAGE_NAME}:${IMAGE_TAG}" "${REGISTRY}/${IMAGE_NAME}:latest"
        
        # Push to registry
        docker push "${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
        docker push "${REGISTRY}/${IMAGE_NAME}:latest"
        
        log_success "Image pushed to registry"
    else
        log_info "No registry specified - skipping push"
    fi
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build optimized Docker image for nmap scanner with advanced caching and verification.

OPTIONS:
    -t, --tag TAG           Image tag (default: latest)
    -r, --registry REGISTRY Registry URL for pushing
    -f, --file DOCKERFILE   Dockerfile path (default: Dockerfile)
    -c, --clean             Clean build (no cache)
    -p, --push              Push to registry after build
    -h, --help              Show this help message

ENVIRONMENT VARIABLES:
    IMAGE_TAG               Image tag override
    REGISTRY               Registry URL override
    CLEAN_BUILD            Set to 1 for clean build
    DOCKERFILE             Dockerfile path override

EXAMPLES:
    $0                      # Basic build with caching
    $0 -t v2.0 -p          # Build with tag and push
    $0 -c -r my-registry.com # Clean build and push to registry
    
EOF
}

# Main execution
main() {
    local push_image_flag=0
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -r|--registry)
                REGISTRY="$2"
                shift 2
                ;;
            -f|--file)
                DOCKERFILE="$2"
                shift 2
                ;;
            -c|--clean)
                CLEAN_BUILD=1
                shift
                ;;
            -p|--push)
                push_image_flag=1
                shift
                ;;
            -h|--help)
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
    
    log_info "Starting optimized Docker build process"
    log_info "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
    log_info "Dockerfile: ${DOCKERFILE}"
    log_info "Build context: ${BUILD_CONTEXT}"
    
    # Execute build pipeline
    check_prerequisites
    prepare_build_env
    build_image
    verify_image
    
    if [[ $push_image_flag -eq 1 ]]; then
        push_image
    fi
    
    log_success "Build process completed successfully!"
    
    # Show final image information
    echo ""
    log_info "Final image information:"
    docker images "${IMAGE_NAME}:${IMAGE_TAG}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
}

# Execute main function with all arguments
main "$@"