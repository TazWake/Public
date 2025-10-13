#!/bin/bash

# Example usage script for Process Validation Tool
# This script demonstrates various ways to use proc_check.py

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Process Validation Tool - Usage Examples${NC}"
echo "=============================================="

# Check if the script exists
if [[ ! -f "proc_check.py" ]]; then
    echo -e "${RED}Error: proc_check.py not found in current directory${NC}"
    echo "Please run this script from the directory containing proc_check.py"
    exit 1
fi

# Example 1: Basic validation
echo -e "\n${YELLOW}Example 1: Basic Process Validation${NC}"
echo "----------------------------------------"
echo "Running basic process validation..."
python3 proc_check.py

# Example 2: Verbose output
echo -e "\n${YELLOW}Example 2: Verbose Output${NC}"
echo "----------------------------------------"
echo "Running with verbose output..."
python3 proc_check.py --verbose

# Example 3: Logging to file
echo -e "\n${YELLOW}Example 3: Logging to File${NC}"
echo "----------------------------------------"
echo "Running with logging to file..."
python3 proc_check.py --log proc_validation.log
if [[ -f "proc_validation.log" ]]; then
    echo -e "${GREEN}Log file created: proc_validation.log${NC}"
    echo "Last few lines of log:"
    tail -5 proc_validation.log
else
    echo -e "${RED}Log file not created${NC}"
fi

# Example 4: JSON output
echo -e "\n${YELLOW}Example 4: JSON Output${NC}"
echo "----------------------------------------"
echo "Running with JSON output..."
python3 proc_check.py --output proc_results.json
if [[ -f "proc_results.json" ]]; then
    echo -e "${GREEN}JSON file created: proc_results.json${NC}"
    echo "JSON content preview:"
    head -10 proc_results.json
else
    echo -e "${RED}JSON file not created${NC}"
fi

# Example 5: Quiet mode
echo -e "\n${YELLOW}Example 5: Quiet Mode${NC}"
echo "----------------------------------------"
echo "Running in quiet mode..."
python3 proc_check.py --quiet
echo -e "${GREEN}Quiet mode completed${NC}"

# Example 6: Full logging and output
echo -e "\n${YELLOW}Example 6: Full Logging and Output${NC}"
echo "----------------------------------------"
echo "Running with full logging and JSON output..."
python3 proc_check.py --verbose --log full_validation.log --output full_results.json
if [[ -f "full_validation.log" && -f "full_results.json" ]]; then
    echo -e "${GREEN}Full logging completed${NC}"
    echo "Files created:"
    echo "  - full_validation.log"
    echo "  - full_results.json"
else
    echo -e "${RED}Full logging failed${NC}"
fi

# Example 7: Help and version
echo -e "\n${YELLOW}Example 7: Help and Version${NC}"
echo "----------------------------------------"
echo "Displaying help:"
python3 proc_check.py --help | head -20
echo "..."
echo ""
echo "Displaying version:"
python3 proc_check.py --version

# Example 8: Error handling
echo -e "\n${YELLOW}Example 8: Error Handling${NC}"
echo "----------------------------------------"
echo "Testing invalid option:"
python3 proc_check.py --invalid-option 2>/dev/null || echo -e "${GREEN}Invalid option properly rejected${NC}"

echo "Testing conflicting options:"
python3 proc_check.py --quiet --verbose 2>/dev/null || echo -e "${GREEN}Conflicting options properly rejected${NC}"

# Cleanup
echo -e "\n${YELLOW}Cleanup${NC}"
echo "----------------------------------------"
echo "Cleaning up example files..."
rm -f proc_validation.log proc_results.json full_validation.log full_results.json
echo -e "${GREEN}Cleanup completed${NC}"

echo -e "\n${BLUE}All examples completed!${NC}"
echo "=============================================="
echo ""
echo "For more information, run:"
echo "  python3 proc_check.py --help"
echo ""
echo "For detailed documentation, see:"
echo "  proc_check_README.md"
