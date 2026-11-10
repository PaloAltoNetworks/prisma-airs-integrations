#!/bin/bash

# Unified test runner for all API types supported by AIRS v3 fragment
# Runs tests for MCP, OpenAI, Anthropic, and Azure AI Foundry Claude

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Parse options
TRACE_MODE=false
VERBOSE=false
TEST_SUITE="quick"  # quick, full, security

while [[ $# -gt 0 ]]; do
    case $1 in
        --trace)
            TRACE_MODE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        quick|full|security)
            TEST_SUITE="$1"
            shift
            ;;
        *)
            echo "Usage: $0 [--trace] [--verbose] [quick|full|security]"
            echo
            echo "Test Suites:"
            echo "  quick    - Simple tests for each API (default)"
            echo "  full     - All tests including DLP and malicious content"
            echo "  security - Only security tests (DLP, malicious, injection)"
            exit 1
            ;;
    esac
done

# Build test options
TEST_OPTS=""
if [ "$TRACE_MODE" = true ]; then
    TEST_OPTS="$TEST_OPTS --trace"
fi
if [ "$VERBOSE" = true ]; then
    TEST_OPTS="$TEST_OPTS --verbose"
fi

# Results tracking (bash 3.2 compatible)
RESULTS_FILE=$(mktemp)
trap "rm -f $RESULTS_FILE" EXIT
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test
run_test() {
    local api_name="$1"
    local script="$2"
    local test_type="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Testing: $api_name - $test_type${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if "$SCRIPT_DIR/$script" $TEST_OPTS "$test_type"; then
        echo "✅ PASS|$api_name-$test_type" >> "$RESULTS_FILE"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "❌ FAIL|$api_name-$test_type" >> "$RESULTS_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Print header
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           AIRS v3 Unified Fragment - Test Suite              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${YELLOW}Test Suite: $TEST_SUITE${NC}"
if [ "$TRACE_MODE" = true ]; then
    echo -e "${YELLOW}Trace Mode: Enabled${NC}"
fi
echo

# Determine which tests to run based on suite
case "$TEST_SUITE" in
    quick)
        TESTS_TO_RUN=("simple")
        ;;
    full)
        TESTS_TO_RUN=("simple" "dlp" "malicious" "injection")
        ;;
    security)
        TESTS_TO_RUN=("dlp" "malicious" "injection")
        ;;
esac

# Run tests for each API type
for test_type in "${TESTS_TO_RUN[@]}"; do
    # MCP Tests
    if [ -f "$SCRIPT_DIR/test-mcp.sh" ]; then
        if [ "$test_type" = "simple" ]; then
            # MCP uses different test names
            run_test "MCP" "test-mcp.sh" "list"
        elif [ "$test_type" = "dlp" ]; then
            # MCP DLP test uses the dlp command
            run_test "MCP" "test-mcp.sh" "dlp"
        elif [ "$test_type" = "malicious" ]; then
            run_test "MCP" "test-mcp.sh" "malicious"
        fi
    fi

    # OpenAI Tests
    if [ -f "$SCRIPT_DIR/test-openai.sh" ]; then
        run_test "OpenAI" "test-openai.sh" "$test_type"
    fi

    # Anthropic Tests
    if [ -f "$SCRIPT_DIR/test-anthropic.sh" ]; then
        run_test "Anthropic" "test-anthropic.sh" "$test_type"
    fi

    # Azure AI Foundry Claude Tests (/v1/messages)
    if [ -f "$SCRIPT_DIR/test-foundry-claude.sh" ]; then
        run_test "Foundry-Claude" "test-foundry-claude.sh" "$test_type"
    fi

    # Azure AI Foundry GPT Tests (/openai/v1/responses)
    if [ -f "$SCRIPT_DIR/test-foundry-gpt.sh" ]; then
        run_test "Foundry-GPT" "test-foundry-gpt.sh" "$test_type"
    fi
done

# Print results
echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                       Test Results                            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo

if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
    while IFS='|' read -r result test_name; do
        echo -e "  ${result}  $test_name"
    done < "$RESULTS_FILE"
fi

echo
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Total Tests: $TOTAL_TESTS"
echo -e "  ${GREEN}Passed: $PASSED_TESTS${NC}"
if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "  ${RED}Failed: $FAILED_TESTS${NC}"
else
    echo -e "  Failed: 0"
fi
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    exit 1
fi
