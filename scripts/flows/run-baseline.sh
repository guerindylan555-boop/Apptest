#!/bin/bash

# Baseline Flow Validation Script
#
# Chains login/unlock/lock flows to validate success criteria before releases.
# This script runs the core MaynDrive flows and verifies they meet the success
# criteria defined in the specification.

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FLOWS_DIR="$PROJECT_ROOT/var/flows"
LOGS_DIR="$PROJECT_ROOT/var/logs/baseline"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$LOGS_DIR/baseline_$TIMESTAMP.log"
TEMP_DIR="$PROJECT_ROOT/var/temp/baseline"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Success criteria (from specification)
EXPECTED_SUCCESS_RATE=95  # 95% success rate
EXPECTED_MAX_TIME=30      # 30 seconds per flow
EXPECTED_MAX_INTERVENTIONS=1  # ≤1 manual intervention per run

# Create necessary directories
mkdir -p "$LOGS_DIR"
mkdir -p "$TEMP_DIR"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Check if required tools are available
check_prerequisites() {
    log "Checking prerequisites..."

    # Check if flow runner is available
    if ! command -v node &> /dev/null; then
        print_status "ERROR" "Node.js is not available"
        exit 1
    fi

    # Check if flows directory exists
    if [ ! -d "$FLOWS_DIR" ]; then
        print_status "ERROR" "Flows directory not found: $FLOWS_DIR"
        exit 1
    fi

    # Check if required flows exist
    local required_flows=("login-flow" "unlock-flow" "lock-flow")
    for flow in "${required_flows[@]}"; do
        if [ ! -f "$FLOWS_DIR/${flow}.yaml" ]; then
            print_status "WARNING" "Flow not found: ${flow}.yaml"
        fi
    done

    print_status "SUCCESS" "Prerequisites check completed"
}

# Run a single flow and capture results
run_flow() {
    local flow_name=$1
    local variables=$2
    local start_time=$(date +%s)

    log "Running flow: $flow_name"
    print_status "INFO" "Executing flow: $flow_name"

    # Create temporary variables file
    local var_file="$TEMP_DIR/${flow_name}_vars.json"
    echo "$variables" > "$var_file"

    # Run the flow using the API
    local response=$(curl -s -X POST \
        http://localhost:3001/api/flows/"$flow_name"/run \
        -H "Content-Type: application/json" \
        -d "$variables" \
        2>&1)

    local end_time=$(date +%s)
    local execution_time=$((end_time - start_time))

    # Extract execution ID from response
    local execution_id=$(echo "$response" | grep -o '"executionId":"[^"]*"' | cut -d'"' -f4)

    if [ -z "$execution_id" ]; then
        print_status "ERROR" "Failed to start flow: $flow_name"
        echo "Response: $response" >> "$LOG_FILE"
        return 1
    fi

    log "Flow started with execution ID: $execution_id"

    # Wait for flow completion and monitor status
    local max_wait=300  # 5 minutes max wait
    local wait_time=0
    local final_status="unknown"

    while [ $wait_time -lt $max_wait ]; do
        sleep 2
        wait_time=$((wait_time + 2))

        # Check execution status
        local status_response=$(curl -s \
            http://localhost:3001/api/flows/"$flow_name"/runs/"$execution_id" \
            2>/dev/null)

        if echo "$status_response" | grep -q '"status":"completed"'; then
            final_status="completed"
            break
        elif echo "$status_response" | grep -q '"status":"failed"'; then
            final_status="failed"
            break
        fi
    done

    if [ "$wait_time" -ge $max_wait ]; then
        final_status="timeout"
    fi

    # Get detailed results
    local results_response=$(curl -s \
        http://localhost:3001/api/flows/"$flow_name"/runs/"$execution_id" \
        2>/dev/null)

    # Extract metrics
    local success=$(echo "$results_response" | grep -o '"success":[^,]*' | cut -d':' -f2)
    local steps_executed=$(echo "$results_response" | grep -o '"stepsExecuted":[^,]*' | cut -d':' -f2)
    local total_steps=$(echo "$results_response" | grep -o '"totalSteps":[^,]*' | cut -d':' -f2)
    local recovery_triggered=$(echo "$results_response" | grep -o '"recoveryTriggered":"[^"]*"' | cut -d'"' -f4)

    # Log results
    log "Flow $flow_name completed:"
    log "  Status: $final_status"
    log "  Success: $success"
    log "  Execution time: ${execution_time}s"
    log "  Steps: $steps_executed/$total_steps"
    log "  Recovery triggered: ${recovery_triggered:-'none'}"

    # Return results as JSON
    cat << EOF
{
  "flow_name": "$flow_name",
  "execution_id": "$execution_id",
  "status": "$final_status",
  "success": $success,
  "execution_time": $execution_time,
  "steps_executed": $steps_executed,
  "total_steps": $total_steps,
  "recovery_triggered": "${recovery_triggered:-none}",
  "start_time": $start_time,
  "end_time": $end_time
}
EOF

    # Cleanup
    rm -f "$var_file"
}

# Run baseline test suite
run_baseline() {
    log "Starting baseline flow validation"
    print_status "INFO" "Running baseline validation with timestamp: $TIMESTAMP"

    local total_flows=0
    local successful_flows=0
    local total_execution_time=0
    local manual_interventions=0
    local results=()

    # Define flow configurations
    declare -A flow_configs
    flow_configs[login-flow]='{"phone": "+1234567890", "password": "test123"}'
    flow_configs[unlock-flow]='{}'
    flow_configs[lock-flow]='{}'

    # Run each flow
    for flow_name in "${!flow_configs[@]}"; do
        if [ -f "$FLOWS_DIR/${flow_name}.yaml" ]; then
            total_flows=$((total_flows + 1))

            local result=$(run_flow "$flow_name" "${flow_configs[$flow_name]}")
            results+=("$result")

            # Parse results
            local success=$(echo "$result" | grep -o '"success":[^,]*' | cut -d':' -f2)
            local execution_time=$(echo "$result" | grep -o '"execution_time":[^,]*' | cut -d':' -f2)
            local recovery_triggered=$(echo "$result" | grep -o '"recovery_triggered":"[^"]*"' | cut -d'"' -f4)

            if [ "$success" = "true" ]; then
                successful_flows=$((successful_flows + 1))
                print_status "SUCCESS" "Flow $flow_name completed successfully"
            else
                print_status "ERROR" "Flow $flow_name failed"
            fi

            total_execution_time=$((total_execution_time + execution_time))

            # Count manual interventions (recovery triggers)
            if [ "$recovery_triggered" != "none" ] && [ "$recovery_triggered" != "" ]; then
                manual_interventions=$((manual_interventions + 1))
            fi

            # Wait between flows
            sleep 5
        else
            print_status "WARNING" "Skipping missing flow: $flow_name"
        fi
    done

    # Calculate metrics
    local success_rate=0
    if [ $total_flows -gt 0 ]; then
        success_rate=$((successful_flows * 100 / total_flows))
    fi

    local avg_execution_time=0
    if [ $total_flows -gt 0 ]; then
        avg_execution_time=$((total_execution_time / total_flows))
    fi

    # Generate report
    generate_report "$success_rate" "$avg_execution_time" "$manual_interventions" "$total_flows" "$successful_flows" "${results[@]}"

    # Evaluate against success criteria
    evaluate_results "$success_rate" "$avg_execution_time" "$manual_interventions"
}

# Generate test report
generate_report() {
    local success_rate=$1
    local avg_execution_time=$2
    local manual_interventions=$3
    local total_flows=$4
    local successful_flows=$5
    shift 5
    local results=("$@")

    local report_file="$LOGS_DIR/baseline_report_$TIMESTAMP.json"

    cat << EOF > "$report_file"
{
  "timestamp": "$(date -Iseconds)",
  "summary": {
    "total_flows": $total_flows,
    "successful_flows": $successful_flows,
    "success_rate": $success_rate,
    "average_execution_time": $avg_execution_time,
    "manual_interventions": $manual_interventions,
    "total_execution_time": $total_execution_time
  },
  "success_criteria": {
    "expected_success_rate": $EXPECTED_SUCCESS_RATE,
    "expected_max_time": $EXPECTED_MAX_TIME,
    "expected_max_interventions": $EXPECTED_MAX_INTERVENTIONS
  },
  "flow_results": [
$(IFS=','; printf '%s\n' "${results[*]}")
  ],
  "log_file": "$LOG_FILE"
}
EOF

    print_status "INFO" "Report generated: $report_file"
}

# Evaluate results against success criteria
evaluate_results() {
    local success_rate=$1
    local avg_execution_time=$2
    local manual_interventions=$3

    log "Evaluating results against success criteria:"
    log "  Success rate: ${success_rate}% (expected: ≥${EXPECTED_SUCCESS_RATE}%)"
    log "  Average execution time: ${avg_execution_time}s (expected: ≤${EXPECTED_MAX_TIME}s)"
    log "  Manual interventions: $manual_interventions (expected: ≤${EXPECTED_MAX_INTERVENTIONS})"

    local overall_success=true

    if [ $success_rate -lt $EXPECTED_SUCCESS_RATE ]; then
        print_status "ERROR" "Success rate below threshold: ${success_rate}% < ${EXPECTED_SUCCESS_RATE}%"
        overall_success=false
    else
        print_status "SUCCESS" "Success rate meets requirement: ${success_rate}% ≥ ${EXPECTED_SUCCESS_RATE}%"
    fi

    if [ $avg_execution_time -gt $EXPECTED_MAX_TIME ]; then
        print_status "ERROR" "Average execution time exceeds limit: ${avg_execution_time}s > ${EXPECTED_MAX_TIME}s"
        overall_success=false
    else
        print_status "SUCCESS" "Execution time meets requirement: ${avg_execution_time}s ≤ ${EXPECTED_MAX_TIME}s"
    fi

    if [ $manual_interventions -gt $EXPECTED_MAX_INTERVENTIONS ]; then
        print_status "ERROR" "Too many manual interventions: $manual_interventions > $EXPECTED_MAX_INTERVENTIONS"
        overall_success=false
    else
        print_status "SUCCESS" "Manual interventions within limit: $manual_interventions ≤ $EXPECTED_MAX_INTERVENTIONS"
    fi

    if [ "$overall_success" = true ]; then
        print_status "SUCCESS" "🎉 Baseline validation PASSED - All success criteria met!"
        log "BASELINE PASSED"
        return 0
    else
        print_status "ERROR" "❌ Baseline validation FAILED - Some success criteria not met"
        log "BASELINE FAILED"
        return 1
    fi
}

# Cleanup function
cleanup() {
    log "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
}

# Main execution
main() {
    print_status "INFO" "Starting MaynDrive Baseline Flow Validation"
    print_status "INFO" "Log file: $LOG_FILE"

    # Set up trap for cleanup
    trap cleanup EXIT

    # Check prerequisites
    check_prerequisites

    # Run baseline tests
    run_baseline

    log "Baseline validation completed"
}

# Parse command line arguments
case "${1:-}" in
    --help|-h)
        echo "MaynDrive Baseline Flow Validation Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --clean        Clean up old log files only"
        echo ""
        echo "This script runs the core MaynDrive flows (login, unlock, lock) and"
        echo "validates they meet the success criteria defined in the specification."
        exit 0
        ;;
    --clean)
        print_status "INFO" "Cleaning up old baseline logs..."
        find "$LOGS_DIR" -name "baseline_*.log" -mtime +7 -delete
        find "$LOGS_DIR" -name "baseline_report_*.json" -mtime +7 -delete
        print_status "SUCCESS" "Cleanup completed"
        exit 0
        ;;
    "")
        # No arguments, run baseline
        main
        ;;
    *)
        print_status "ERROR" "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac