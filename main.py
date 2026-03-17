import json
import sys
from utils.logger import logger
from utils.helpers import load_json
from agents.orchestrator import OrchestratorAgent


def run_pipeline(log_source: str = "data/sample_logs.json") -> dict:
    logger.info("Starting Cybersec Threat Detection System...")

    # Load logs
    try:
        raw_logs = load_json(log_source)
        logger.info(f"Loaded {len(raw_logs)} log entries from {log_source}")
    except FileNotFoundError:
        logger.error(f"Log file not found: {log_source}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load logs: {e}")
        sys.exit(1)

    # Run pipeline
    orchestrator = OrchestratorAgent()
    result = orchestrator.run(raw_logs)

    # Print final summary to console
    if result.get("pipeline_status") == "completed":
        summary = result.get("summary", {})
        print("\n")
        print("=" * 60)
        print("         THREAT DETECTION COMPLETE")
        print("=" * 60)
        print(f"  Incident ID    : {result.get('incident_id')}")
        print(f"  Threat Type    : {summary.get('threat_type')}")
        print(f"  Severity       : {summary.get('severity_level', '').upper()} ({summary.get('severity_score')}/10)")
        print(f"  Attack Stage   : {summary.get('attack_stage', '').upper()}")
        print(f"  Confirmed      : {summary.get('threat_confirmed')}")
        print(f"  Containment    : {summary.get('containment_status', '').upper()}")
        print(f"  Escalation     : {summary.get('escalation_required')}")
        print(f"  Report saved   : {summary.get('report_saved_at')}")
        print(f"  Started at     : {result.get('started_at')}")
        print(f"  Completed at   : {result.get('completed_at')}")
        print("=" * 60)
        print("\n")
    else:
        print("\n")
        print("=" * 60)
        print("  PIPELINE FAILED")
        print(f"  Error: {result.get('error')}")
        print(f"  Details: {result.get('details')}")
        print("=" * 60)
        print("\n")

    return result


if __name__ == "__main__":
    # Allow custom log file via command line argument
    # Usage: python3 main.py
    # Usage: python3 main.py data/custom_logs.json
    log_file = sys.argv[1] if len(sys.argv) > 1 else "data/sample_logs.json"
    run_pipeline(log_file)