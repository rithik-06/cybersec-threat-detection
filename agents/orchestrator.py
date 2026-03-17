import json
from utils.logger import logger
from utils.helpers import format_timestamp, severity_color
from agents.log_analyzer import LogAnalyzerAgent
from agents.threat_classifier import ThreatClassifierAgent
from agents.ioc_enrichment import IOCEnrichmentAgent
from agents.threat_hunter import ThreatHunterAgent
from agents.auto_responder import AutoResponderAgent
from agents.report_writer import ReportWriterAgent

from utils.helpers import agent_delay
from config.settings import AGENT_DELAY_SECONDS


class OrchestratorAgent:
    def __init__(self):
        logger.info("Orchestrator: Initializing all agents...")
        self.log_analyzer = LogAnalyzerAgent()
        self.threat_classifier = ThreatClassifierAgent()
        self.ioc_enrichment = IOCEnrichmentAgent()
        self.threat_hunter = ThreatHunterAgent()
        self.auto_responder = AutoResponderAgent()
        self.report_writer = ReportWriterAgent()
        logger.info("Orchestrator: All agents ready ✓")

    def _print_pipeline_step(self, step: int, total: int, name: str):
        bar = "█" * step + "░" * (total - step)
        logger.info(f"Pipeline [{bar}] Step {step}/{total} → {name}")

    def run(self, raw_logs: list) -> dict:
        total_steps = 6
        start_time = format_timestamp()

        logger.info("=" * 60)
        logger.info("CYBERSEC THREAT DETECTION — PIPELINE STARTED")
        logger.info(f"Timestamp: {start_time}")
        logger.info(f"Total log entries: {len(raw_logs)}")
        logger.info("=" * 60)

        # Step 1 — Log Analysis
        self._print_pipeline_step(1, total_steps, "Log Analyzer")
        try:
            log_analysis = self.log_analyzer.analyze(raw_logs)
            logger.info(f"Step 1 complete ✓ — {log_analysis.get('total_events', 0)} events analyzed")
        except Exception as e:
            logger.error(f"Step 1 failed → {e}")
            return {"error": "Log analysis failed", "details": str(e)}

        # Step 2 — Threat Classification
        self._print_pipeline_step(2, total_steps, "Threat Classifier")
        try:
            classification = self.threat_classifier.classify(log_analysis)
            severity = classification.get("severity", {}).get("level", "unknown")
            logger.info(f"Step 2 complete ✓ — Severity: {severity_color(severity)}")
        except Exception as e:
            logger.error(f"Step 2 failed → {e}")
            return {"error": "Threat classification failed", "details": str(e)}

        # Step 3 — IOC Enrichment
        self._print_pipeline_step(3, total_steps, "IOC Enrichment")
        try:
            enrichment = self.ioc_enrichment.enrich(log_analysis, classification)
            confirmed = enrichment.get("threat_confirmed", False)
            logger.info(f"Step 3 complete ✓ — Threat confirmed: {confirmed}")
        except Exception as e:
            logger.error(f"Step 3 failed → {e}")
            enrichment = {
                "enrichment_summary": {},
                "high_risk_indicators": [],
                "intelligence_confidence": "low",
                "threat_confirmed": False,
                "enrichment_notes": "Enrichment failed — skipped",
                "timestamp": format_timestamp()
            }
            logger.warning("Step 3 skipped — using fallback enrichment")

        # Step 4 — Threat Hunting
        self._print_pipeline_step(4, total_steps, "Threat Hunter")
        try:
            hunting = self.threat_hunter.hunt(log_analysis, classification, enrichment)
            attack_stage = hunting.get("hunting_findings", {}).get("attack_stage", "unknown")
            logger.info(f"Step 4 complete ✓ — Attack stage: {attack_stage.upper()}")
        except Exception as e:
            logger.error(f"Step 4 failed → {e}")
            return {"error": "Threat hunting failed", "details": str(e)}

        # Step 5 — Auto Response
        self._print_pipeline_step(5, total_steps, "Auto Responder")
        try:
            response = self.auto_responder.respond(
                log_analysis,
                classification,
                enrichment,
                hunting
            )
            containment = response.get("containment_status", "unknown")
            logger.info(f"Step 5 complete ✓ — Containment: {containment.upper()}")
        except Exception as e:
            logger.error(f"Step 5 failed → {e}")
            return {"error": "Auto response failed", "details": str(e)}

        # Step 6 — Report Writing
        self._print_pipeline_step(6, total_steps, "Report Writer")
        try:
            report = self.report_writer.write_report(
                log_analysis,
                classification,
                enrichment,
                hunting,
                response
            )
            incident_id = report.get("incident_report", {}).get("incident_id", "unknown")
            logger.info(f"Step 6 complete ✓ — Report: {incident_id}")
        except Exception as e:
            logger.error(f"Step 6 failed → {e}")
            return {"error": "Report writing failed", "details": str(e)}

        # Final Summary
        end_time = format_timestamp()
        severity_level = classification.get("severity", {}).get("level", "unknown")
        severity_score = classification.get("severity", {}).get("score", 0)

        final_result = {
            "pipeline_status": "completed",
            "incident_id": report.get("incident_report", {}).get("incident_id", "unknown"),
            "started_at": start_time,
            "completed_at": end_time,
            "summary": {
                "total_events_analyzed": log_analysis.get("total_events", 0),
                "threat_type": classification.get("threat_classification", {}).get("primary_threat_type", "unknown"),
                "severity_level": severity_level,
                "severity_score": severity_score,
                "threat_confirmed": enrichment.get("threat_confirmed", False),
                "attack_stage": hunting.get("hunting_findings", {}).get("attack_stage", "unknown"),
                "containment_status": response.get("containment_status", "unknown"),
                "escalation_required": response.get("escalation_required", False),
                "report_saved_at": report.get("saved_path", "unknown")
            },
            "full_results": {
                "log_analysis": log_analysis,
                "classification": classification,
                "enrichment": enrichment,
                "hunting": hunting,
                "response": response,
                "report": report
            }
        }

        logger.info("=" * 60)
        logger.info("PIPELINE COMPLETED SUCCESSFULLY")
        logger.info(f"Incident ID   : {final_result['incident_id']}")
        logger.info(f"Severity      : {severity_color(severity_level)} (Score: {severity_score}/10)")
        logger.info(f"Threat type   : {final_result['summary']['threat_type']}")
        logger.info(f"Containment   : {final_result['summary']['containment_status'].upper()}")
        logger.info(f"Report saved  : {final_result['summary']['report_saved_at']}")
        logger.info("=" * 60)

        return final_result