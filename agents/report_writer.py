import json
from autogen import AssistantAgent, UserProxyAgent
from config.settings import LLM_CONFIG
from utils.logger import logger
from utils.helpers import format_timestamp, save_report


class ReportWriterAgent:
    def __init__(self):
        self.agent = autogen.AssistantAgent(
            name="ReportWriter",
            system_message="""You are a professional cybersecurity incident report writer.
Your job is to:
1. Synthesize all findings from every agent into a clear incident report
2. Write in professional language suitable for both technical and non-technical readers
3. Structure the report clearly with executive summary, technical details and recommendations
4. Assign a unique incident ID
5. Ensure nothing important is missed

Always respond with valid JSON only. No extra text.""",
            llm_config=LLM_CONFIG,
        )

        self.user_proxy = autogen.UserProxyAgent(
            name="ReportWriterProxy",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
            code_execution_config=False,
        )

    def write_report(
        self,
        log_analysis: dict,
        classification: dict,
        enrichment: dict,
        hunting: dict,
        response: dict
    ) -> dict:
        logger.info("ReportWriter: Generating final incident report...")

        prompt = f"""Generate a complete professional cybersecurity incident report:

LOG ANALYSIS:
{json.dumps(log_analysis, indent=2)}

THREAT CLASSIFICATION:
{json.dumps(classification, indent=2)}

IOC ENRICHMENT:
{json.dumps(enrichment, indent=2)}

THREAT HUNTING:
{json.dumps(hunting, indent=2)}

AUTO RESPONSE:
{json.dumps(response, indent=2)}

Return JSON with this exact structure:
{{
  "incident_report": {{
    "incident_id": "<INC-YYYYMMDD-XXXX format>",
    "title": "<descriptive incident title>",
    "classification": "<Critical|High|Medium|Low> Severity Incident",
    "status": "<Open|Contained|Resolved>",
    "detected_at": "<timestamp>",
    "reported_at": "<current timestamp>",

    "executive_summary": "<3-4 sentences explaining what happened, impact and current status in plain English>",

    "technical_details": {{
      "attack_type": "<type of attack>",
      "attack_vector": "<how the attack came in>",
      "affected_systems": ["<system 1>", "<system 2>"],
      "indicators_of_compromise": {{
        "malicious_ips": ["<ip 1>", "<ip 2>"],
        "file_hashes": ["<hash 1>"],
        "domains": ["<domain 1>"]
      }},
      "mitre_attack_mapping": {{
        "tactic": "<tactic>",
        "technique": "<technique>"
      }},
      "timeline": [
        {{
          "time": "<timestamp>",
          "event": "<what happened>"
        }}
      ]
    }},

    "impact_analysis": {{
      "severity_score": <1-10>,
      "systems_affected": <number>,
      "data_at_risk": "<description or none>",
      "business_impact": "<description of business impact>"
    }},

    "response_actions_taken": [
      "<action 1>",
      "<action 2>"
    ],

    "recommendations": {{
      "immediate": ["<rec 1>", "<rec 2>"],
      "short_term": ["<rec 1>", "<rec 2>"],
      "long_term": ["<rec 1>", "<rec 2>"]
    }},

    "lessons_learned": "<what this incident teaches us>",
    "next_review_date": "<date 7 days from now>"
  }}
}}"""

        self.user_proxy.initiate_chat(
            self.agent,
            message=prompt,
            silent=True,
        )

        agent_response = self.user_proxy.last_message()["content"]

        try:
            start = agent_response.find("{")
            end = agent_response.rfind("}") + 1
            result = json.loads(agent_response[start:end])

            report = result.get("incident_report", {})
            incident_id = report.get("incident_id", "INC-UNKNOWN")
            severity = report.get("classification", "Unknown")

            saved_path = save_report(result, f"logs/reports/{incident_id}.json")

            logger.info(f"ReportWriter: Report generated → {incident_id}")
            logger.info(f"ReportWriter: Classification → {severity}")
            logger.info(f"ReportWriter: Saved to → {saved_path}")

            result["saved_path"] = saved_path
            return result

        except Exception as e:
            logger.error(f"ReportWriter: Failed to parse response → {e}")
            fallback = {
                "incident_report": {
                    "incident_id": f"INC-{format_timestamp().replace(' ', '-').replace(':', '')}",
                    "title": "Security Incident — Auto Report",
                    "classification": f"{classification.get('severity', {}).get('level', 'medium').upper()} Severity Incident",
                    "status": "Open",
                    "detected_at": log_analysis.get("timestamp", format_timestamp()),
                    "reported_at": format_timestamp(),
                    "executive_summary": "A security incident was detected and analyzed by the automated threat detection system. Manual review is required due to report generation issues.",
                    "technical_details": {
                        "attack_type": classification.get("threat_classification", {}).get("primary_threat_type", "Unknown"),
                        "attack_vector": "Unknown",
                        "affected_systems": [],
                        "indicators_of_compromise": log_analysis.get("indicators", {}),
                        "mitre_attack_mapping": classification.get("threat_classification", {}).get("mitre_attack", {}),
                        "timeline": []
                    },
                    "impact_analysis": {
                        "severity_score": classification.get("severity", {}).get("score", 5),
                        "systems_affected": 1,
                        "data_at_risk": "Unknown",
                        "business_impact": "Under investigation"
                    },
                    "response_actions_taken": response.get("executed_actions", []),
                    "recommendations": {
                        "immediate": ["Manual review required"],
                        "short_term": ["Update security policies"],
                        "long_term": ["Conduct full security audit"]
                    },
                    "lessons_learned": "Automated report generation failed — improve log quality.",
                    "next_review_date": "7 days from incident"
                }
            }
            saved_path = save_report(fallback)
            fallback["saved_path"] = saved_path
            return fallback