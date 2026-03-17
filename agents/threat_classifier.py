import json
import autogen
from config.settings import LLM_CONFIG
from utils.logger import logger
from utils.helpers import format_timestamp, severity_color


class ThreatClassifierAgent:
    def __init__(self):
        self.agent = autogen.AssistantAgent(
            name="ThreatClassifier",
            system_message="""You are an expert cybersecurity threat classification specialist.
Your job is to:
1. Take normalized log analysis results and classify the threat in detail
2. Identify the attack pattern (brute force, reconnaissance, injection, etc.)
3. Map threats to MITRE ATT&CK framework categories
4. Assign a final severity: low, medium, high, critical
5. Estimate the potential business impact
6. Suggest immediate containment actions

Always respond with valid JSON only. No extra text.""",
            llm_config=LLM_CONFIG,
        )

        self.user_proxy = autogen.UserProxyAgent(
            name="ThreatClassifierProxy",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
            code_execution_config=False,
        )

    def classify(self, log_analysis: dict) -> dict:
        logger.info("ThreatClassifier: Classifying threat...")

        prompt = f"""Classify this security threat in detail based on the log analysis:

LOG ANALYSIS:
{json.dumps(log_analysis, indent=2)}

Return JSON with this exact structure:
{{
  "threat_classification": {{
    "primary_threat_type": "<e.g. Brute Force Attack>",
    "attack_pattern": "<e.g. Credential Stuffing>",
    "mitre_attack": {{
      "tactic": "<e.g. Initial Access>",
      "technique": "<e.g. T1110 - Brute Force>",
      "sub_technique": "<if applicable>"
    }},
    "threat_actor_type": "<e.g. Automated Bot, Human Attacker, Insider Threat>"
  }},
  "severity": {{
    "level": "<low|medium|high|critical>",
    "score": <1-10>,
    "justification": "<why this severity>"
  }},
  "impact_assessment": {{
    "confidentiality": "<none|low|medium|high>",
    "integrity": "<none|low|medium|high>",
    "availability": "<none|low|medium|high>",
    "estimated_business_impact": "<brief description>"
  }},
  "containment_actions": [
    "<action 1>",
    "<action 2>",
    "<action 3>"
  ],
  "requires_immediate_action": <true|false>,
  "timestamp": "<current timestamp>"
}}"""

        self.user_proxy.initiate_chat(
            self.agent,
            message=prompt,
            silent=True,
        )

        response = self.user_proxy.last_message()["content"]

        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            result = json.loads(response[start:end])
            severity = result.get("severity", {}).get("level", "unknown")
            logger.info(f"ThreatClassifier: {severity_color(severity)} — {result['threat_classification']['primary_threat_type']}")
            return result
        except Exception as e:
            logger.error(f"ThreatClassifier: Failed to parse response → {e}")
            return {
                "threat_classification": {
                    "primary_threat_type": "Unknown Threat",
                    "attack_pattern": "Unknown",
                    "mitre_attack": {
                        "tactic": "Unknown",
                        "technique": "Unknown",
                        "sub_technique": "N/A"
                    },
                    "threat_actor_type": "Unknown"
                },
                "severity": {
                    "level": log_analysis.get("initial_severity", "medium"),
                    "score": 5,
                    "justification": "Default classification due to parsing error"
                },
                "impact_assessment": {
                    "confidentiality": "medium",
                    "integrity": "medium",
                    "availability": "low",
                    "estimated_business_impact": "Unknown — manual review required"
                },
                "containment_actions": [
                    "Monitor affected systems",
                    "Review logs manually",
                    "Escalate to security team"
                ],
                "requires_immediate_action": False,
                "timestamp": format_timestamp()
            }