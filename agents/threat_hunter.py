import json
from autogen import AssistantAgent, UserProxyAgent
from config.settings import LLM_CONFIG
from utils.logger import logger
from utils.helpers import format_timestamp, severity_color


class ThreatHunterAgent:
    def __init__(self):
        self.agent = autogen.AssistantAgent(
            name="ThreatHunter",
            system_message="""You are an elite cybersecurity threat hunter with 10+ years experience.
Your job is to:
1. Correlate all evidence from log analysis, classification and IOC enrichment
2. Hunt for hidden attack patterns not immediately obvious
3. Identify lateral movement, persistence mechanisms, or data exfiltration attempts
4. Find relationships between indicators (same attacker, campaign, etc.)
5. Predict the attacker's next likely move
6. Recommend a full investigation scope

Always respond with valid JSON only. No extra text.""",
            llm_config=LLM_CONFIG,
        )

        self.user_proxy = autogen.UserProxyAgent(
            name="ThreatHunterProxy",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
            code_execution_config=False,
        )

    def hunt(self, log_analysis: dict, classification: dict, enrichment: dict) -> dict:
        logger.info("ThreatHunter: Starting deep threat hunting investigation...")

        prompt = f"""Perform a deep threat hunting investigation using all available evidence:

LOG ANALYSIS:
{json.dumps(log_analysis, indent=2)}

THREAT CLASSIFICATION:
{json.dumps(classification, indent=2)}

IOC ENRICHMENT:
{json.dumps(enrichment, indent=2)}

Return JSON with this exact structure:
{{
  "hunting_findings": {{
    "attack_stage": "<reconnaissance|initial_access|execution|persistence|lateral_movement|exfiltration|impact>",
    "kill_chain_position": "<which stage of cyber kill chain>",
    "hidden_patterns": [
      "<pattern 1>",
      "<pattern 2>"
    ],
    "lateral_movement_detected": <true|false>,
    "persistence_mechanism": "<detected persistence or none>",
    "data_exfiltration_risk": "<none|low|medium|high>"
  }},
  "attacker_profile": {{
    "sophistication_level": "<script_kiddie|intermediate|advanced|nation_state>",
    "likely_motivation": "<financial|espionage|disruption|hacktivism>",
    "campaign_indicators": "<signs this is part of larger campaign or isolated>",
    "predicted_next_move": "<what attacker will likely do next>"
  }},
  "correlated_indicators": [
    {{
      "indicator": "<ip, hash, or domain>",
      "correlation": "<how it relates to other indicators>"
    }}
  ],
  "investigation_scope": {{
    "systems_to_investigate": ["<system 1>", "<system 2>"],
    "logs_to_review": ["<log type 1>", "<log type 2>"],
    "timeframe": "<how far back to investigate>"
  }},
  "hunter_confidence": "<low|medium|high>",
  "critical_findings": "<most important finding in 2 sentences>",
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
            attack_stage = result.get("hunting_findings", {}).get("attack_stage", "unknown")
            confidence = result.get("hunter_confidence", "unknown")
            logger.info(f"ThreatHunter: Attack stage → {attack_stage.upper()} | Confidence → {confidence}")
            return result
        except Exception as e:
            logger.error(f"ThreatHunter: Failed to parse response → {e}")
            return {
                "hunting_findings": {
                    "attack_stage": "unknown",
                    "kill_chain_position": "unknown",
                    "hidden_patterns": ["Manual investigation required"],
                    "lateral_movement_detected": False,
                    "persistence_mechanism": "unknown",
                    "data_exfiltration_risk": "medium"
                },
                "attacker_profile": {
                    "sophistication_level": "unknown",
                    "likely_motivation": "unknown",
                    "campaign_indicators": "Insufficient data for profiling",
                    "predicted_next_move": "Monitor for further activity"
                },
                "correlated_indicators": [],
                "investigation_scope": {
                    "systems_to_investigate": ["All affected systems"],
                    "logs_to_review": ["System logs", "Network logs", "Auth logs"],
                    "timeframe": "Last 7 days"
                },
                "hunter_confidence": "low",
                "critical_findings": "Threat hunting completed with parsing issues. Manual review strongly recommended.",
                "timestamp": format_timestamp()
            }