import json
import autogen
from config.settings import LLM_CONFIG
from utils.logger import logger
from utils.helpers import format_timestamp, severity_color


class AutoResponderAgent:
    def __init__(self):
        self.agent = autogen.AssistantAgent(
            name="AutoResponder",
            system_message="""You are an automated cybersecurity incident responder.
Your job is to:
1. Review all threat findings and decide on automated response actions
2. Prioritize actions by urgency and impact
3. Distinguish between actions that can be automated vs need human approval
4. Generate specific, actionable response steps with clear commands
5. Ensure response is proportional to threat severity
6. Define rollback steps in case response causes issues

Always respond with valid JSON only. No extra text.""",
            llm_config=LLM_CONFIG,
        )

        self.user_proxy = autogen.UserProxyAgent(
            name="AutoResponderProxy",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
            code_execution_config=False,
        )

    def _simulate_block_ip(self, ip: str) -> dict:
        logger.warning(f"AutoResponder: [SIMULATED] Blocking IP → {ip}")
        return {
            "action": "block_ip",
            "target": ip,
            "status": "simulated",
            "command": f"iptables -A INPUT -s {ip} -j DROP",
            "note": "Simulated — in production this runs on your firewall"
        }

    def _simulate_kill_session(self, user: str) -> dict:
        logger.warning(f"AutoResponder: [SIMULATED] Killing session for user → {user}")
        return {
            "action": "kill_session",
            "target": user,
            "status": "simulated",
            "command": f"pkill -u {user}",
            "note": "Simulated — in production this runs on your server"
        }

    def _simulate_isolate_host(self, host: str) -> dict:
        logger.warning(f"AutoResponder: [SIMULATED] Isolating host → {host}")
        return {
            "action": "isolate_host",
            "target": host,
            "status": "simulated",
            "command": f"iptables -I INPUT -s {host} -j DROP && iptables -I OUTPUT -d {host} -j DROP",
            "note": "Simulated — in production this runs on your network"
        }

    def respond(
        self,
        log_analysis: dict,
        classification: dict,
        enrichment: dict,
        hunting: dict
    ) -> dict:
        logger.info("AutoResponder: Determining automated response actions...")

        severity = classification.get("severity", {}).get("level", "medium")
        requires_immediate = classification.get("requires_immediate_action", False)
        high_risk = enrichment.get("high_risk_indicators", [])
        ips = log_analysis.get("indicators", {}).get("ips", [])

        executed_actions = []

        if severity in ["high", "critical"] and requires_immediate:
            for ip in ips[:3]:
                action = self._simulate_block_ip(ip)
                executed_actions.append(action)

        if hunting.get("hunting_findings", {}).get("lateral_movement_detected", False):
            dest_ip = log_analysis.get("indicators", {}).get("ips", ["unknown"])[0]
            action = self._simulate_isolate_host(dest_ip)
            executed_actions.append(action)

        prompt = f"""Based on all threat findings, generate a complete automated response plan:

SEVERITY: {severity}
REQUIRES IMMEDIATE ACTION: {requires_immediate}
HIGH RISK INDICATORS: {json.dumps(high_risk, indent=2)}

LOG ANALYSIS SUMMARY:
{json.dumps(log_analysis.get("summary", ""), indent=2)}

CLASSIFICATION:
{json.dumps(classification.get("threat_classification", {}), indent=2)}

HUNTING FINDINGS:
{json.dumps(hunting.get("hunting_findings", {}), indent=2)}

ALREADY EXECUTED ACTIONS:
{json.dumps(executed_actions, indent=2)}

Return JSON with this exact structure:
{{
  "response_plan": {{
    "immediate_actions": [
      {{
        "action": "<action name>",
        "priority": "<1-5, 1 being highest>",
        "automated": <true|false>,
        "command": "<specific command or step>",
        "reason": "<why this action>"
      }}
    ],
    "short_term_actions": [
      {{
        "action": "<action name>",
        "timeframe": "<within X hours>",
        "owner": "<security_team|sysadmin|management>",
        "details": "<what needs to be done>"
      }}
    ],
    "long_term_recommendations": [
      "<recommendation 1>",
      "<recommendation 2>",
      "<recommendation 3>"
    ]
  }},
  "containment_status": "<not_contained|partially_contained|contained>",
  "escalation_required": <true|false>,
  "escalation_reason": "<why escalation is needed or none>",
  "executed_actions": {json.dumps(executed_actions)},
  "response_summary": "<2 sentence summary of response taken>",
  "rollback_steps": [
    "<rollback step 1>",
    "<rollback step 2>"
  ],
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
            containment = result.get("containment_status", "unknown")
            escalation = result.get("escalation_required", False)
            logger.info(f"AutoResponder: Containment → {containment.upper()} | Escalation needed → {escalation}")
            return result
        except Exception as e:
            logger.error(f"AutoResponder: Failed to parse response → {e}")
            return {
                "response_plan": {
                    "immediate_actions": [],
                    "short_term_actions": [],
                    "long_term_recommendations": [
                        "Review security policies",
                        "Update firewall rules",
                        "Conduct security audit"
                    ]
                },
                "containment_status": "not_contained",
                "escalation_required": True,
                "escalation_reason": "Automated response failed — manual intervention required",
                "executed_actions": executed_actions,
                "response_summary": "Automated response encountered issues. Immediate manual review required.",
                "rollback_steps": ["Review all changes manually"],
                "timestamp": format_timestamp()
            }