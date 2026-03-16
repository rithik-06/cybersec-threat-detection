import json
import autogen
from config.settings import LLM_CONFIG
from utils.logger import logger
from utils.helpers import extract_ips, extract_domains, extract_hashes, format_timestamp


class LogAnalyzerAgent:
    def __init__(self):
        self.agent = autogen.AssistantAgent(
            name="LogAnalyzer",
            system_message="""You are a cybersecurity log analysis expert.
Your job is to:
1. Parse raw security logs and normalize them into structured format
2. Extract key indicators like IPs, domains, file hashes, usernames
3. Identify the type of event (failed_login, port_scan, malware, sql_injection, etc.)
4. Assign an initial severity score: low, medium, high, critical
5. Return a clean structured JSON summary

Always respond with valid JSON only. No extra text.""",
            llm_config=LLM_CONFIG,
        )

        self.user_proxy = autogen.UserProxyAgent(
            name="LogAnalyzerProxy",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
            code_execution_config=False,
        )

    def analyze(self, raw_logs: list) -> dict:
        logger.info(f"LogAnalyzer: Processing {len(raw_logs)} log entries")

        ips, domains, hashes = [], [], []
        for log in raw_logs:
            message = log.get("message", "")
            ips.extend(extract_ips(message))
            domains.extend(extract_domains(message))
            hashes.extend(extract_hashes(message))

        prompt = f"""Analyze these security logs and return a JSON summary:

LOGS:
{json.dumps(raw_logs, indent=2)}

EXTRACTED INDICATORS:
- IPs found: {list(set(ips))}
- Domains found: {list(set(domains))}
- File hashes found: {list(set(hashes))}

Return JSON with this exact structure:
{{
  "total_events": <number>,
  "event_types": [<list of event types found>],
  "indicators": {{
    "ips": [<list of IPs>],
    "domains": [<list of domains>],
    "hashes": [<list of hashes>]
  }},
  "initial_severity": "<low|medium|high|critical>",
  "summary": "<2 sentence summary of what happened>",
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
            result["timestamp"] = format_timestamp()
            logger.info(f"LogAnalyzer: Severity detected → {result.get('initial_severity', 'unknown').upper()}")
            return result
        except Exception as e:
            logger.error(f"LogAnalyzer: Failed to parse response → {e}")
            return {
                "total_events": len(raw_logs),
                "event_types": [log.get("event_type", "unknown") for log in raw_logs],
                "indicators": {"ips": list(set(ips)), "domains": list(set(domains)), "hashes": list(set(hashes))},
                "initial_severity": "medium",
                "summary": "Log analysis completed with parsing issues.",
                "timestamp": format_timestamp(),
            }