import json
import requests
import autogen
from config.settings import LLM_CONFIG, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, VIRUSTOTAL_BASE_URL, ABUSEIPDB_BASE_URL
from utils.logger import logger
from utils.helpers import format_timestamp


class IOCEnrichmentAgent:
    def __init__(self):
        self.agent = autogen.AssistantAgent(
            name="IOCEnrichment",
            system_message="""You are a threat intelligence expert specializing in IOC enrichment.
Your job is to:
1. Analyze threat intelligence data fetched from VirusTotal and AbuseIPDB
2. Determine if indicators are malicious, suspicious, or clean
3. Provide a confidence score for each indicator
4. Summarize the overall threat intelligence picture

Always respond with valid JSON only. No extra text.""",
            llm_config=LLM_CONFIG,
        )

        self.user_proxy = autogen.UserProxyAgent(
            name="IOCEnrichmentProxy",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
            code_execution_config=False,
        )

    def _check_ip_virustotal(self, ip: str) -> dict:
        try:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.get(
                f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "ip": ip,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "status": "malicious" if stats.get("malicious", 0) > 0 else "clean"
                }
        except Exception as e:
            logger.warning(f"IOCEnrichment: VirusTotal IP check failed for {ip} → {e}")
        return {"source": "virustotal", "ip": ip, "status": "unknown", "error": "API call failed"}

    def _check_ip_abuseipdb(self, ip: str) -> dict:
        try:
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            response = requests.get(
                f"{ABUSEIPDB_BASE_URL}/check",
                headers=headers,
                params=params,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "ip": ip,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "unknown"),
                    "isp": data.get("isp", "unknown"),
                    "status": "malicious" if data.get("abuseConfidenceScore", 0) > 25 else "clean"
                }
        except Exception as e:
            logger.warning(f"IOCEnrichment: AbuseIPDB check failed for {ip} → {e}")
        return {"source": "abuseipdb", "ip": ip, "status": "unknown", "error": "API call failed"}

    def _check_hash_virustotal(self, file_hash: str) -> dict:
        try:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.get(
                f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "hash": file_hash,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "status": "malicious" if stats.get("malicious", 0) > 0 else "clean"
                }
        except Exception as e:
            logger.warning(f"IOCEnrichment: VirusTotal hash check failed for {file_hash} → {e}")
        return {"source": "virustotal", "hash": file_hash, "status": "unknown", "error": "API call failed"}

    def enrich(self, log_analysis: dict, classification: dict) -> dict:
        logger.info("IOCEnrichment: Starting threat intelligence lookups...")

        indicators = log_analysis.get("indicators", {})
        ips = indicators.get("ips", [])
        hashes = indicators.get("hashes", [])

        intel_results = {"ip_results": [], "hash_results": []}

        for ip in ips[:5]:
            logger.info(f"IOCEnrichment: Checking IP {ip}")
            vt_result = self._check_ip_virustotal(ip)
            abuse_result = self._check_ip_abuseipdb(ip)
            intel_results["ip_results"].append({
                "ip": ip,
                "virustotal": vt_result,
                "abuseipdb": abuse_result
            })

        for file_hash in hashes[:3]:
            logger.info(f"IOCEnrichment: Checking hash {file_hash}")
            vt_result = self._check_hash_virustotal(file_hash)
            intel_results["hash_results"].append({
                "hash": file_hash,
                "virustotal": vt_result
            })

        prompt = f"""Analyze this threat intelligence data and provide enrichment summary:

THREAT INTEL RESULTS:
{json.dumps(intel_results, indent=2)}

ORIGINAL CLASSIFICATION:
{json.dumps(classification.get("threat_classification", {}), indent=2)}

Return JSON with this exact structure:
{{
  "enrichment_summary": {{
    "total_indicators_checked": <number>,
    "malicious_indicators": <number>,
    "suspicious_indicators": <number>,
    "clean_indicators": <number>
  }},
  "high_risk_indicators": [
    {{
      "indicator": "<ip or hash>",
      "type": "<ip|hash>",
      "risk_level": "<high|critical>",
      "reason": "<why it is high risk>"
    }}
  ],
  "intelligence_confidence": "<low|medium|high>",
  "threat_confirmed": <true|false>,
  "enrichment_notes": "<2 sentence summary of intel findings>",
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
            confirmed = result.get("threat_confirmed", False)
            confidence = result.get("intelligence_confidence", "unknown")
            logger.info(f"IOCEnrichment: Threat confirmed → {confirmed} | Confidence → {confidence}")
            result["raw_intel"] = intel_results
            return result
        except Exception as e:
            logger.error(f"IOCEnrichment: Failed to parse response → {e}")
            return {
                "enrichment_summary": {
                    "total_indicators_checked": len(ips) + len(hashes),
                    "malicious_indicators": 0,
                    "suspicious_indicators": 0,
                    "clean_indicators": len(ips) + len(hashes)
                },
                "high_risk_indicators": [],
                "intelligence_confidence": "low",
                "threat_confirmed": False,
                "enrichment_notes": "Enrichment completed with parsing issues. Manual review recommended.",
                "raw_intel": intel_results,
                "timestamp": format_timestamp()
            }