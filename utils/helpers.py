import json
import re
from datetime import datetime


def extract_ips(text: str) -> list:
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return list(set(re.findall(pattern, text)))


def extract_domains(text: str) -> list:
    pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    return list(set(re.findall(pattern, text)))


def extract_hashes(text: str) -> list:
    md5 = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
    sha256 = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
    return list(set(md5 + sha256))


def format_timestamp(ts: str = None) -> str:
    if ts:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def save_report(report: dict, filename: str = None) -> str:
    import os
    os.makedirs("logs/reports", exist_ok=True)
    if not filename:
        filename = f"logs/reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    return filename


def load_json(filepath: str) -> dict:
    with open(filepath, "r") as f:
        return json.load(f)


def severity_color(severity: str) -> str:
    colors = {
        "critical": "\033[91m",
        "high":     "\033[93m",
        "medium":   "\033[94m",
        "low":      "\033[92m",
    }
    reset = "\033[0m"
    return f"{colors.get(severity.lower(), '')}[{severity.upper()}]{reset}"


import time

def retry_on_rate_limit(func, *args, max_retries=3, delay=10, **kwargs):
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_msg = str(e).lower()
            if "rate limit" in error_msg or "429" in error_msg:
                wait_time = delay * (attempt + 1)
                from utils.logger import logger
                logger.warning(f"Rate limit hit — waiting {wait_time}s before retry {attempt + 1}/{max_retries}")
                time.sleep(wait_time)
            else:
                raise e
    raise Exception(f"Max retries ({max_retries}) exceeded due to rate limiting")


def agent_delay(seconds=3):
    from utils.logger import logger
    logger.info(f"Rate limit guard — waiting {seconds}s before next agent...")
    time.sleep(seconds)