import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "llama3-8b-8192")
MAX_TOKENS = int(os.getenv("MAX_TOKENS", 1000))

LLM_CONFIG = {
    "config_list": [
        {
            "model": MODEL_NAME,
            "api_key": GROQ_API_KEY,
            "base_url": "https://api.groq.com/openai/v1",
            "api_type": "openai",
        }
    ],
    "temperature": 0.3,
    "max_tokens": MAX_TOKENS,
}

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

LOG_FILE = "logs/threats.log"
REPORTS_DIR = "logs/reports"