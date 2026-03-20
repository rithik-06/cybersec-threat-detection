import json
import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn

from utils.logger import logger
from utils.helpers import load_json
from agents.orchestrator import OrchestratorAgent

app = FastAPI(
    title="Cybersec Threat Detection API",
    description="AI-powered multi-agent cybersecurity threat detection system",
    version="1.0.0"
)

app.mount("/static", StaticFiles(directory="static"), name="static")

orchestrator = None


def get_orchestrator():
    global orchestrator
    if orchestrator is None:
        logger.info("API: Initializing orchestrator...")
        orchestrator = OrchestratorAgent()
    return orchestrator


# ── Models ──────────────────────────────────────────────
class LogPayload(BaseModel):
    logs: list
    source: Optional[str] = "api"


class IPCheckPayload(BaseModel):
    ip: str


class HashCheckPayload(BaseModel):
    file_hash: str


# ── Routes ──────────────────────────────────────────────

@app.get("/")
def root():
    return FileResponse("static/index.html")


@app.get("/health")
def health():
    return {
        "status": "online",
        "service": "Cybersec Threat Detection API",
        "version": "1.0.0"
    }


@app.post("/analyze")
async def analyze_logs(payload: LogPayload):
    if not payload.logs:
        raise HTTPException(status_code=400, detail="No logs provided")
    if len(payload.logs) > 50:
        raise HTTPException(status_code=400, detail="Max 50 log entries per request")

    try:
        logger.info(f"API: Received {len(payload.logs)} logs from source: {payload.source}")
        orc = get_orchestrator()
        result = orc.run(payload.logs)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"API: Pipeline failed → {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/file")
async def analyze_log_file(file: UploadFile = File(...)):
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only JSON files are supported")

    try:
        contents = await file.read()
        logs = json.loads(contents)
        if not isinstance(logs, list):
            raise HTTPException(status_code=400, detail="JSON file must contain a list of logs")

        logger.info(f"API: Received file {file.filename} with {len(logs)} logs")
        orc = get_orchestrator()
        result = orc.run(logs)
        return JSONResponse(content=result)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        logger.error(f"API: File analysis failed → {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/check/ip")
async def check_ip(payload: IPCheckPayload):
    if not payload.ip:
        raise HTTPException(status_code=400, detail="No IP provided")

    try:
        from agents.ioc_enrichment import IOCEnrichmentAgent
        agent = IOCEnrichmentAgent()
        vt_result = agent._check_ip_virustotal(payload.ip)
        abuse_result = agent._check_ip_abuseipdb(payload.ip)
        return JSONResponse(content={
            "ip": payload.ip,
            "virustotal": vt_result,
            "abuseipdb": abuse_result,
            "verdict": "malicious" if (
                vt_result.get("status") == "malicious" or
                abuse_result.get("status") == "malicious"
            ) else "clean"
        })
    except Exception as e:
        logger.error(f"API: IP check failed → {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/check/hash")
async def check_hash(payload: HashCheckPayload):
    if not payload.file_hash:
        raise HTTPException(status_code=400, detail="No hash provided")

    try:
        from agents.ioc_enrichment import IOCEnrichmentAgent
        agent = IOCEnrichmentAgent()
        result = agent._check_hash_virustotal(payload.file_hash)
        return JSONResponse(content={
            "hash": payload.file_hash,
            "virustotal": result,
            "verdict": result.get("status", "unknown")
        })
    except Exception as e:
        logger.error(f"API: Hash check failed → {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reports")
def list_reports():
    import os
    reports_dir = "logs/reports"
    try:
        files = [f for f in os.listdir(reports_dir) if f.endswith(".json")]
        files.sort(reverse=True)
        return {"total": len(files), "reports": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reports/{incident_id}")
def get_report(incident_id: str):
    import os
    filepath = f"logs/reports/{incident_id}.json"
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        with open(filepath) as f:
            return JSONResponse(content=json.load(f))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sample-logs")
def get_sample_logs():
    try:
        logs = load_json("data/sample_logs.json")
        return {"logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("api:app", host="0.0.0.0", port=port, reload=False)    