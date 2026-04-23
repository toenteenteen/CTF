import os
import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Acme Device Sync Challenge", version="1.0.0")

FLAG = os.getenv("FLAG", "KPMG{replace_me}")
EXPECTED_DEVICE_ID = os.getenv("EXPECTED_DEVICE_ID", "ws-91ac72ef")
EXPECTED_TENANT = os.getenv("EXPECTED_TENANT", "apac-finance")
EXPECTED_BUILD = os.getenv("EXPECTED_BUILD", "2.4.17")
EXPECTED_PROFILE = os.getenv("EXPECTED_PROFILE", "edge-cache")
EXPECTED_CAMPAIGN = os.getenv("EXPECTED_CAMPAIGN", "crystal-fall")
EXPECTED_USER_AGENT = os.getenv("EXPECTED_USER_AGENT", "AcmeDeviceSync/2.4 (Windows NT 10.0; Win64; x64)")
ARTIFACT_ID = os.getenv("ARTIFACT_ID", "obj-172")
SEED_PART1 = os.getenv("SEED_PART1", "crystal-fall")
SEED_PART2 = os.getenv("SEED_PART2", "apac-finance")
SEED_PART3 = os.getenv("SEED_PART3", "edge-cache")
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "300"))
TIMESTAMP_SKEW_SECONDS = int(os.getenv("TIMESTAMP_SKEW_SECONDS", "60"))

SEED = ":".join([SEED_PART1, SEED_PART2, SEED_PART3])

bootstrapped: Dict[str, datetime] = {}
checked_in: Dict[str, datetime] = {}
outstanding_challenges: Dict[str, dict] = {}
redeemed_artifacts: Dict[str, str] = {}

class CheckinBody(BaseModel):
    profile: str
    operation: str
    campaign: str
    capabilities: list[str]

class RedeemBody(BaseModel):
    nonce: str
    artifact_id: str

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _session_id_from_device(device_id: str) -> Optional[str]:
    prefix = "ws-"
    if not device_id.startswith(prefix):
        return None
    suffix = device_id[len(prefix):]
    if len(suffix) != 8:
        return None
    try:
        int(suffix, 16)
    except ValueError:
        return None
    return suffix

def _access_key(device_id: str) -> bytes:
    session_id = _session_id_from_device(device_id)
    if not session_id:
        raise ValueError("invalid device id")
    return hashlib.sha256(f"{SEED}:{session_id}".encode()).digest()

def _canonical_string(method: str, path: str, device_id: str, tenant: str, timestamp: str, nonce: str) -> str:
    return "\n".join([
        method.upper(),
        path,
        device_id,
        tenant,
        timestamp,
        nonce,
    ])

def _reject(status_code: int, message: str):
    raise HTTPException(status_code=status_code, detail=message)

def _require_common_headers(
    user_agent: Optional[str],
    x_device_id: Optional[str],
    x_tenant: Optional[str],
    x_build: Optional[str],
    x_trace_id: Optional[str],
):
    if user_agent != EXPECTED_USER_AGENT:
        _reject(403, "forbidden")
    if x_device_id != EXPECTED_DEVICE_ID:
        _reject(403, "forbidden")
    if x_tenant != EXPECTED_TENANT:
        _reject(403, "forbidden")
    if x_build != EXPECTED_BUILD:
        _reject(403, "forbidden")
    if not x_trace_id:
        _reject(403, "forbidden")

def _require_bootstrap_and_checkin(device_id: str):
    if device_id not in bootstrapped:
        _reject(404, "not found")
    if device_id not in checked_in:
        _reject(404, "not found")

def _parse_iso8601_z(ts: str) -> datetime:
    if not ts.endswith("Z"):
        raise ValueError
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/api/v2/bootstrap/config")
def bootstrap_config(
    user_agent: Optional[str] = Header(default=None),
    x_device_id: Optional[str] = Header(default=None),
    x_tenant: Optional[str] = Header(default=None),
    x_build: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None),
    accept: Optional[str] = Header(default=None),
):
    _require_common_headers(user_agent, x_device_id, x_tenant, x_build, x_trace_id)
    if accept != "application/json":
        _reject(403, "forbidden")
    bootstrapped[x_device_id] = _now()
    return {
        "profile": EXPECTED_PROFILE,
        "sig_scheme": "attestation-v2",
        "canonical_fields": [
            "method",
            "path",
            "x-device-id",
            "x-tenant",
            "x-request-timestamp",
            "nonce"
        ],
        "key_derivation": "sha256(seed:session_id)",
        "session_id_source": "suffix-hex from x-device-id after 'ws-'",
        "redeem_path": "/api/v2/device/redeem",
        "challenge_path": "/api/v2/device/challenge",
        "artifact_path_template": "/content/{artifact_id}/report.bin"
    }

@app.post("/api/v2/device/checkin")
async def device_checkin(
    request: Request,
    body: CheckinBody,
    user_agent: Optional[str] = Header(default=None),
    x_device_id: Optional[str] = Header(default=None),
    x_tenant: Optional[str] = Header(default=None),
    x_build: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None),
    content_type: Optional[str] = Header(default=None),
    accept: Optional[str] = Header(default=None),
):
    _require_common_headers(user_agent, x_device_id, x_tenant, x_build, x_trace_id)
    if accept != "application/json":
        _reject(403, "forbidden")
    if content_type != "application/json":
        _reject(403, "forbidden")
    if x_device_id not in bootstrapped:
        _reject(404, "not found")
    raw = await request.body()
    if len(raw) < 40 or len(raw) > 512:
        _reject(403, "forbidden")
    if body.profile != EXPECTED_PROFILE or body.operation != "checkin" or body.campaign != EXPECTED_CAMPAIGN:
        _reject(403, "forbidden")
    if body.capabilities != ["delta", "gzip", "resume"]:
        _reject(403, "forbidden")
    checked_in[x_device_id] = _now()
    return {"status": "ok", "next": "challenge"}

@app.get("/api/v2/device/challenge")
def device_challenge(
    user_agent: Optional[str] = Header(default=None),
    x_device_id: Optional[str] = Header(default=None),
    x_tenant: Optional[str] = Header(default=None),
    x_build: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None),
    accept: Optional[str] = Header(default=None),
):
    _require_common_headers(user_agent, x_device_id, x_tenant, x_build, x_trace_id)
    if accept != "application/json":
        _reject(403, "forbidden")
    _require_bootstrap_and_checkin(x_device_id)
    nonce = secrets.token_hex(8)
    outstanding_challenges[x_device_id] = {
        "nonce": nonce,
        "artifact_id": ARTIFACT_ID,
        "issued_at": _now(),
        "used": False,
    }
    return {"nonce": nonce, "artifact_id": ARTIFACT_ID}

@app.post("/api/v2/device/redeem")
async def device_redeem(
    request: Request,
    body: RedeemBody,
    user_agent: Optional[str] = Header(default=None),
    x_device_id: Optional[str] = Header(default=None),
    x_tenant: Optional[str] = Header(default=None),
    x_build: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None),
    x_request_timestamp: Optional[str] = Header(default=None),
    x_signature: Optional[str] = Header(default=None),
    content_type: Optional[str] = Header(default=None),
    accept: Optional[str] = Header(default=None),
):
    _require_common_headers(user_agent, x_device_id, x_tenant, x_build, x_trace_id)
    if accept != "application/json":
        _reject(403, "forbidden")
    if content_type != "application/json":
        _reject(403, "forbidden")
    _require_bootstrap_and_checkin(x_device_id)

    ch = outstanding_challenges.get(x_device_id)
    if not ch:
        _reject(404, "not found")

    if ch["used"]:
        _reject(409, "conflict")

    if body.artifact_id != ch["artifact_id"] or body.nonce != ch["nonce"]:
        _reject(403, "forbidden")

    raw = await request.body()
    if len(raw) < 20 or len(raw) > 256:
        _reject(403, "forbidden")

    if not x_request_timestamp:
        _reject(401, "unauthorized")
    try:
        ts = _parse_iso8601_z(x_request_timestamp)
    except ValueError:
        _reject(401, "unauthorized")

    age = abs((_now() - ts).total_seconds())
    if age > TIMESTAMP_SKEW_SECONDS:
        _reject(401, "unauthorized")

    issued_age = (_now() - ch["issued_at"]).total_seconds()
    if issued_age > NONCE_TTL_SECONDS:
        outstanding_challenges.pop(x_device_id, None)
        _reject(401, "unauthorized")

    if not x_signature:
        _reject(403, "forbidden")

    try:
        key = _access_key(x_device_id)
    except ValueError:
        _reject(403, "forbidden")

    canonical = _canonical_string(
        method="POST",
        path="/api/v2/device/redeem",
        device_id=x_device_id,
        tenant=x_tenant,
        timestamp=x_request_timestamp,
        nonce=body.nonce,
    ).encode()

    expected_sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, x_signature):
        _reject(403, "attestation failed")

    ch["used"] = True
    redeemed_artifacts[x_device_id] = body.artifact_id
    return {
        "status": "approved",
        "download_path": f"/content/{body.artifact_id}/report.bin"
    }

@app.get("/content/{artifact_id}/report.bin")
def get_artifact(
    artifact_id: str,
    user_agent: Optional[str] = Header(default=None),
    x_device_id: Optional[str] = Header(default=None),
    x_tenant: Optional[str] = Header(default=None),
    x_build: Optional[str] = Header(default=None),
    x_trace_id: Optional[str] = Header(default=None),
):
    _require_common_headers(user_agent, x_device_id, x_tenant, x_build, x_trace_id)
    if redeemed_artifacts.get(x_device_id) != artifact_id:
        _reject(404, "not found")
    return PlainTextResponse(FLAG, media_type="text/plain")

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    body = {
        "error": exc.detail
    }
    return JSONResponse(status_code=exc.status_code, content=body)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
