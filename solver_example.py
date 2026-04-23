import hashlib
import hmac
import json
import urllib.request
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8000"
DEVICE_ID = "ws-91ac72ef"
TENANT = "apac-finance"
BUILD = "2.4.17"
TRACE_ID = "solver-demo-001"
USER_AGENT = "AcmeDeviceSync/2.4 (Windows NT 10.0; Win64; x64)"
SEED = "crystal-fall:apac-finance:edge-cache"

def req(method, path, body=None, extra_headers=None):
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "X-Device-ID": DEVICE_ID,
        "X-Tenant": TENANT,
        "X-Build": BUILD,
        "X-Trace-ID": TRACE_ID,
    }
    if extra_headers:
        headers.update(extra_headers)
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE_URL + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request) as resp:
        raw = resp.read()
        ctype = resp.headers.get("Content-Type", "")
        if "application/json" in ctype:
            return resp.status, json.loads(raw.decode())
        return resp.status, raw.decode()

# 1) bootstrap
print(req("GET", "/api/v2/bootstrap/config"))

# 2) checkin
checkin_body = {
    "profile": "edge-cache",
    "operation": "checkin",
    "campaign": "crystal-fall",
    "capabilities": ["delta", "gzip", "resume"],
}
print(req("POST", "/api/v2/device/checkin", checkin_body))

# 3) challenge
_, challenge = req("GET", "/api/v2/device/challenge")
print(challenge)

# 4) build signature
nonce = challenge["nonce"]
artifact_id = challenge["artifact_id"]
timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
session_id = DEVICE_ID.split("ws-")[1]
access_key = hashlib.sha256(f"{SEED}:{session_id}".encode()).digest()
canonical = "\n".join([
    "POST",
    "/api/v2/device/redeem",
    DEVICE_ID,
    TENANT,
    timestamp,
    nonce,
]).encode()
signature = hmac.new(access_key, canonical, hashlib.sha256).hexdigest()

# 5) redeem
redeem_headers = {
    "X-Request-Timestamp": timestamp,
    "X-Signature": signature,
}
redeem_body = {
    "nonce": nonce,
    "artifact_id": artifact_id,
}
print(req("POST", "/api/v2/device/redeem", redeem_body, redeem_headers))

# 6) fetch final artifact
request = urllib.request.Request(BASE_URL + f"/content/{artifact_id}/report.bin", headers={
    "User-Agent": USER_AGENT,
    "X-Device-ID": DEVICE_ID,
    "X-Tenant": TENANT,
    "X-Build": BUILD,
    "X-Trace-ID": TRACE_ID,
}, method="GET")
with urllib.request.urlopen(request) as resp:
    print(resp.read().decode())
