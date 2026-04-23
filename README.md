# Device Sync Attestation CTF

This bundle contains a realistic HTTP-based CTF where a compromised workstation tries to impersonate a legitimate device-sync agent.

## Story

The PCAP shows:

1. DNS bootstrap to discover the sync service.
2. A legitimate agent bootstrap request that leaks the attestation rules.
3. A legitimate check-in.
4. An attacker request to obtain a challenge nonce.
5. A failed attacker redeem attempt that gets rejected because the signature is wrong.

The actual flag is **not** inside the PCAP. A player must replay the flow against the live service, calculate the correct signature, redeem access, and then fetch the flag from a second endpoint.

## Files

- `main.py` - FastAPI challenge server
- `requirements.txt` - Python dependencies
- `.env.example` - environment variable template
- `solver_example.py` - organizer/test solver
- `../device_sync_attestation.pcap` - the forensic artifact shown to players

## Challenge values shown in the PCAP

- Host: `sync-gateway.example.net`
- Device ID: `ws-91ac72ef`
- Tenant: `apac-finance`
- Build: `2.4.17`
- Profile: `edge-cache`
- Campaign: `crystal-fall`
- Artifact ID (sample): `obj-172`

Seed parts are exposed through DNS TXT records:

- `seed_part1=crystal-fall`
- `seed_part2=apac-finance`
- `seed_part3=edge-cache`

The bootstrap response also leaks:

- `sig_scheme = attestation-v2`
- `canonical_fields = method, path, x-device-id, x-tenant, x-request-timestamp, nonce`
- `key_derivation = sha256(seed:session_id)`
- `session_id_source = suffix-hex from x-device-id after 'ws-'`

## Signature rule

1. Build the seed by joining the DNS TXT parts with colons:

```text
crystal-fall:apac-finance:edge-cache
```

2. Extract the session ID from the device ID suffix:

```text
91ac72ef
```

3. Derive the access key:

```text
access_key = SHA256(seed + ":" + session_id)
```

4. Build the canonical string:

```text
METHOD + "\n" + PATH + "\n" + DEVICE_ID + "\n" + TENANT + "\n" + TIMESTAMP + "\n" + NONCE
```

5. Sign it:

```text
signature = HMAC-SHA256(access_key, canonical_string)
```

The attacker in the PCAP signs the redeem request incorrectly and receives `403`.

## Local test

Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Start the service:

```bash
python main.py
```

It will listen on `http://127.0.0.1:8000`.

You can test the full solve path with:

```bash
python solver_example.py
```

## Endpoints

- `GET /api/v2/bootstrap/config`
- `POST /api/v2/device/checkin`
- `GET /api/v2/device/challenge`
- `POST /api/v2/device/redeem`
- `GET /content/{artifact_id}/report.bin`
- `GET /healthz`

## Request rules enforced by the server

The service rejects requests unless they match the profile from the PCAP:

- Exact `User-Agent`
- Exact `X-Device-ID`
- Exact `X-Tenant`
- Exact `X-Build`
- `X-Trace-ID` must exist
- JSON API requests must use `Accept: application/json`
- POST requests must use `Content-Type: application/json`
- Challenge requires successful bootstrap and check-in first
- Redeem requires a live nonce issued by `/api/v2/device/challenge`
- `X-Request-Timestamp` must be within the configured freshness window
- Each nonce is one-time use
- Direct artifact fetch before a valid redeem returns `404`

> Note: the server **does not** validate the `Host` header because your Koyeb domain will not be `sync-gateway.example.net` unless you later attach a custom domain.

## Deploy to Koyeb (control panel)

1. Put these files in a GitHub repository.
2. In Koyeb, click **Create Web Service**.
3. Select **GitHub** as the deployment method.
4. Choose your repository and branch.
5. Under **Build options**, choose **Buildpack**.
6. Override the **Run command** and set it to:

```text
uvicorn main:app --host 0.0.0.0
```

7. Add the environment variables from `.env.example` in the service settings.
8. Deploy the service.
9. After it becomes healthy, open `<your-koyeb-url>/healthz` to verify it is running.

## Quick Koyeb environment variables

At minimum set:

- `FLAG=KPMG{your_real_flag}`

Optionally change any of the defaults in `.env.example` if you want a different story or values.

## What to give players

Give players only:
- the `device_sync_attestation.pcap`
- a short story blurb
- the live base URL

Do **not** ship `solver_example.py` or this README to players.
