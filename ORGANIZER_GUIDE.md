# Organizer Guide

## Scenario

The attacker reached the device-sync API and copied the visible headers and JSON shapes from the legitimate agent, but failed at the final attestation step. The capture contains a failed redeem request with a bad `X-Signature`. Players must recover the correct signing inputs from the bootstrap/config response and fix the signature logic to retrieve the final artifact.

## Solve outline

1. Open the PCAP and inspect DNS TXT records:
   - `seed_part1=crystal-fall`
   - `seed_part2=apac-finance`
   - `seed_part3=edge-cache`

2. Inspect the bootstrap/config response:
   - `canonical_fields = method, path, x-device-id, x-tenant, x-request-timestamp, nonce`
   - `key_derivation = sha256(seed:session_id)`
   - `session_id_source = suffix-hex from x-device-id after 'ws-'`

3. From the HTTP requests:
   - `device_id = ws-91ac72ef`
   - `tenant = apac-finance`

4. Derive:
   - `seed = crystal-fall:apac-finance:edge-cache`
   - `session_id = 91ac72ef`

5. Recreate the flow:
   - `GET /api/v2/bootstrap/config`
   - `POST /api/v2/device/checkin`
   - `GET /api/v2/device/challenge`

6. Receive a fresh nonce and artifact ID.

7. Build the signature:
   - `access_key = SHA256(seed + ":" + session_id)`
   - `canonical = "POST\n/api/v2/device/redeem\nws-91ac72ef\napac-finance\n<TIMESTAMP>\n<NONCE>"`
   - `signature = HMAC-SHA256(access_key, canonical)`

8. Send:
   - `POST /api/v2/device/redeem`
   - headers:
     - `X-Request-Timestamp`
     - `X-Signature`
   - body:
     - `{"nonce":"<nonce>","artifact_id":"obj-172"}`

9. Fetch:
   - `GET /content/obj-172/report.bin`

## Example correct signature for the sample nonce in the PCAP

Using:
- timestamp: `2026-04-23T09:10:11Z`
- nonce: `9d8c4f0a3e21b7c5`

The correct signature is:

```text
3662dacc79d5e542232cf5d49fdc91c0f958bb4a60fc4d547298d7fe16b79e47
```

The PCAP intentionally contains this incorrect signature instead:

```text
05cdbb05a78576ba5b398ec1c849bccd18e04e30aea3370944d684a417209884
```

That is why the attacker got `403`.
