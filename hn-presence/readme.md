

---

# HelloNivaan — Presence Chamber (VAYU)

**Phase:** MVP-1
**Essence:** *Breath-of-Identity* — deterministic, privacy-safe presence ID (“sigil”) with **no PII stored**.

## Why this exists

* **Lightweight identity proof:** Produce a stable “presence_id” for a pseudonym on a device without usernames, emails, or databases.
* **Deterministic & stateless:** Same `(alias, client_salt, server PEPPER)` ⇒ same `presence_id`.
* **Safe by design:** No persistence, no tracking cookies, and no secrets revealed to clients.

Typical use:

* Gate non-critical actions behind “are you present?” checks.
* Tie local progress to a pseudonym+device, without creating an account.
* Pre-auth signal for upper layers (Auth/Session) to decide “who” without PII.

---

## Endpoints

### `GET /health` → `200 {"ok":true}`

### `POST /sigil/derive`

**Request (JSON)**

```json
{ "alias": "raven42", "client_salt": "deviceA-001" }
```

**Response (200)**

```json
{
  "presence_id": "687f5c04a4bd84aeca90e1f4",
  "algo": "sha256(hex)[first_24]",
  "created_at": "2025-11-10T18:03:48.885409Z"
}
```

**Validation**

* `alias`: 3–48 chars; ASCII letters/digits/`_-.'`
* `client_salt`: 3–64 chars; ASCII letters/digits/`_- .#@/+`
* 400 `{"code":"bad_input","message":"alias/salt invalid (len or charset)"}` on failure.

### `POST /sigil/verify`

**Request (JSON)**

```json
{
  "alias": "raven42",
  "client_salt": "deviceA-001",
  "presence_id": "687f5c04a4bd84aeca90e1f4"
}
```

**Response (200)**

```json
{ "ok": true, "expected": "687f5c04a4bd84aeca90e1f4" }
```

* Uses **constant-time comparison** to avoid subtle timing leaks.
* If mismatch: `{ "ok": false, "expected": "<deterministic-id>" }`

---

## Run local

```powershell
# from hn/hn-presence
$env:PRESENCE_PEPPER="use-a-long-random-string-here"  # set a real secret in prod
$env:ENABLE_SEC_HEADERS="true"                        # optional headers
cargo run
# Service → http://127.0.0.1:8082
```

---

## Quick tests (PowerShell-native)

```powershell
# 1) Health
Invoke-RestMethod -Method Get http://127.0.0.1:8082/health

# 2) Derive
$derivePayload = @{ alias="raven42"; client_salt="deviceA-001" } | ConvertTo-Json -Compress
$derive = Invoke-RestMethod -Method Post http://127.0.0.1:8082/sigil/derive `
          -ContentType "application/json" -Body $derivePayload
$derive

# 3) Verify (should be ok=True)
$verifyPayload = @{
  alias       = "raven42"
  client_salt = "deviceA-001"
  presence_id = $derive.presence_id
} | ConvertTo-Json -Compress
$verify = Invoke-RestMethod -Method Post http://127.0.0.1:8082/sigil/verify `
          -ContentType "application/json" -Body $verifyPayload
$verify
```

### curl.exe (Windows) notes

If you prefer `curl.exe`, ensure **UTF-8 without BOM**, otherwise the server may say “Json deserialize error”.

```powershell
# Derive (BOM-free temp file approach)
$json = '{"alias":"raven42","client_salt":"deviceA-001"}'
$tmp  = New-TemporaryFile
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($tmp.FullName, $json, $utf8NoBom)
curl.exe -s -X POST -H "Content-Type: application/json" --data-binary "@$($tmp.FullName)" http://127.0.0.1:8082/sigil/derive
Remove-Item $tmp

# Verify (replace <ID> with id from derive)
$verify = '{"alias":"raven42","client_salt":"deviceA-001","presence_id":"<ID>"}'
$tmp  = New-TemporaryFile
[System.IO.File]::WriteAllText($tmp.FullName, $verify, $utf8NoBom)
curl.exe -s -X POST -H "Content-Type: application/json" --data-binary "@$($tmp.FullName)" http://127.0.0.1:8082/sigil/verify
Remove-Item $tmp
```

---

## Security posture

* **No PII** handled; only pseudonym + client salt.
* **Server secret (PEPPER)** must be set via environment in real deployments.
* **Constant-time compare** defends against timing side-channels.
* **Optional headers**: CSP, X-Frame-Options, nosniff, via `ENABLE_SEC_HEADERS=1`.
* **No persistence**: nothing is stored server-side.

**Non-goals (MVP-1):**

* No rate limiting yet.
* No replay detection across time (deterministic by design).
* No binding to IP/UA (privacy choice).

**Future (MVP-2+):**

* Per-route rate limits and minimal abuse controls.
* Optionally include a short-lived signed token over `presence_id` for upstream services.
* Salt guidance helper endpoint (e.g., “device fingerprint light” without tracking).

---

## Troubleshooting

* **“Json deserialize error: key must be a string …”**
  Usually BOM or wrong content-type. Use PowerShell `Invoke-RestMethod` or BOM-free files with `curl.exe`.

* **Mismatch on verify (`ok:false`)**
  The trio `(alias, client_salt, PRESENCE_PEPPER)` must match exactly. Check spacing and env var.

* **Headers not present**
  Set `ENABLE_SEC_HEADERS=1` before starting.

---

## Test recommendations (what to cover)

1. **Happy path**

   * Derive then verify with same alias/salt → `ok:true`.

2. **Determinism**

   * Run derive twice with same inputs → identical `presence_id`.

3. **Salt matters**

   * Same alias, different salt → different `presence_id`.

4. **Pepper secrecy**

   * Restart with different `PRESENCE_PEPPER`; same alias/salt now yields a different `presence_id`.

5. **Validation**

   * Too short alias/salt → `400` with `code:"bad_input"`.

6. **Malformed JSON**

   * Broken JSON → 400 from extractor.

7. **Headers (if enabled)**

   * `curl -sI http://127.0.0.1:8082/ | findstr /I "content-security-policy x-frame-options x-content-type-options"`

---

## One-shot smoke test (PowerShell script)

 `test_scripts\presence-smoke.ps1`:

```powershell
param(
  [string]$HostName = "127.0.0.1",
  [int]   $Port     = 8082,
  [string]$Alias    = "raven42",
  [string]$Salt     = "deviceA-001"
)

$base = "http://$($HostName):$Port"

function Fail($msg){ throw $msg }

# 1) Health
$h = Invoke-RestMethod -Method Get -Uri "$base/health"
if(-not $h.ok){ Fail "Health failed" }

# 2) Derive
$derivePayload = @{ alias=$Alias; client_salt=$Salt } | ConvertTo-Json -Compress
$derive = Invoke-RestMethod -Method Post -Uri "$base/sigil/derive" `
          -ContentType "application/json" -Body $derivePayload

# 3) Verify (deterministic round-trip)
$verifyPayload = @{
  alias       = $Alias
  client_salt = $Salt
  presence_id = $derive.presence_id
} | ConvertTo-Json -Compress

$verify = Invoke-RestMethod -Method Post -Uri "$base/sigil/verify" `
          -ContentType "application/json" -Body $verifyPayload

[pscustomobject]@{
  health_ok     = $h.ok
  presence_id   = $derive.presence_id
  verify_ok     = $verify.ok
  expected_echo = $verify.expected
}

```

Run:()

# From hn/hn-presence
powershell -ExecutionPolicy Bypass -File .\test_scripts\presence-smoke.ps1
# or override host/port if needed:
powershell -ExecutionPolicy Bypass -File .\test_scripts\presence-smoke.ps1 -HostName 127.0.0.1 -Port 8082

