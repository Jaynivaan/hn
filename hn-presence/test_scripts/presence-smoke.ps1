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
