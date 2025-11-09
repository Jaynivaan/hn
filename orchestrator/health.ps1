# health.ps1 — Orchestrator MVP-1 health check (Windows PowerShell friendly)

# 0) Anchor to script folder
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$now     = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
$indexPath = "index.json"
$chDir     = "chambers"

# 1) Load index.json
try {
  $index = Get-Content $indexPath -Raw | ConvertFrom-Json
}
catch {
  Write-Error "index.json invalid or missing"; exit 1
}

# 2) Enumerate chamber files
$expected = @("gateway","challenge","presence","auth","content","session")
$report   = @()

foreach($name in $expected){
  $file   = Join-Path $chDir "$name.json"
  $exists = Test-Path $file
  $status = if($exists){"present"} else {"missing"}
  $report += [pscustomobject]@{ chamber=$name; file=$file; status=$status }
  if(-not $exists){ $index.chambers.$name.status = "missing_file" }
}

# 3) Update last_update in index.json  <<< FIXED
$index.last_update = $now

# 4) Ensure reports/ and write status file (UTF-8)
$repDir  = "reports"
if(-not (Test-Path $repDir)){ New-Item -ItemType Directory $repDir | Out-Null }
$repPath = Join-Path $repDir ("status-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".json")

# Write files (Windows PowerShell safe encodings)
($index  | ConvertTo-Json -Depth 10) | Out-File $indexPath -Encoding utf8   # or: Set-Content -Encoding UTF8
($report | ConvertTo-Json -Depth 10) | Out-File $repPath  -Encoding utf8    # or: Set-Content -Encoding UTF8

# 5) Append progress.log
$present = ($report | Where-Object {$_.status -eq "present"}).Count
$missing = ($report | Where-Object {$_.status -ne "present"}).Count
$line = "[{0}] Health check: {1} present, {2} missing" -f $now, $present, $missing
Add-Content -Path "progress.log" -Value $line

# 6) Console summary
$report | Format-Table -AutoSize
Write-Host "`nIndex updated. Report -> $repPath"
