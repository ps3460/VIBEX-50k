param(
  [string]$ToolsRoot = "C:\Tools",
  [string]$PayloadDir = "S:\tool_payload",
  [string]$OutputDir = "S:\results",
  [switch]$InstallFromPayload,
  [switch]$AllowInternetDownload
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

New-Item -ItemType Directory -Force $ToolsRoot,$OutputDir | Out-Null
$JsonPath = Join-Path $OutputDir "deep_static_toolchain_audit.json"
$ReportPath = Join-Path $OutputDir "deep_static_toolchain_audit.md"

function Shorten([string]$Text, [int]$Max) {
  if ($null -eq $Text) { return "" }
  $clean = ($Text -replace "[\r\n]+", " ") -replace "\s+", " "
  $clean = ($clean -replace "\s+", " ").Trim()
  if ($clean.Length -le $Max) { return $clean }
  return $clean.Substring(0, $Max)
}

function Find-Exe([string[]]$Candidates) {
  foreach ($candidate in $Candidates) {
    if ($candidate -and (Test-Path $candidate)) { return (Resolve-Path $candidate).Path }
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
  }
  return ""
}

function Expand-ToolZip([string]$Name, [string]$Pattern, [string]$Destination) {
  $result = [ordered]@{ name=$Name; status="skipped"; source=""; destination=$Destination; error="" }
  if (-not $InstallFromPayload) { return $result }
  if (-not (Test-Path $PayloadDir)) {
    $result.status = "payload_dir_missing"
    return $result
  }
  $zip = Get-ChildItem $PayloadDir -Filter $Pattern -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $zip) {
    $result.status = "payload_missing"
    return $result
  }
  try {
    New-Item -ItemType Directory -Force $Destination | Out-Null
    Expand-Archive -Path $zip.FullName -DestinationPath $Destination -Force
    $result.status = "installed_from_payload"
    $result.source = $zip.FullName
  } catch {
    $result.status = "error"
    $result.error = Shorten $_.Exception.Message 800
  }
  return $result
}

function Download-ToolZip([string]$Name, [string]$Url, [string]$Destination) {
  $result = [ordered]@{ name=$Name; status="skipped"; url=$Url; destination=$Destination; error="" }
  if (-not $AllowInternetDownload) { return $result }
  $downloadDir = Join-Path $ToolsRoot "Downloads"
  $zipPath = Join-Path $downloadDir ([System.IO.Path]::GetFileName($Url))
  try {
    New-Item -ItemType Directory -Force $downloadDir,$Destination | Out-Null
    Invoke-WebRequest -Uri $Url -OutFile $zipPath -UseBasicParsing -TimeoutSec 120
    Expand-Archive -Path $zipPath -DestinationPath $Destination -Force
    $result.status = "downloaded"
  } catch {
    $result.status = "error"
    $result.error = Shorten $_.Exception.Message 800
  }
  return $result
}

function Command-Version([string]$Exe, [string[]]$Args) {
  if (-not $Exe -or -not (Test-Path $Exe)) { return "" }
  $stdout = Join-Path $env:TEMP ("vibex_tool_version_{0}.out" -f [guid]::NewGuid())
  $stderr = Join-Path $env:TEMP ("vibex_tool_version_{0}.err" -f [guid]::NewGuid())
  try {
    $p = Start-Process -FilePath $Exe -ArgumentList $Args -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $p.WaitForExit(15000)) {
      try { $p.Kill() } catch {}
      return "timeout"
    }
    $text = ""
    if (Test-Path $stdout) { $text += Get-Content $stdout -Raw -ErrorAction SilentlyContinue }
    if (Test-Path $stderr) { $text += " " + (Get-Content $stderr -Raw -ErrorAction SilentlyContinue) }
    return Shorten $text 500
  } catch {
    return "error: " + (Shorten $_.Exception.Message 300)
  } finally {
    Remove-Item $stdout,$stderr -Force -ErrorAction SilentlyContinue
  }
}

$installActions = @()
$installActions += Expand-ToolZip "capa" "capa*v9.4.0*windows*.zip" (Join-Path $ToolsRoot "capa-v9.4.0-windows")
$installActions += Expand-ToolZip "floss" "floss*v3.1.1*windows*.zip" (Join-Path $ToolsRoot "floss-v3.1.1-windows")
$installActions += Expand-ToolZip "yara" "yara*4.5.5*win64*.zip" (Join-Path $ToolsRoot "yara-4.5.5-win64")
$installActions += Expand-ToolZip "exiftool" "exiftool*.zip" (Join-Path $ToolsRoot "exiftool")

$installActions += Download-ToolZip "capa" "https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-windows.zip" (Join-Path $ToolsRoot "capa-v9.4.0-windows")
$installActions += Download-ToolZip "floss" "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.zip" (Join-Path $ToolsRoot "floss-v3.1.1-windows")
$installActions += Download-ToolZip "yara" "https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip" (Join-Path $ToolsRoot "yara-4.5.5-win64")

$tools = [ordered]@{
  sigcheck = Find-Exe @("$ToolsRoot\Sysinternals\sigcheck64.exe", "$ToolsRoot\SysinternalsSuite\sigcheck64.exe", "sigcheck64.exe")
  strings = Find-Exe @("$ToolsRoot\Sysinternals\strings64.exe", "$ToolsRoot\SysinternalsSuite\strings64.exe", "strings64.exe")
  diec = Find-Exe @("$ToolsRoot\die_win64_portable_3.21_x64\die\diec.exe", "$ToolsRoot\die\diec.exe", "diec.exe")
  yara = Find-Exe @("$ToolsRoot\yara-4.5.5-win64\yara64.exe", "$ToolsRoot\yara-4.5.5-2368-win64\yara64.exe", "yara64.exe")
  capa = Find-Exe @("$ToolsRoot\capa-v9.4.0-windows\capa.exe", "capa.exe")
  floss = Find-Exe @("$ToolsRoot\floss-v3.1.1-windows\floss.exe", "floss.exe")
  exiftool = Find-Exe @("$ToolsRoot\exiftool\exiftool.exe", "$ToolsRoot\exiftool\exiftool(-k).exe", "exiftool.exe")
  clamscan = Find-Exe @("clamscan.exe")
  python = Find-Exe @("python.exe", "py.exe")
}

$toolReports = @()
foreach ($name in $tools.Keys) {
  $exe = $tools[$name]
  $version = ""
  if ($exe) {
    $versionArgs = @("--version")
    if ($name -eq "sigcheck" -or $name -eq "strings") { $versionArgs = @("-nobanner","-?") }
    if ($name -eq "diec") { $versionArgs = @("--version") }
    if ($name -eq "python") { $versionArgs = @("--version") }
    $version = Command-Version $exe $versionArgs
  }
  $toolReports += [pscustomobject]@{
    name=$name
    status=($(if ($exe) { "present" } else { "missing" }))
    path=$exe
    version=$version
  }
}

$pythonModules = @()
if ($tools.python) {
  foreach ($module in @("pefile","lief","dnfile","tlsh","ssdeep")) {
    $code = "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('$module') else 1)"
    try {
      & $tools.python -c $code *> $null
      $pythonModules += [pscustomobject]@{ name=$module; status=($(if ($LASTEXITCODE -eq 0) { "present" } else { "missing" })) }
    } catch {
      $pythonModules += [pscustomobject]@{ name=$module; status="error" }
    }
  }
}

$rulesDir = "S:\rules"
$rules = @()
if (Test-Path $rulesDir) {
  $rules = @(Get-ChildItem $rulesDir -Include *.yar,*.yara -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
}
$provenancePath = Join-Path $rulesDir "RULES_PROVENANCE.json"

$requiredMissing = @($toolReports | Where-Object { $_.name -in @("sigcheck","strings","diec","yara","capa","floss") -and $_.status -ne "present" } | ForEach-Object { $_.name })
$payload = [ordered]@{
  audited_utc=(Get-Date).ToUniversalTime().ToString("o")
  user=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  tools_root=$ToolsRoot
  payload_dir=$PayloadDir
  install_from_payload=[bool]$InstallFromPayload
  allow_internet_download=[bool]$AllowInternetDownload
  install_actions=$installActions
  tools=$toolReports
  python_modules=$pythonModules
  yara_rules=[ordered]@{
    rules_dir=$rulesDir
    rule_files=$rules
    provenance_path=$provenancePath
    provenance_present=(Test-Path $provenancePath)
    ready=($rules.Count -gt 0 -and (Test-Path $provenancePath))
  }
  required_missing=$requiredMissing
  ready_for_deep_static=($requiredMissing.Count -eq 0)
}
$payload | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $JsonPath

$lines = @()
$lines += "# VIBEX Deep Static Toolchain Audit"
$lines += ""
$lines += "- Audited UTC: ``$($payload.audited_utc)``"
$lines += "- Ready for deep static: ``$($payload.ready_for_deep_static)``"
$lines += "- Required missing: ``$(($requiredMissing -join ', '))``"
$lines += "- YARA rule files: ``$($rules.Count)``"
$lines += "- YARA provenance present: ``$($payload.yara_rules.provenance_present)``"
$lines += ""
$lines += "## Tools"
foreach ($tool in $toolReports) {
  $lines += "- ``$($tool.name)``: ``$($tool.status)`` $($tool.path)"
}
$lines += ""
$lines += "## Python Modules"
foreach ($module in $pythonModules) {
  $lines += "- ``$($module.name)``: ``$($module.status)``"
}
$lines | Set-Content -Encoding UTF8 $ReportPath

Write-Output "VIBEX_TOOLCHAIN_AUDIT_COMPLETE ready=$($payload.ready_for_deep_static) missing=$(($requiredMissing -join ','))"
