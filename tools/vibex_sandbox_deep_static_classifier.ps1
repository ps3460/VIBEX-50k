param(
  [string]$ClassificationCsv = "S:\results\windows_family_hints.csv",
  [string]$LexiconPath = "S:\targets\family_lexicon.csv",
  [string]$SamplesDir = "S:\samples",
  [string]$ResultsDir = "S:\results",
  [string]$RulesDir = "S:\rules",
  [int]$Limit = 0,
  [int]$Seed = 20260612,
  [int]$SigcheckTimeoutSeconds = 25,
  [int]$DieTimeoutSeconds = 35,
  [int]$StringsTimeoutSeconds = 35,
  [int]$CapaTimeoutSeconds = 120,
  [int]$FlossTimeoutSeconds = 120,
  [int]$YaraTimeoutSeconds = 60,
  [switch]$Smoke,
  [switch]$RunDefender,
  [switch]$RunClam
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

New-Item -ItemType Directory -Force $ResultsDir | Out-Null
$ResultsPath = Join-Path $ResultsDir "deep_static_family_results.csv"
$SummaryPath = Join-Path $ResultsDir "deep_static_family_summary.json"
$ReportPath = Join-Path $ResultsDir "deep_static_family_report.md"
$ProgressPath = Join-Path $ResultsDir "deep_static_family_progress.json"

if ($Smoke) {
  $SigcheckTimeoutSeconds = [Math]::Min($SigcheckTimeoutSeconds, 12)
  $DieTimeoutSeconds = [Math]::Min($DieTimeoutSeconds, 15)
  $StringsTimeoutSeconds = [Math]::Min($StringsTimeoutSeconds, 12)
  $CapaTimeoutSeconds = [Math]::Min($CapaTimeoutSeconds, 15)
  $FlossTimeoutSeconds = [Math]::Min($FlossTimeoutSeconds, 15)
  $YaraTimeoutSeconds = [Math]::Min($YaraTimeoutSeconds, 15)
}

function Shorten([string]$Text, [int]$Max) {
  if ($null -eq $Text) { return "" }
  $clean = ($Text -replace "[\r\n]+", " ") -replace "\s+", " "
  $clean = $clean -replace '[^A-Za-z0-9 \._:/\\\-\(\)\[\];!@#%+=,]', ' '
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

function Invoke-Tool([string]$Name, [string]$Exe, [string[]]$ToolArgs, [int]$TimeoutSeconds, [int]$StdoutMax = 6000) {
  $result = [ordered]@{ name=$Name; status="missing"; exit_code=$null; stdout=""; stderr="" }
  if (-not $Exe -or -not (Test-Path $Exe)) { return $result }
  $stdout = Join-Path $env:TEMP ("vibex_deep_{0}_{1}.out" -f $Name, [guid]::NewGuid())
  $stderr = Join-Path $env:TEMP ("vibex_deep_{0}_{1}.err" -f $Name, [guid]::NewGuid())
  try {
    $p = Start-Process -FilePath $Exe -ArgumentList $ToolArgs -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
      try { $p.Kill() } catch {}
      $result.status = "timeout"
    } else {
      $result.status = "completed"
      $result.exit_code = $p.ExitCode
    }
    if (Test-Path $stdout) { $result.stdout = Shorten (Get-Content $stdout -Raw -ErrorAction SilentlyContinue) $StdoutMax }
    if (Test-Path $stderr) { $result.stderr = Shorten (Get-Content $stderr -Raw -ErrorAction SilentlyContinue) 1200 }
  } catch {
    $result.status = "error"
    $result.stderr = Shorten $_.Exception.Message 1200
  } finally {
    Remove-Item $stdout,$stderr -Force -ErrorAction SilentlyContinue
  }
  return $result
}

function Read-PeSummary([string]$Path) {
  $summary = [ordered]@{ magic=""; pe_signature=""; machine=""; section_count=""; timestamp=""; optional_magic=""; subsystem=""; characteristics=""; error="" }
  try {
    $fs = [System.IO.File]::OpenRead($Path)
    try {
      $br = New-Object System.IO.BinaryReader($fs)
      $fs.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
      $b0 = $br.ReadByte()
      $b1 = $br.ReadByte()
      $summary.magic = "{0:X2}{1:X2}" -f $b0,$b1
      if ($fs.Length -lt 0x40) { return $summary }
      $fs.Seek(0x3c, [System.IO.SeekOrigin]::Begin) | Out-Null
      $peOff = $br.ReadInt32()
      if ($peOff -le 0 -or $peOff -gt ($fs.Length - 24)) { return $summary }
      $fs.Seek($peOff, [System.IO.SeekOrigin]::Begin) | Out-Null
      $sig = $br.ReadUInt32()
      $summary.pe_signature = "{0:X8}" -f $sig
      if ($sig -ne 0x00004550) { return $summary }
      $machine = $br.ReadUInt16()
      $sections = $br.ReadUInt16()
      $stamp = $br.ReadUInt32()
      $fs.Seek(12, [System.IO.SeekOrigin]::Current) | Out-Null
      $optionalSize = $br.ReadUInt16()
      $characteristics = $br.ReadUInt16()
      $optionalStart = $fs.Position
      $optionalMagic = 0
      $subsystem = 0
      if ($optionalSize -ge 70) {
        $optionalMagic = $br.ReadUInt16()
        $fs.Seek($optionalStart + 68, [System.IO.SeekOrigin]::Begin) | Out-Null
        $subsystem = $br.ReadUInt16()
      }
      $summary.machine = "0x{0:X4}" -f $machine
      $summary.section_count = "$sections"
      $summary.timestamp = "$stamp"
      $summary.optional_magic = "0x{0:X4}" -f $optionalMagic
      $summary.subsystem = "$subsystem"
      $summary.characteristics = "0x{0:X4}" -f $characteristics
    } finally {
      $fs.Dispose()
    }
  } catch {
    $summary.error = Shorten $_.Exception.Message 500
  }
  return $summary
}

function Load-Lexicon([string]$Path) {
  if (-not (Test-Path $Path)) { return @() }
  $rows = @(Import-Csv $Path)
  return $rows | Where-Object { $_.family -and $_.pattern -and $_.pattern.Length -ge 3 }
}

$GenericLabels = @{
  ""=$true; "agent"=$true; "ambiguous"=$true; "backdoor"=$true; "dropper"=$true
  "generic"=$true; "generickd"=$true; "heur"=$true; "malware"=$true; "packed"=$true
  "packer"=$true; "pua"=$true; "riskware"=$true; "trojan"=$true; "virus"=$true
  "vmprotect"=$true; "worm"=$true; "unlabelled"=$true; "insufficient_votes"=$true
}
$CommonStringFalseHints = @{"score"=$true; "scar"=$true; "small"=$true; "ransom"=$true; "genie"=$true}
$ShortStringAllow = @{"zbot"=$true; "zusy"=$true; "juko"=$true; "gozi"=$true; "virut"=$true; "expiro"=$true; "upatre"=$true; "sality"=$true}

function Find-FamilyHints([string]$Text, $Lexicon, [string]$SourceName) {
  $hits = @{}
  $value = ($Text + "").ToLowerInvariant()
  foreach ($row in $Lexicon) {
    $pattern = ($row.pattern + "").ToLowerInvariant()
    if (-not $pattern) { continue }
    if ($SourceName -eq "strings") {
      if ($CommonStringFalseHints.ContainsKey($pattern)) { continue }
      if ($pattern.Length -lt 6 -and -not $ShortStringAllow.ContainsKey($pattern)) { continue }
    }
    if ($value.Contains($pattern)) {
      $family = ($row.family + "").ToLowerInvariant()
      if ($family -and -not $GenericLabels.ContainsKey($family)) { $hits[$family] = $true }
    }
  }
  return @($hits.Keys | Sort-Object)
}

function Stable-Rank([string]$Value, [int]$Seed) {
  $bytes = [System.Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $Seed,$Value))
  $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
  return [BitConverter]::ToString($sha).Replace("-","")
}

function Invoke-PythonStatic([string]$PythonExe, [string]$Sample) {
  $result = [ordered]@{ status="missing"; imphash=""; tlsh=""; ssdeep=""; dotnet=""; imports=""; error="" }
  if (-not $PythonExe -or -not (Test-Path $PythonExe)) { return $result }
  $script = Join-Path $env:TEMP ("vibex_static_{0}.py" -f [guid]::NewGuid())
  $out = Join-Path $env:TEMP ("vibex_static_{0}.json" -f [guid]::NewGuid())
  @'
import json, sys
path=sys.argv[1]
out={"status":"completed","imphash":"","tlsh":"","ssdeep":"","dotnet":"","imports":"","error":""}
try:
    try:
        import pefile
        pe=pefile.PE(path, fast_load=False)
        try: out["imphash"]=pe.get_imphash()
        except Exception: pass
        names=[]
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll=(entry.dll or b"").decode("utf-8","ignore").lower()
            if dll: names.append(dll)
        out["imports"]=";".join(sorted(set(names))[:60])
    except Exception as exc:
        out["error"] += " pefile:" + str(exc)[:180]
    try:
        import dnfile
        dn=dnfile.dnPE(path)
        out["dotnet"]="yes" if getattr(dn, "net", None) else "no"
    except Exception:
        pass
    try:
        import tlsh
        data=open(path,"rb").read()
        h=tlsh.hash(data)
        out["tlsh"]=h if h != "TNULL" else ""
    except Exception:
        pass
    try:
        import ssdeep
        out["ssdeep"]=ssdeep.hash_from_file(path)
    except Exception:
        pass
except Exception as exc:
    out["status"]="error"; out["error"]=str(exc)[:300]
print(json.dumps(out, sort_keys=True))
'@ | Set-Content -Encoding UTF8 $script
  try {
    $stdout = & $PythonExe $script $Sample 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $stdout) {
      $result.status = "error"
      return $result
    }
    $parsed = $stdout | ConvertFrom-Json
    $result.status = $parsed.status
    $result.imphash = $parsed.imphash
    $result.tlsh = $parsed.tlsh
    $result.ssdeep = Shorten $parsed.ssdeep 250
    $result.dotnet = $parsed.dotnet
    $result.imports = Shorten $parsed.imports 700
    $result.error = Shorten $parsed.error 500
  } catch {
    $result.status = "error"
    $result.error = Shorten $_.Exception.Message 500
  } finally {
    Remove-Item $script,$out -Force -ErrorAction SilentlyContinue
  }
  return $result
}

function Get-RulesArgument([string]$RuleRoot) {
  if (-not (Test-Path $RuleRoot)) { return "" }
  $rules = @(Get-ChildItem $RuleRoot -Include *.yar,*.yara -Recurse -File -ErrorAction SilentlyContinue)
  if ($rules.Count -lt 1) { return "" }
  return $RuleRoot
}

$tool = @{
  sigcheck = Find-Exe @("C:\Tools\SysinternalsSuite\sigcheck64.exe","C:\Tools\Sysinternals\sigcheck64.exe","sigcheck64.exe")
  strings = Find-Exe @("C:\Tools\SysinternalsSuite\strings64.exe","C:\Tools\Sysinternals\strings64.exe","strings64.exe")
  diec = Find-Exe @("C:\Tools\die_win64_portable_3.21_x64\die\diec.exe","C:\Tools\die\diec.exe","diec.exe")
  yara = Find-Exe @("C:\Tools\yara-4.5.5-win64\yara64.exe","C:\Tools\yara-4.5.5-2368-win64\yara64.exe","yara64.exe")
  capa = Find-Exe @("C:\Tools\capa-v9.4.0-windows\capa.exe","capa.exe")
  floss = Find-Exe @("C:\Tools\floss-v3.1.1-windows\floss.exe","floss.exe")
  clamscan = Find-Exe @("clamscan.exe")
  python = Find-Exe @("python.exe","py.exe")
}
$rulesArg = Get-RulesArgument $RulesDir
$lexicon = Load-Lexicon $LexiconPath

if (-not (Test-Path $ClassificationCsv)) { throw "Classification CSV missing: $ClassificationCsv" }
$classification = @(Import-Csv $ClassificationCsv)
$latestBySha = [ordered]@{}
foreach ($row in $classification) {
  $sha = ($row.raw_sha256 + "").ToLowerInvariant()
  if ($sha) { $latestBySha[$sha] = $row }
}
$targets = @($latestBySha.Values | ForEach-Object {
  $_ | Add-Member -NotePropertyName static_rank -NotePropertyValue (Stable-Rank ($_.raw_sha256 + "") $Seed) -Force
  $_
} | Sort-Object static_rank)
if ($Smoke) { $targets = @($targets | Select-Object -First 20) }
elseif ($Limit -gt 0) { $targets = @($targets | Select-Object -First $Limit) }
if ($targets.Count -lt 1) { throw "No target rows available" }

$done = @{}
$decisionCountMap = @{}
$familyCountMap = @{}
$toolStatusCountMap = @{}
foreach ($toolName in @("sigcheck_status","diec_status","strings_status","capa_status","floss_status","yara_status","clam_status","defender_status","python_static_status")) {
  $toolStatusCountMap[$toolName] = @{}
}

function Add-Count($Map, [string]$Key) {
  $value = ($Key + "")
  if (-not $Map.ContainsKey($value)) { $Map[$value] = 0 }
  $Map[$value] = [int]$Map[$value] + 1
}

function Add-ResultStats($Row) {
  Add-Count $decisionCountMap ($Row.static_decision + "")
  $family = ($Row.static_hint_family + "")
  if ($family) { Add-Count $familyCountMap $family }
  foreach ($toolName in @("sigcheck_status","diec_status","strings_status","capa_status","floss_status","yara_status","clam_status","defender_status","python_static_status")) {
    Add-Count $toolStatusCountMap[$toolName] ($Row.$toolName + "")
  }
}

$savedRows = 0
if (Test-Path $ResultsPath) {
  Import-Csv $ResultsPath | ForEach-Object {
    $savedRows += 1
    $sha = ($_.raw_sha256 + "").ToLowerInvariant()
    if ($sha) { $done[$sha] = $true }
    Add-ResultStats $_
  }
}

$started = (Get-Date).ToUniversalTime().ToString("o")
$processedThisRun = 0

foreach ($target in $targets) {
  $sha = ($target.raw_sha256 + "").ToLowerInvariant()
  if ($done.ContainsKey($sha)) { continue }
  $sample = Join-Path $SamplesDir $sha
  $item = $null
  $pe = [ordered]@{}
  $pythonStatic = [ordered]@{ status="not_run"; imphash=""; tlsh=""; ssdeep=""; dotnet=""; imports=""; error="" }
  $sigcheck = [ordered]@{ status="not_run"; stdout=""; stderr="" }
  $diec = [ordered]@{ status="not_run"; stdout=""; stderr="" }
  $strings = [ordered]@{ status="not_run"; stdout=""; stderr="" }
  $capa = [ordered]@{ status="missing"; stdout=""; stderr="" }
  $floss = [ordered]@{ status="missing"; stdout=""; stderr="" }
  $yara = [ordered]@{ status="missing_rules"; stdout=""; stderr="" }
  $clam = [ordered]@{ status="not_run"; stdout=""; stderr="" }
  $defenderName = ""
  $defenderStatus = "not_run"
  $errorText = ""
  $latestRow = $null
  try {
    if (-not (Test-Path $sample)) { throw "missing staged sample" }
    $item = Get-Item $sample
    $actual = (Get-FileHash -Algorithm SHA256 $sample).Hash.ToLowerInvariant()
    if ($actual -ne $sha) { throw "sha256 mismatch actual=$actual expected=$sha" }
    $pe = Read-PeSummary $sample
    $pythonStatic = Invoke-PythonStatic $tool.python $sample
    $sigcheck = Invoke-Tool -Name "sigcheck" -Exe $tool.sigcheck -ToolArgs @("-accepteula","-nobanner","-q","-m","-h",$sample) -TimeoutSeconds $SigcheckTimeoutSeconds -StdoutMax 8000
    $diec = Invoke-Tool -Name "diec" -Exe $tool.diec -ToolArgs @("-j",$sample) -TimeoutSeconds $DieTimeoutSeconds -StdoutMax 12000
    $strings = Invoke-Tool -Name "strings" -Exe $tool.strings -ToolArgs @("-accepteula","-nobanner","-n","8",$sample) -TimeoutSeconds $StringsTimeoutSeconds -StdoutMax 20000
    if ($tool.capa) { $capa = Invoke-Tool -Name "capa" -Exe $tool.capa -ToolArgs @("-q",$sample) -TimeoutSeconds $CapaTimeoutSeconds -StdoutMax 10000 }
    if ($tool.floss) { $floss = Invoke-Tool -Name "floss" -Exe $tool.floss -ToolArgs @("-q","--no-static-strings",$sample) -TimeoutSeconds $FlossTimeoutSeconds -StdoutMax 12000 }
    if ($tool.yara -and $rulesArg) { $yara = Invoke-Tool -Name "yara" -Exe $tool.yara -ToolArgs @("-r","--no-warnings",$rulesArg,$sample) -TimeoutSeconds $YaraTimeoutSeconds -StdoutMax 10000 }
    if ($RunClam -and $tool.clamscan) { $clam = Invoke-Tool -Name "clamscan" -Exe $tool.clamscan -ToolArgs @("--no-summary",$sample) -TimeoutSeconds 60 -StdoutMax 6000 }
    if ($RunDefender) {
      try {
        $before = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
        Start-MpScan -ScanPath $sample -ScanType CustomScan -DisableRemediation -ErrorAction SilentlyContinue
        $after = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
        $new = @($after | Where-Object { $_.Resources -match [regex]::Escape($sha) -or $_.Resources -match [regex]::Escape($sample) })
        if ($new.Count -gt 0) { $defenderName = ($new | Select-Object -First 1).ThreatName }
        $defenderStatus = "completed"
      } catch {
        $defenderStatus = "error"
      }
    }

    $sourceHints = @{}
    foreach ($pair in @(
      @{name="defender"; value=$defenderName},
      @{name="sigcheck"; value=$sigcheck.stdout},
      @{name="die"; value=$diec.stdout},
      @{name="strings"; value=$strings.stdout},
      @{name="capa"; value=$capa.stdout},
      @{name="floss"; value=$floss.stdout},
      @{name="yara"; value=$yara.stdout},
      @{name="clam"; value=$clam.stdout}
    )) {
      $hits = Find-FamilyHints $pair.value $lexicon $pair.name
      foreach ($hit in $hits) {
        if (-not $sourceHints.ContainsKey($hit)) { $sourceHints[$hit] = New-Object System.Collections.Generic.List[string] }
        $sourceHints[$hit].Add($pair.name) | Out-Null
      }
    }
    $rankedHints = @($sourceHints.Keys | ForEach-Object {
      [pscustomobject]@{ family=$_; source_count=($sourceHints[$_] | Sort-Object -Unique).Count; sources=(($sourceHints[$_] | Sort-Object -Unique) -join ";") }
    } | Sort-Object -Property @{Expression="source_count";Descending=$true},family)
    $topFamily = ""
    $topSources = ""
    $topSourceCount = 0
    if ($rankedHints.Count -gt 0) {
      $topFamily = $rankedHints[0].family
      $topSources = $rankedHints[0].sources
      $topSourceCount = [int]$rankedHints[0].source_count
    }
    $staticDecision = "reject"
    $staticReason = "no_family_hint"
    if ($topFamily -and $topSourceCount -ge 3) {
      $staticDecision = "high_confidence_static"
      $staticReason = "three_or_more_static_sources"
    } elseif ($topFamily -and $topSourceCount -ge 2) {
      $staticDecision = "medium_confidence_static"
      $staticReason = "two_static_sources"
    } elseif ($topFamily) {
      $staticDecision = "review_only"
      $staticReason = "single_static_source"
    }

    $latestRow = [pscustomobject]@{
      raw_sha256=$sha
      source=$target.source
      split=$target.split
      file_kind=$target.file_kind
      raw_size_bytes=$item.Length
      file_magic=$pe.magic
      pe_signature=$pe.pe_signature
      pe_machine=$pe.machine
      pe_section_count=$pe.section_count
      pe_timestamp=$pe.timestamp
      pe_optional_magic=$pe.optional_magic
      pe_subsystem=$pe.subsystem
      imphash=$pythonStatic.imphash
      tlsh=$pythonStatic.tlsh
      ssdeep=$pythonStatic.ssdeep
      dotnet=$pythonStatic.dotnet
      import_dlls=$pythonStatic.imports
      static_hint_family=$topFamily
      static_hint_sources=$topSources
      static_hint_source_count=$topSourceCount
      all_static_hints=(($rankedHints | ForEach-Object { $_.family + ":" + $_.source_count }) -join ";")
      static_decision=$staticDecision
      static_decision_reason=$staticReason
      original_candidate_status=$target.candidate_status
      original_hint_family=($target.tool_hint_family + "").ToLowerInvariant()
      original_hint_sources=$target.hint_sources
      sigcheck_status=$sigcheck.status
      diec_status=$diec.status
      strings_status=$strings.status
      capa_status=$capa.status
      floss_status=$floss.status
      yara_status=$yara.status
      clam_status=$clam.status
      defender_status=$defenderStatus
      defender_name=$defenderName
      python_static_status=$pythonStatic.status
      yara_rules_dir=$rulesArg
      capability_summary=(Shorten $capa.stdout 700)
      packer_compiler_summary=(Shorten $diec.stdout 700)
      floss_summary=(Shorten $floss.stdout 700)
      yara_summary=(Shorten $yara.stdout 700)
      tool_errors=(Shorten (($sigcheck.stderr + " " + $diec.stderr + " " + $strings.stderr + " " + $capa.stderr + " " + $floss.stderr + " " + $yara.stderr + " " + $clam.stderr + " " + $pythonStatic.error) -join " ") 1200)
      error=""
    }
  } catch {
    $errorText = Shorten $_.Exception.Message 1000
    $latestRow = [pscustomobject]@{
      raw_sha256=$sha
      source=$target.source
      split=$target.split
      file_kind=$target.file_kind
      raw_size_bytes=""
      file_magic=$pe.magic
      pe_signature=$pe.pe_signature
      pe_machine=$pe.machine
      pe_section_count=$pe.section_count
      pe_timestamp=$pe.timestamp
      pe_optional_magic=$pe.optional_magic
      pe_subsystem=$pe.subsystem
      imphash=""
      tlsh=""
      ssdeep=""
      dotnet=""
      import_dlls=""
      static_hint_family=""
      static_hint_sources=""
      static_hint_source_count=0
      all_static_hints=""
      static_decision="reject"
      static_decision_reason="tool_error"
      original_candidate_status=$target.candidate_status
      original_hint_family=($target.tool_hint_family + "").ToLowerInvariant()
      original_hint_sources=$target.hint_sources
      sigcheck_status=$sigcheck.status
      diec_status=$diec.status
      strings_status=$strings.status
      capa_status=$capa.status
      floss_status=$floss.status
      yara_status=$yara.status
      clam_status=$clam.status
      defender_status=$defenderStatus
      defender_name=$defenderName
      python_static_status=$pythonStatic.status
      yara_rules_dir=$rulesArg
      capability_summary=""
      packer_compiler_summary=""
      floss_summary=""
      yara_summary=""
      tool_errors=""
      error=$errorText
    }
  } finally {
    $processedThisRun += 1
    $done[$sha] = $true
    $savedRows += 1
    $latest = $latestRow
    Add-ResultStats $latest
    if (-not (Test-Path $ResultsPath) -or (Get-Item $ResultsPath).Length -eq 0) {
      $latest | Export-Csv -NoTypeInformation -Encoding UTF8 $ResultsPath
    } else {
      $latest | Export-Csv -NoTypeInformation -Encoding UTF8 -Append $ResultsPath
    }
    [pscustomobject]@{
      updated_utc=(Get-Date).ToUniversalTime().ToString("o")
      started_utc=$started
      target_rows=$targets.Count
      saved_rows=$savedRows
      processed_this_run=$processedThisRun
      last_sha256=$sha
      smoke=[bool]$Smoke
      results_csv=$ResultsPath
    } | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $ProgressPath
  }
}

function CountMapToObjects($Map) {
  return @($Map.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{name=$_; count=[int]$Map[$_]} })
}

$decisionCounts = CountMapToObjects $decisionCountMap
$familyCounts = @($familyCountMap.Keys | ForEach-Object { [pscustomobject]@{family=$_; count=[int]$familyCountMap[$_]} } | Sort-Object count -Descending | Select-Object -First 80)
$toolCounts = @()
foreach ($toolName in @("sigcheck_status","diec_status","strings_status","capa_status","floss_status","yara_status","clam_status","defender_status","python_static_status")) {
  $toolCounts += [pscustomobject]@{
    tool=$toolName.Replace("_status","")
    counts=(CountMapToObjects $toolStatusCountMap[$toolName])
  }
}

[pscustomobject]@{
  completed_utc=(Get-Date).ToUniversalTime().ToString("o")
  started_utc=$started
  source_rows=$latestBySha.Count
  target_rows=$targets.Count
  saved_rows=$savedRows
  seed=$Seed
  smoke=[bool]$Smoke
  run_defender=[bool]$RunDefender
  run_clam=[bool]$RunClam
  timeouts_seconds=@{
    sigcheck=$SigcheckTimeoutSeconds
    die=$DieTimeoutSeconds
    strings=$StringsTimeoutSeconds
    capa=$CapaTimeoutSeconds
    floss=$FlossTimeoutSeconds
    yara=$YaraTimeoutSeconds
  }
  decision_counts=$decisionCounts
  top_static_hints=$familyCounts
  tool_status_counts=$toolCounts
  outputs=@{
    results="S:\results\deep_static_family_results.csv"
    summary="S:\results\deep_static_family_summary.json"
    report="S:\results\deep_static_family_report.md"
    progress="S:\results\deep_static_family_progress.json"
  }
} | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $SummaryPath

$lines = @()
$lines += "# VIBEX Deep Static Family Classification"
$lines += ""
$lines += "- Completed UTC: ``$((Get-Date).ToUniversalTime().ToString("o"))``"
$lines += "- Target rows: ``$($targets.Count)``"
$lines += "- Saved rows: ``$($savedRows)``"
$lines += "- Smoke: ``$([bool]$Smoke)``"
$lines += "- Raw malware stayed on sandbox ``S:``."
$lines += ""
$lines += "## Decision Counts"
foreach ($count in $decisionCounts) { $lines += "- ``$($count.name)``: $($count.count)" }
$lines += ""
$lines += "## Top Static Hints"
foreach ($count in ($familyCounts | Select-Object -First 30)) { $lines += "- ``$($count.family)``: $($count.count)" }
$lines += ""
$lines += "## Tool Status Counts"
foreach ($toolCount in $toolCounts) {
  $parts = @($toolCount.counts | ForEach-Object { "$($_.name)=$($_.count)" })
  $lines += "- ``$($toolCount.tool)``: $(($parts -join ', '))"
}
$lines | Set-Content -Encoding UTF8 $ReportPath

Write-Output "VIBEX_DEEP_STATIC_FAMILY_COMPLETE saved_rows=$($savedRows) target_rows=$($targets.Count)"
