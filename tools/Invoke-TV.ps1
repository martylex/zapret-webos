param(
    [Parameter(Mandatory=$true)][string]$Script,
    [string]$Log = 'diagnostics/tv-latest.txt',
    [Parameter(Mandatory=$true)][string]$TVAddress,
    [switch]$AcceptNewHostKey
)
$ErrorActionPreference = 'Stop'
$parsedTVAddress=$null
if (-not [Net.IPAddress]::TryParse($TVAddress,[ref]$parsedTVAddress) -or $parsedTVAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'TVAddress must be an IPv4 address.' }
$TVAddress=$parsedTVAddress.ToString()
$projectRoot = Split-Path -Parent $PSScriptRoot
$diagnostics = Join-Path $projectRoot 'diagnostics'
New-Item -ItemType Directory -Path $diagnostics -Force | Out-Null
$askpass = Join-Path $PSScriptRoot 'ssh-askpass.exe'
if (-not (Test-Path -LiteralPath $askpass)) {
    Add-Type -Path (Join-Path $PSScriptRoot 'ssh-askpass.cs') -OutputAssembly $askpass -OutputType ConsoleApplication
}
if (-not $env:FLOWSEAL_SSH_PASSWORD) { throw 'Set FLOWSEAL_SSH_PASSWORD for this process before connecting.' }
$env:SSH_ASKPASS = $askpass
$env:SSH_ASKPASS_REQUIRE = 'force'
$env:DISPLAY = 'flowseal:0'
$knownHosts = (Join-Path $projectRoot 'diagnostics/known_hosts').Replace('\','/')
$hostKeyPolicy = if ($AcceptNewHostKey) { 'accept-new' } else { 'yes' }
$scriptText = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Script)).Replace("`r`n", "`n")
# Write UTF-8 bytes directly; Windows PowerShell pipes otherwise replace non-ASCII bytes.
$start = New-Object Diagnostics.ProcessStartInfo
$start.FileName = (Get-Command ssh.exe).Source
$start.Arguments = '-T -o BatchMode=no -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=' + $hostKeyPolicy + ' -o UserKnownHostsFile="' + $knownHosts + '" root@' + $TVAddress + ' sh -s'
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [Diagnostics.Process]::Start($start)
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
$process.StandardInput.Write($scriptText + "`n")
$process.StandardInput.Close()
$process.WaitForExit()
$result = $stdout.Result + $stderr.Result
[IO.File]::WriteAllText((Join-Path $projectRoot $Log), $result, (New-Object Text.UTF8Encoding($false)))
Write-Output $result
exit $process.ExitCode
