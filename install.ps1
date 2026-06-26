# Corv Client installer for Windows.
#   irm https://raw.githubusercontent.com/khalid-src/corv-client/main/install.ps1 | iex
#
# Downloads the prebuilt binary from the latest GitHub release, verifies its
# SHA-256 checksum, and installs it into a per-user directory.
$ErrorActionPreference = "Stop"

$repo = "khalid-src/corv-client"
$base = "https://github.com/$repo/releases/latest/download"
$asset = "corv-windows-amd64.exe"
$installDir = Join-Path $env:LOCALAPPDATA "Programs\Corv"
$target = Join-Path $installDir "corv.exe"
$legacyTarget = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\corv.exe"

function Remove-FileIfExists($path) {
	if (Test-Path -LiteralPath $path) {
		Remove-Item -LiteralPath $path -Force
	}
}

function Stop-CorvFromPath($path) {
	$resolved = $null
	if (Test-Path -LiteralPath $path) {
		$resolved = (Resolve-Path -LiteralPath $path).Path
	}
	if (-not $resolved) {
		return
	}

	$running = Get-Process corv -ErrorAction SilentlyContinue | Where-Object {
		try {
			$_.Path -and ((Resolve-Path -LiteralPath $_.Path -ErrorAction Stop).Path -eq $resolved)
		} catch {
			$false
		}
	}

	if ($running) {
		Write-Host "Stopping running corv.exe before update ..."
		$running | Stop-Process -Force
		Start-Sleep -Milliseconds 500
	}
}

function Add-ToUserPath($dir) {
	$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
	$parts = @()
	if ($userPath) {
		$parts = $userPath -split ";" | Where-Object { $_ -and ($_.TrimEnd("\") -ine $dir.TrimEnd("\")) }
	}

	$newPath = (@($dir) + $parts) -join ";"
	[Environment]::SetEnvironmentVariable("Path", $newPath, "User")

	$processParts = $env:Path -split ";" | Where-Object { $_ -and ($_.TrimEnd("\") -ine $dir.TrimEnd("\")) }
	$env:Path = (@($dir) + $processParts) -join ";"
}

New-Item -ItemType Directory -Force -Path $installDir | Out-Null

$tmpExe = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
$tmpSums = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
$tmpNew = "$target.new"

try {
	Write-Host "Downloading $asset ..."
	Invoke-WebRequest -Uri "$base/$asset" -OutFile $tmpExe -UseBasicParsing
	Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $tmpSums -UseBasicParsing

	# Read checksums explicitly as text. On some PowerShell/.NET combinations,
	# Invoke-WebRequest.Content for extensionless files is a byte array.
	$sums = [System.IO.File]::ReadAllText($tmpSums, [System.Text.Encoding]::UTF8)
	$line = $sums -split "`r?`n" | Where-Object { $_ -match "(^|\s)\*$([regex]::Escape($asset))$|(^|\s)$([regex]::Escape($asset))$" } | Select-Object -First 1
	$expected = if ($line) { (($line.Trim() -split "\s+")[0]).ToLowerInvariant() } else { "" }
	$actual = (Get-FileHash -LiteralPath $tmpExe -Algorithm SHA256).Hash.ToLowerInvariant()

	if (-not $expected) {
		throw "corv: checksum entry for $asset not found in SHA256SUMS"
	}
	if ($expected -ne $actual) {
		throw "corv: checksum verification failed; refusing to install"
	}

	Stop-CorvFromPath $target
	Stop-CorvFromPath $legacyTarget

	Copy-Item -LiteralPath $tmpExe -Destination $tmpNew -Force
	Unblock-File -LiteralPath $tmpNew

	Remove-FileIfExists $target
	Move-Item -LiteralPath $tmpNew -Destination $target -Force

	# Older installers used WindowsApps. Remove that copy when possible so PATH
	# does not pick up a stale binary before the new install directory.
	if ((Test-Path -LiteralPath $legacyTarget) -and ((Resolve-Path -LiteralPath $legacyTarget).Path -ne (Resolve-Path -LiteralPath $target).Path)) {
		try {
			Remove-Item -LiteralPath $legacyTarget -Force
		} catch {
			Write-Warning "Could not remove old install at $legacyTarget. If 'corv --version' shows an old version, remove that file manually."
		}
	}

	Add-ToUserPath $installDir

	Write-Host "Installed corv to $target"
	Write-Host "Run: corv"
} finally {
	Remove-FileIfExists $tmpExe
	Remove-FileIfExists $tmpSums
	Remove-FileIfExists $tmpNew
}
