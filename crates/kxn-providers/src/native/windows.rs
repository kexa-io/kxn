//! Windows hosts reached over SSH (the OpenSSH server built into Windows).
//!
//! Each collector is a short PowerShell script that prints JSON. It runs
//! through `powershell -EncodedCommand`, which works whether sshd's default
//! shell is cmd.exe or PowerShell and needs no quoting. Everything is read
//! with a standard account: the OS build, installed updates, installed
//! software. scripts/windows/enable-ssh.ps1 turns sshd on.

use base64::Engine;
use serde_json::Value;

/// The object types of a Windows host.
pub const TYPES: &[&str] = &["windows_info", "windows_hotfixes", "windows_software"];

/// Output as UTF-8, whatever the console code page: software names are not
/// all ASCII.
const PREAMBLE: &str = "$ProgressPreference='SilentlyContinue'; \
    [Console]::OutputEncoding=[Text.Encoding]::UTF8; ";

/// OS build down to the update revision (UBR): 20348.2700 is what Microsoft
/// advisories and KB articles name. Registry only: over SSH, a standard
/// account is denied WMI (Get-CimInstance, Get-HotFix) and COM, not the
/// registry.
const INFO: &str = r#"
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$tcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction SilentlyContinue
$build = [int]$cv.CurrentBuildNumber
# Windows 11 still says "Windows 10" in ProductName.
$caption = $cv.ProductName
if ($build -ge 22000 -and $caption -like 'Windows 10*') { $caption = $caption -replace '^Windows 10', 'Windows 11' }
$release = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
$os = [Environment]::OSVersion.Version
[pscustomobject]@{
  caption = $caption
  version = "$($os.Major).$($os.Minor).$build"
  build = $build
  ubr = [int]$cv.UBR
  full_build = "$build.$($cv.UBR)"
  display_version = $release
  edition = $cv.EditionID
  installation_type = $cv.InstallationType
  architecture = $env:PROCESSOR_ARCHITECTURE
  hostname = $env:COMPUTERNAME
  dns_domain = $tcp.Domain
  last_boot = (Get-Date).ToUniversalTime().AddMilliseconds(-[Environment]::TickCount64).ToString('o')
  install_date = [DateTimeOffset]::FromUnixTimeSeconds([int64]$cv.InstallDate).UtcDateTime.ToString('o')
} | ConvertTo-Json -Compress
"#;

/// Updates from the Component Based Servicing store, one row per KB (and
/// one for the latest cumulative update, `RollupFix`). Readable by any
/// account, unlike Get-HotFix.
const HOTFIXES: &str = r#"
$states = @{ 112 = 'installed'; 80 = 'superseded'; 64 = 'staged'; 32 = 'resolved'; 0 = 'absent' }
$root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
$h = Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
  if ($_.PSChildName -match '_for_(KB\d+|RollupFix)~[^~]*~[^~]*~[^~]*~([\d.]+)$') {
    $hi = $_.GetValue('InstallTimeHigh'); $lo = $_.GetValue('InstallTimeLow')
    $when = $null
    if ($hi -ne $null -and $lo -ne $null) {
      # 0xFFFFFFFF would be -1 (Int32) in PowerShell: the mask is a long.
      $when = [DateTime]::FromFileTimeUtc(([int64]$hi -shl 32) -bor ([int64]$lo -band 4294967295L)).ToString('yyyy-MM-dd')
    }
    $state = [int]$_.GetValue('CurrentState')
    [pscustomobject]@{
      id = $Matches[1]
      package_version = $Matches[2]
      state = if ($states.ContainsKey($state)) { $states[$state] } else { "$state" }
      installed_on = $when
    }
  }
} | Sort-Object id, package_version -Unique
ConvertTo-Json -InputObject @($h) -Compress
"#;

/// Programs as "Apps & features" lists them, 64- and 32-bit: Exchange,
/// SharePoint, SQL Server, Office, agents… with their versions.
const SOFTWARE: &str = r#"
$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$s = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
  [pscustomobject]@{
    name = $_.DisplayName
    version = $_.DisplayVersion
    publisher = $_.Publisher
    install_date = $_.InstallDate
  }
} | Sort-Object name, version -Unique
ConvertTo-Json -InputObject @($s) -Compress
"#;

/// The command line that runs a collector.
pub fn command(resource_type: &str) -> Option<String> {
    let script = match resource_type {
        "windows_info" => INFO,
        "windows_hotfixes" => HOTFIXES,
        "windows_software" => SOFTWARE,
        _ => return None,
    };
    Some(encoded(&format!("{PREAMBLE}{script}")))
}

/// `powershell -EncodedCommand`: the script as base64 of UTF-16LE.
fn encoded(script: &str) -> String {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    format!(
        "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
        base64::engine::general_purpose::STANDARD.encode(utf16)
    )
}

/// The JSON a collector printed, as a list of objects.
pub fn parse(output: &str) -> Vec<Value> {
    let start = output.find(['{', '[']);
    let Some(start) = start else { return vec![] };
    match serde_json::from_str::<Value>(output[start..].trim()) {
        Ok(Value::Array(items)) => items.into_iter().filter(|v| v.is_object()).collect(),
        Ok(v @ Value::Object(_)) => vec![v],
        _ => vec![],
    }
}

/// `ver` on Windows: `Microsoft Windows [Version 10.0.20348.2700]`.
pub fn is_windows(ver_output: &str) -> bool {
    ver_output.contains("Microsoft Windows [Version")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_command_is_utf16le_base64() {
        let cmd = encoded("Write-Output 'é'");
        let b64 = cmd.rsplit(' ').next().unwrap();
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        let units: Vec<u16> = bytes.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap(), "Write-Output 'é'");
        assert!(command("windows_info").unwrap().starts_with("powershell -NoProfile"));
        assert!(command("users").is_none());
    }

    #[test]
    fn parse_skips_noise_and_wraps_one_object() {
        assert_eq!(parse("#< CLIXML\r\n{\"build\":20348}").len(), 1);
        assert_eq!(parse("[{\"id\":\"KB1\"},{\"id\":\"KB2\"}]").len(), 2);
        assert!(parse("[]").is_empty());
        assert!(parse("'powershell' is not recognized").is_empty());
        assert!(is_windows("\r\nMicrosoft Windows [Version 10.0.20348.2700]\r\n"));
    }
}
