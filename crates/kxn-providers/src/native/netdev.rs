//! Network devices reached over SSH: routers, switches and firewalls.
//!
//! They have no POSIX shell, so none of the Linux collectors apply. kxn
//! identifies the operating system from the output of a version command and
//! returns one `device` object — vendor, os, version, model, hostname,
//! serial — that rules (CVE packs first) can judge like `packages_cve`.

use regex::Regex;
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetOs {
    Ios,
    IosXe,
    NxOs,
    Asa,
    Eos,
    Junos,
    SrLinux,
    RouterOs,
    FortiOs,
    PanOs,
}

impl NetOs {
    /// The `os` of `ssh://user@host?os=<name>`.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "ios" => Self::Ios,
            "iosxe" => Self::IosXe,
            "nxos" | "nexus" => Self::NxOs,
            "asa" | "ftd" => Self::Asa,
            "eos" | "arista" => Self::Eos,
            "junos" | "juniper" => Self::Junos,
            "srlinux" | "srl" | "nokia" => Self::SrLinux,
            "routeros" | "mikrotik" => Self::RouterOs,
            "fortios" | "fortigate" | "fortinet" => Self::FortiOs,
            "panos" | "paloalto" => Self::PanOs,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::IosXe => "ios-xe",
            Self::NxOs => "nx-os",
            Self::Asa => "asa",
            Self::Eos => "eos",
            Self::Junos => "junos",
            Self::SrLinux => "srlinux",
            Self::RouterOs => "routeros",
            Self::FortiOs => "fortios",
            Self::PanOs => "pan-os",
        }
    }

    pub fn vendor(self) -> &'static str {
        match self {
            Self::Ios | Self::IosXe | Self::NxOs | Self::Asa => "cisco",
            Self::Eos => "arista",
            Self::Junos => "juniper",
            Self::SrLinux => "nokia",
            Self::RouterOs => "mikrotik",
            Self::FortiOs => "fortinet",
            Self::PanOs => "paloaltonetworks",
        }
    }

    /// The read-only command whose output describes the device.
    pub fn version_command(self) -> &'static str {
        match self {
            Self::RouterOs => "/system resource print",
            Self::FortiOs => "get system status",
            Self::PanOs => "show system info",
            _ => "show version",
        }
    }

    /// A second command for what the first one leaves out.
    pub fn hostname_command(self) -> Option<&'static str> {
        match self {
            Self::RouterOs => Some("/system identity print"),
            Self::Eos => Some("show hostname"),
            _ => None,
        }
    }
}

/// Tried in this order on a host that is not Linux, until one output is
/// recognised. All are read-only.
pub const PROBES: &[&str] = &[
    "show version",
    "/system resource print",
    "get system status",
    "show system info",
];

/// Which operating system printed this version output.
pub fn identify(output: &str) -> Option<NetOs> {
    let has = |s: &str| output.contains(s);
    Some(if has("Cisco Adaptive Security Appliance") {
        NetOs::Asa
    } else if has("Cisco Nexus Operating System") || has("NX-OS") {
        NetOs::NxOs
    } else if has("Cisco IOS XE Software") || has("Cisco IOS-XE software") {
        NetOs::IosXe
    } else if has("Cisco IOS Software") || has("Cisco Internetwork Operating System") {
        NetOs::Ios
    } else if has("Arista") && has("Software image version") {
        NetOs::Eos
    } else if has("Junos:") || has("JUNOS ") {
        NetOs::Junos
    } else if has("SR Linux") || (has("Chassis Type") && has("Software Version")) {
        NetOs::SrLinux
    } else if has("board-name:") && has("version:") {
        NetOs::RouterOs
    } else if output.lines().any(|l| l.trim_start().starts_with("Version: Forti")) {
        NetOs::FortiOs
    } else if has("sw-version:") {
        NetOs::PanOs
    } else {
        return None;
    })
}

/// The value after `key<sep>` on the first line that starts with `key`.
fn field(output: &str, key: &str, sep: char) -> Option<String> {
    output.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix(key)?;
        let rest = rest.trim_start().strip_prefix(sep)?;
        Some(rest.trim().to_string()).filter(|v| !v.is_empty())
    })
}

fn capture(output: &str, pattern: &str) -> Option<String> {
    let re = Regex::new(pattern).ok()?;
    re.captures(output)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().trim_end_matches(',').to_string())
        .filter(|v| !v.is_empty())
}

/// The `device` object. `extra` is the output of `hostname_command`, if any.
pub fn parse(os: NetOs, output: &str, extra: Option<&str>) -> Value {
    let output = &output.replace('\r', "");
    let mut d = Map::new();
    let mut put = |k: &str, v: Option<String>| {
        if let Some(v) = v {
            d.insert(k.to_string(), Value::String(v));
        }
    };

    match os {
        NetOs::Ios | NetOs::IosXe => {
            // IOS-XE 3.x prints both its own and the IOSd version; the XE one
            // is what Cisco advisories name.
            let xe = capture(output, r"Cisco IOS[ -]XE Software,? Version ([^\s,]+)");
            let ios = capture(output, r"Cisco IOS Software.*?Version ([^\s,]+)");
            put("version", xe.clone().or_else(|| ios.clone()));
            if xe.is_some() {
                put("ios_version", ios);
            }
            put("hostname", capture(output, r"(?m)^(\S+) uptime is"));
            put("uptime", capture(output, r"(?m)^\S+ uptime is (.+)$"));
            put("model", capture(output, r"(?mi)^cisco (\S+) .*processor"));
            put("serial", capture(output, r"Processor board ID (\S+)"));
            put("image", capture(output, r#"System image file is "([^"]+)""#));
        }
        NetOs::NxOs => {
            put(
                "version",
                capture(output, r"(?m)NXOS: version (\S+)")
                    .or_else(|| capture(output, r"(?m)^\s*system:\s+version (\S+)")),
            );
            put("hostname", capture(output, r"Device name: (\S+)"));
            put("model", capture(output, r"(?mi)^\s*cisco (.+?) [Cc]hassis"));
            put("serial", capture(output, r"Processor Board ID (\S+)"));
            put("uptime", capture(output, r"Kernel uptime is (.+)"));
        }
        NetOs::Asa => {
            put("version", capture(output, r"Adaptive Security Appliance Software Version (\S+)"));
            put("hostname", capture(output, r"(?m)^(\S+) up \d"));
            put("uptime", capture(output, r"(?m)^\S+ up (\d.+)$"));
            put("model", capture(output, r"Hardware:\s+([^,]+)"));
            put("serial", capture(output, r"Serial Number: (\S+)"));
        }
        NetOs::Eos => {
            put("version", capture(output, r"Software image version: (\S+)"));
            put("model", capture(output, r"(?m)^Arista (\S+)"));
            put("serial", capture(output, r"Serial number:\s*(\S+)"));
            put("hostname", extra.and_then(|e| capture(e, r"Hostname: (\S+)")));
        }
        NetOs::Junos => {
            put(
                "version",
                capture(output, r"(?m)^Junos: (\S+)")
                    .or_else(|| capture(output, r"JUNOS [^\[]*\[([^\]]+)\]")),
            );
            put("hostname", capture(output, r"(?m)^Hostname: (\S+)"));
            put("model", capture(output, r"(?m)^Model: (\S+)"));
        }
        NetOs::SrLinux => {
            put("version", field(output, "Software Version", ':').map(|v| v.trim_start_matches('v').to_string()));
            put("hostname", field(output, "Hostname", ':'));
            put("model", field(output, "Chassis Type", ':'));
            put("serial", field(output, "Serial Number", ':'));
            put("build", field(output, "Build Number", ':'));
        }
        NetOs::RouterOs => {
            // `version: 7.16.2 (stable)`
            let full = field(output, "version", ':');
            put("version", full.as_ref().and_then(|v| v.split_whitespace().next().map(String::from)));
            put("channel", full.as_ref().and_then(|v| capture(v, r"\((\w+)\)")));
            put("model", field(output, "board-name", ':'));
            put("architecture", field(output, "architecture-name", ':'));
            put("uptime", field(output, "uptime", ':'));
            put("hostname", extra.and_then(|e| field(e, "name", ':')));
        }
        NetOs::FortiOs => {
            // `Version: FortiGate-VM64 v7.4.3,build2573,240201 (GA.F)`
            let line = field(output, "Version", ':');
            put("model", line.as_ref().and_then(|l| l.split_whitespace().next().map(String::from)));
            put("version", line.as_ref().and_then(|l| capture(l, r"v(\d[\w.]*)")));
            put("build", line.as_ref().and_then(|l| capture(l, r"build(\d+)")));
            put("hostname", field(output, "Hostname", ':'));
            put("serial", field(output, "Serial-Number", ':'));
        }
        NetOs::PanOs => {
            put("version", field(output, "sw-version", ':'));
            put("hostname", field(output, "hostname", ':'));
            put("model", field(output, "model", ':'));
            put("serial", field(output, "serial", ':'));
            put("uptime", field(output, "uptime", ':'));
        }
    }

    d.insert("vendor".into(), Value::String(os.vendor().into()));
    d.insert("os".into(), Value::String(os.name().into()));
    let raw: String = output.trim().chars().take(8000).collect();
    d.insert("raw".into(), Value::String(raw));
    Value::Object(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `show version` of route-views.routeviews.org, a public Cisco ASR1004
    /// route server (University of Oregon Route Views), captured 2026-11-20.
    const ROUTE_VIEWS: &str = include_str!("testdata/cisco-iosxe-routeviews.txt");

    #[test]
    fn cisco_ios_xe_route_server() {
        assert_eq!(identify(ROUTE_VIEWS), Some(NetOs::IosXe));
        let d = parse(NetOs::IosXe, ROUTE_VIEWS, None);
        assert_eq!(d["vendor"], "cisco");
        assert_eq!(d["os"], "ios-xe");
        assert_eq!(d["version"], "03.16.10.S");
        assert_eq!(d["ios_version"], "15.5(3)S10");
        assert_eq!(d["hostname"], "route-views");
        assert_eq!(d["model"], "ASR1004");
        assert_eq!(d["serial"], "FXS1739Q3LN");
    }

    #[test]
    fn names_and_unknown_output() {
        assert_eq!(NetOs::from_name("IOS-XE"), Some(NetOs::IosXe));
        assert_eq!(NetOs::from_name("mikrotik"), Some(NetOs::RouterOs));
        assert_eq!(NetOs::from_name("linux"), None);
        assert_eq!(identify("bash: show: command not found"), None);
    }
}
