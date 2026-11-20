//! Container image references, split the way rules need them.
//!
//! `gitlab/gitlab-ce:17.5.1-ce.0` running somewhere is a GitLab 17.5.1: a
//! rule on `name = gitlab/gitlab-ce` and `version` sees it whether it runs in
//! Kubernetes or Docker, from Docker Hub or a mirror. Shared by the
//! `container_images` object of both providers.

use serde_json::{json, Value};

/// The parts of an image reference.
#[derive(Debug, PartialEq, Eq)]
pub struct ImageRef {
    /// `docker.io`, `ghcr.io`, `192.168.1.5:5000`…
    pub registry: String,
    /// The path in the registry: `library/nginx`, `gitlab/gitlab-ce`.
    pub path: String,
    /// What a person calls the image: the path without `library/` on Docker
    /// Hub (`nginx`, `gitlab/gitlab-ce`), registry included elsewhere
    /// (`ghcr.io/berriai/litellm`).
    pub name: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

pub fn parse(reference: &str) -> ImageRef {
    let reference = reference.trim();
    let (rest, digest) = match reference.split_once('@') {
        Some((r, d)) => (r, Some(d.to_string())),
        None => (reference, None),
    };
    // A tag is the part after the last ':' when that ':' comes after the
    // last '/': `host:5000/app` has a port, not a tag.
    let (rest, tag) = match rest.rfind(':') {
        Some(i) if !rest[i..].contains('/') => (&rest[..i], Some(rest[i + 1..].to_string())),
        _ => (rest, None),
    };
    // The first component is a registry when it looks like a host.
    let (registry, path) = match rest.split_once('/') {
        Some((first, path)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            (first.to_string(), path.to_string())
        }
        _ => ("docker.io".to_string(), rest.to_string()),
    };
    let registry = if registry == "index.docker.io" || registry == "registry-1.docker.io" {
        "docker.io".to_string()
    } else {
        registry
    };
    let path = if registry == "docker.io" && !path.contains('/') {
        format!("library/{path}")
    } else {
        path
    };
    let name = if registry == "docker.io" {
        path.strip_prefix("library/").unwrap_or(&path).to_string()
    } else {
        format!("{registry}/{path}")
    };
    ImageRef { registry, path, name, tag, digest }
}

/// The version a tag carries, if any: `17.5.1-ce.0` → 17.5.1, `v1.8.2` →
/// 1.8.2, `1.27-alpine` → 1.27, `11` → 11. `latest`, commit hashes and
/// branch names carry none.
pub fn version_of(tag: &str) -> Option<String> {
    let t = tag.strip_prefix('v').unwrap_or(tag);
    let end = t.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(t.len());
    let v = t[..end].trim_end_matches('.');
    // A bare hash like `3f013886` starts with digits too: a version is
    // dotted, or a short major (`11`), not a run of hex.
    let looks_like_version = !v.is_empty()
        && (v.contains('.') || (v.len() <= 3 && end == t.len()) || t[end..].starts_with('-'));
    let hexish = t.len() >= 7 && t.chars().all(|c| c.is_ascii_hexdigit());
    (looks_like_version && !hexish).then(|| v.to_string())
}

/// The fields every `container_images` row carries.
pub fn fields(reference: &str) -> Value {
    let r = parse(reference);
    json!({
        "image": reference,
        "registry": r.registry,
        "repository": r.path,
        "name": r.name,
        "tag": r.tag,
        "version": r.tag.as_deref().and_then(version_of),
        "latest_tag": r.tag.as_deref().is_none_or(|t| t == "latest"),
        "digest_pinned": r.digest.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_seen_in_a_real_cluster() {
        let r = parse("192.168.100.5:30500/patrick/gridcraft-web:0.19.1");
        assert_eq!((r.registry.as_str(), r.path.as_str()), ("192.168.100.5:30500", "patrick/gridcraft-web"));
        assert_eq!(r.tag.as_deref(), Some("0.19.1"));
        let r = parse("docker.io/crowdsecurity/crowdsec:v1.8.2");
        assert_eq!((r.name.as_str(), r.tag.as_deref()), ("crowdsecurity/crowdsec", Some("v1.8.2")));
        let r = parse("nginx");
        assert_eq!((r.path.as_str(), r.name.as_str(), r.tag), ("library/nginx", "nginx", None));
        let r = parse("codeberg.org/forgejo/forgejo:11");
        assert_eq!(r.name, "codeberg.org/forgejo/forgejo");
        let r = parse("ghcr.io/berriai/litellm@sha256:abc");
        assert_eq!((r.tag, r.digest.as_deref()), (None, Some("sha256:abc")));
        let r = parse("localhost:5000/app");
        assert_eq!((r.registry.as_str(), r.tag), ("localhost:5000", None));
    }

    #[test]
    fn versions_in_tags() {
        assert_eq!(version_of("17.5.1-ce.0").as_deref(), Some("17.5.1"));
        assert_eq!(version_of("v1.8.2").as_deref(), Some("1.8.2"));
        assert_eq!(version_of("1.27-alpine").as_deref(), Some("1.27"));
        assert_eq!(version_of("11").as_deref(), Some("11"));
        assert_eq!(version_of("1.0.0-beta.11-1").as_deref(), Some("1.0.0"));
        assert_eq!(version_of("latest"), None);
        assert_eq!(version_of("3f013886"), None);
        assert_eq!(version_of("bc649a46c548e75e06ebe914d34496f6435332fd"), None);
        assert_eq!(version_of("dev-7d68d124-postgres"), None);
        assert_eq!(version_of("migr"), None);
        assert_eq!(version_of("d871ff38"), None);
    }
}
