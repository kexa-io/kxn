//! String helpers shared by everything that prints or stores rule content.

/// Cut a string to at most `max` bytes, never inside a character.
///
/// Slicing with `&s[..max]` panics when the index lands mid-character, and the
/// strings cut here are rule names, shell commands, API bodies and error
/// messages — none of them guaranteed ASCII. Byte-slicing them turned a rule
/// named with an accent, or a 1 MiB response body, into a crashed process.
///
/// The bound is in bytes because callers use it to cap memory and payload
/// sizes; the returned slice is always shorter or equal, and always valid.
pub fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// `truncate`, with an ellipsis when something was cut. The ellipsis counts
/// towards `max`, so the result never exceeds it.
pub fn truncate_ellipsis(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let room = max.saturating_sub(3);
    format!("{}...", truncate(s, room))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_short_strings_alone() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate_ellipsis("abc", 10), "abc");
    }

    /// The bug this exists for: `&s[..max]` panics when the cut lands inside a
    /// character. "é" is two bytes, so cutting at 1 is mid-character.
    #[test]
    fn never_cuts_inside_a_character() {
        assert_eq!(truncate("é", 1), "");
        assert_eq!(truncate("aé", 2), "a");
        assert_eq!(truncate("systemctl restart apachée", 24), "systemctl restart apach");
        // Every prefix length must be safe, whatever the bytes.
        let s = "déjà vu — ✓ naïve";
        for max in 0..=s.len() {
            let cut = truncate(s, max);
            assert!(cut.len() <= max);
            assert!(s.starts_with(cut));
        }
    }

    #[test]
    fn the_ellipsis_stays_within_the_bound() {
        let out = truncate_ellipsis("abcdefghij", 8);
        assert_eq!(out, "abcde...");
        assert!(out.len() <= 8);
    }
}
