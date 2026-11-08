//! Reading an operating system's own configuration.
//!
//! Each module owns a command and the parser for its output, together: a
//! collector whose command and parser drift apart is worse than no collector,
//! because it reports on something other than what it measured.
//!
//! They share one rule. When the software is not installed, or the information
//! cannot be read, the collector returns an empty list — never a partial
//! object. The engine reads a missing property as an empty string, so an object
//! with holes in it invents violations; an empty list is reported as "not
//! evaluated", which is the truth.

pub(crate) mod apache;
pub(crate) mod linux;
pub(crate) mod nginx;
pub(crate) mod sshmon;
