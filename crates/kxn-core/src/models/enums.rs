use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level for a rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info = 0,
    Warning = 1,
    Error = 2,
    Fatal = 3,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Level::Info => write!(f, "INFO"),
            Level::Warning => write!(f, "WARNING"),
            Level::Error => write!(f, "ERROR"),
            Level::Fatal => write!(f, "FATAL"),
        }
    }
}

impl Level {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Level::Info,
            1 => Level::Warning,
            2 => Level::Error,
            _ => Level::Fatal,
        }
    }
}

/// All supported condition types (ported from Kexa ConditionEnum)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Condition {
    Equal,
    Different,
    Include,
    NotInclude,
    IncludeNotSensitive,
    NotIncludeNotSensitive,
    Sup,
    Inf,
    SupOrEqual,
    InfOrEqual,
    StartsWith,
    NotStartsWith,
    EndsWith,
    NotEndsWith,
    Regex,
    All,
    NotAny,
    Some,
    One,
    Count,
    CountSup,
    CountInf,
    CountSupOrEqual,
    CountInfOrEqual,
    DateEqual,
    DateSup,
    DateInf,
    DateSupOrEqual,
    DateInfOrEqual,
    Interval,
    DateInterval,
    In,
    NotIn,
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", self));
        write!(f, "{}", s)
    }
}

/// Logical operators for ParentRule grouping
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Operator {
    And,
    Or,
    Xor,
    Nand,
    Nor,
    Xnor,
    Not,
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operator::And => write!(f, "AND"),
            Operator::Or => write!(f, "OR"),
            Operator::Xor => write!(f, "XOR"),
            Operator::Nand => write!(f, "NAND"),
            Operator::Nor => write!(f, "NOR"),
            Operator::Xnor => write!(f, "XNOR"),
            Operator::Not => write!(f, "NOT"),
        }
    }
}
