//! Zero-dependency human-readable duration parser, formatter, and `serde` helpers.
//!
//! Replaces `humantime` for configuration serialization/deserialization
//! (e.g. `"30s"`, `"500ms"`, `"1h 30m 5s"`, `"24h"`).

use std::fmt;
use std::time::Duration;

/// Error returned when parsing a human-readable duration string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurationParseError {
    message: String,
}

impl DurationParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DurationParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DurationParseError {}

const NANOS_PER_SEC: u128 = 1_000_000_000;
const NANOS_PER_MILLI: u128 = 1_000_000;
const NANOS_PER_MICRO: u128 = 1_000;

/// Parses a human-readable duration string (e.g., `"30s"`, `"500ms"`, `"1h 30m 5s"`, `"2m30s"`).
pub fn parse_duration(input: &str) -> Result<Duration, DurationParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(DurationParseError::new("Duration string is empty"));
    }

    let mut total_nanos: u128 = 0;
    let mut rest = s;

    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }

        let num_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if num_end == 0 {
            return Err(DurationParseError::new(format!(
                "Expected unsigned integer in duration '{input}'"
            )));
        }
        let value: u128 = rest[..num_end].parse().map_err(|_| {
            DurationParseError::new(format!("Numeric overflow in duration '{input}'"))
        })?;

        rest = rest[num_end..].trim_start();
        if rest.is_empty() {
            return Err(DurationParseError::new(format!(
                "Missing time unit in duration '{input}'"
            )));
        }

        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c.is_whitespace())
            .unwrap_or(rest.len());
        let unit = &rest[..unit_end];
        rest = &rest[unit_end..];

        let unit_nanos: u128 = match unit {
            "ns" | "nsec" | "nsecs" | "nanosecond" | "nanoseconds" => 1,
            "us" | "µs" | "μs" | "usec" | "usecs" | "microsecond" | "microseconds" => {
                NANOS_PER_MICRO
            }
            "ms" | "msec" | "msecs" | "millisecond" | "milliseconds" => NANOS_PER_MILLI,
            "s" | "sec" | "secs" | "second" | "seconds" => NANOS_PER_SEC,
            "m" | "min" | "mins" | "minute" | "minutes" => 60 * NANOS_PER_SEC,
            "h" | "hr" | "hrs" | "hour" | "hours" => 3_600 * NANOS_PER_SEC,
            "d" | "day" | "days" => 86_400 * NANOS_PER_SEC,
            "w" | "week" | "weeks" => 7 * 86_400 * NANOS_PER_SEC,
            "M" | "month" | "months" => 2_630_016 * NANOS_PER_SEC,
            "y" | "year" | "years" => 31_557_600 * NANOS_PER_SEC,
            _ => {
                return Err(DurationParseError::new(format!(
                    "Unknown duration unit '{unit}' in '{input}'"
                )));
            }
        };

        let term_nanos = value
            .checked_mul(unit_nanos)
            .ok_or_else(|| DurationParseError::new(format!("Duration overflow in '{input}'")))?;
        total_nanos = total_nanos
            .checked_add(term_nanos)
            .ok_or_else(|| DurationParseError::new(format!("Duration overflow in '{input}'")))?;
    }

    let secs_u128 = total_nanos / NANOS_PER_SEC;
    let subsec_nanos = (total_nanos % NANOS_PER_SEC) as u32;
    let secs = u64::try_from(secs_u128).map_err(|_| {
        DurationParseError::new(format!("Duration exceeds u64 seconds in '{input}'"))
    })?;

    Ok(Duration::new(secs, subsec_nanos))
}

/// Formats a [`Duration`] into a compact human-readable string (e.g., `"30s"`, `"1m 30s"`, `"500ms"`).
#[must_use]
pub fn format_duration(duration: Duration) -> String {
    if duration.is_zero() {
        return "0s".to_string();
    }

    let mut parts = Vec::new();
    let mut secs = duration.as_secs();

    let days = secs / 86_400;
    secs %= 86_400;
    let hours = secs / 3_600;
    secs %= 3_600;
    let mins = secs / 60;
    secs %= 60;

    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if mins > 0 {
        parts.push(format!("{mins}m"));
    }
    if secs > 0 {
        parts.push(format!("{secs}s"));
    }

    let mut nanos = duration.subsec_nanos();
    let millis = nanos / 1_000_000;
    nanos %= 1_000_000;
    let micros = nanos / 1_000;
    nanos %= 1_000;

    if millis > 0 {
        parts.push(format!("{millis}ms"));
    }
    if micros > 0 {
        parts.push(format!("{micros}us"));
    }
    if nanos > 0 {
        parts.push(format!("{nanos}ns"));
    }

    parts.join(" ")
}

/// `serde` helper for `std::time::Duration` serialized as a human-readable string.
pub mod serde_duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    use super::{format_duration, parse_duration};

    pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_duration(*duration))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let text = String::deserialize(d)?;
        parse_duration(&text).map_err(serde::de::Error::custom)
    }
}

/// `serde` helper for `Option<std::time::Duration>` serialized as an optional human-readable string.
pub mod serde_duration_opt {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    use super::{format_duration, parse_duration};

    pub fn serialize<S: Serializer>(duration: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match duration {
            Some(d) => s.serialize_str(&format_duration(*d)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(text) => parse_duration(&text)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format_durations_roundtrip() {
        let cases = [
            ("0s", Duration::ZERO),
            ("500ms", Duration::from_millis(500)),
            ("30s", Duration::from_secs(30)),
            ("1d", Duration::from_secs(86_400)),
            ("1h 30m 5s", Duration::from_secs(5405)),
            ("1d 2h 3m 4s", Duration::from_secs(86_400 + 7_200 + 180 + 4)),
            ("100us", Duration::from_micros(100)),
            ("50ns", Duration::from_nanos(50)),
        ];
        for (text, expected) in cases {
            let parsed = parse_duration(text).expect("valid duration");
            assert_eq!(parsed, expected, "for '{text}'");
            assert_eq!(format_duration(parsed), text);
        }

        assert_eq!(parse_duration("2m30s").unwrap(), Duration::from_secs(150));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_duration("100µs").unwrap(), Duration::from_micros(100));
        assert_eq!(
            parse_duration("2w").unwrap(),
            Duration::from_secs(1_209_600)
        );
        assert_eq!(
            parse_duration("1M").unwrap(),
            Duration::from_secs(2_630_016)
        );
        assert_eq!(
            parse_duration("1y").unwrap(),
            Duration::from_secs(31_557_600)
        );
    }

    #[test]
    fn parse_duration_rejects_invalid_inputs() {
        for bad in [
            "",
            "   ",
            "30",
            "abc",
            "-5s",
            "10lightyears",
            "999999999999999999999999999999s",
        ] {
            assert!(parse_duration(bad).is_err(), "'{bad}' should fail");
        }
    }
}
