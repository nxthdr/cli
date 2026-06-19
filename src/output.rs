use std::cell::Cell;

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum OutputFormat {
    #[value(name = "text")]
    Text,
    #[value(name = "json")]
    Json,
    #[value(name = "csv")]
    Csv,
}

thread_local! {
    static FORMAT: Cell<OutputFormat> = const { Cell::new(OutputFormat::Text) };
}

pub fn set_format(fmt: OutputFormat) {
    FORMAT.with(|f| f.set(fmt));
}

/// True only in text mode — use to gate human-facing decoration (notes, hints,
/// truncation) that must not pollute machine-readable JSON/CSV output.
pub fn is_text() -> bool {
    FORMAT.with(|f| f.get()) == OutputFormat::Text
}

fn fmt() -> OutputFormat {
    FORMAT.with(|f| f.get())
}

/// Escape a single CSV field per RFC 4180: quote it when it contains a comma,
/// quote, or newline, doubling any embedded quotes.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_line(cells: &[&str]) -> String {
    cells.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(",")
}

/// Render an empty result set for the active format. In text mode it does
/// nothing and returns `false` so the caller can print a friendly note; in
/// JSON it prints `[]` and in CSV the header row, returning `true`.
pub fn empty(headers: &[&str]) -> bool {
    match fmt() {
        OutputFormat::Text => false,
        OutputFormat::Json => {
            println!("[]");
            true
        }
        OutputFormat::Csv => {
            println!("{}", csv_line(headers));
            true
        }
    }
}

/// Print a section heading with a separator (text mode only).
pub fn section(title: &str) {
    if fmt() == OutputFormat::Text {
        println!("{}", title);
        println!("{}", "─".repeat(title.len()));
    }
}

/// Print a plain informational message (text mode only).
pub fn info(msg: &str) {
    if fmt() == OutputFormat::Text {
        println!("{}", msg);
    }
}

/// Print a success confirmation line (text mode only).
pub fn success(msg: &str) {
    if fmt() == OutputFormat::Text {
        println!("✓ {}", msg);
    }
}

/// Print a warning message (text mode only).
pub fn warn(msg: &str) {
    if fmt() == OutputFormat::Text {
        println!("\n⚠ {}", msg);
    }
}

/// Print a suggested next command (text mode only).
pub fn hint(cmd: &str) {
    if fmt() == OutputFormat::Text {
        println!("\n→ {}", cmd);
    }
}

/// Print aligned key-value pairs.
/// JSON mode: outputs a JSON object.
pub fn kv(pairs: &[(&str, &str)]) {
    if pairs.is_empty() {
        return;
    }
    match fmt() {
        OutputFormat::Text => {
            let width = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            for (k, v) in pairs {
                println!("{:<width$}  {}", k, v, width = width);
            }
        }
        OutputFormat::Json => {
            let obj: serde_json::Map<String, serde_json::Value> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap()
            );
        }
        OutputFormat::Csv => {
            // A key/value block becomes a single-row CSV: keys as the header,
            // values as the one data row.
            let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
            let vals: Vec<&str> = pairs.iter().map(|(_, v)| *v).collect();
            println!("{}", csv_line(&keys));
            println!("{}", csv_line(&vals));
        }
    }
}

/// Print an auto-sized table (headers + separator + rows).
/// Returns the number of lines written so a future watch mode can erase them.
/// JSON mode: outputs a JSON array of objects keyed by header names.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> usize {
    match fmt() {
        OutputFormat::Text => {
            let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
            for row in rows {
                for (i, cell) in row.iter().enumerate() {
                    if let Some(w) = widths.get_mut(i) {
                        *w = (*w).max(cell.len());
                    }
                }
            }
            let fmt_row = |cells: &[&str]| -> String {
                cells
                    .iter()
                    .enumerate()
                    .map(|(i, c)| format!("{:<w$}", c, w = widths.get(i).copied().unwrap_or(0)))
                    .collect::<Vec<_>>()
                    .join("  ")
            };
            let sep_len = widths.iter().sum::<usize>() + 2 * headers.len().saturating_sub(1);
            println!("{}", fmt_row(headers));
            println!("{}", "─".repeat(sep_len));
            for row in rows {
                let cells: Vec<&str> = row.iter().map(|s| s.as_str()).collect();
                println!("{}", fmt_row(&cells));
            }
            2 + rows.len()
        }
        OutputFormat::Json => {
            let arr: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    let obj: serde_json::Map<String, serde_json::Value> = headers
                        .iter()
                        .zip(row.iter())
                        .map(|(h, v)| (h.to_string(), serde_json::Value::String(v.clone())))
                        .collect();
                    serde_json::Value::Object(obj)
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Array(arr)).unwrap()
            );
            0
        }
        OutputFormat::Csv => {
            println!("{}", csv_line(headers));
            for row in rows {
                let cells: Vec<&str> = row.iter().map(|s| s.as_str()).collect();
                println!("{}", csv_line(&cells));
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{csv_field, csv_line};

    #[test]
    fn csv_field_leaves_plain_values_unquoted() {
        assert_eq!(csv_field("vltcdg01"), "vltcdg01");
        assert_eq!(csv_field("2001:db8::/48"), "2001:db8::/48");
    }

    #[test]
    fn csv_field_quotes_and_escapes_special_chars() {
        // Comma forces quoting.
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        // Embedded quotes are doubled and the field is wrapped.
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        // Newlines force quoting.
        assert_eq!(csv_field("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn csv_line_joins_escaped_fields() {
        assert_eq!(csv_line(&["a", "b,c", "d"]), "a,\"b,c\",d");
    }
}
