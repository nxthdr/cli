use std::cell::Cell;

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum OutputFormat {
    #[value(name = "text")]
    Text,
    #[value(name = "json")]
    Json,
}

thread_local! {
    static FORMAT: Cell<OutputFormat> = const { Cell::new(OutputFormat::Text) };
}

pub fn set_format(fmt: OutputFormat) {
    FORMAT.with(|f| f.set(fmt));
}

pub fn is_json() -> bool {
    FORMAT.with(|f| f.get()) == OutputFormat::Json
}

fn fmt() -> OutputFormat {
    FORMAT.with(|f| f.get())
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
    }
}
