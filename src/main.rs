use anyhow::Result;
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path, path::PathBuf};
use tracing::info;

/// A program to split a gitleaks report into unique and duplicate findings.
#[derive(Parser, Debug)]
struct Args {
    /// Print unique findings rather than duplicates.
    #[arg(short = 'u', long)]
    unique: bool,
    /// Output format for the findings.
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    /// The path the the gitleaks JSON report.
    report_path: PathBuf,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum OutputFormat {
    Json,
    Text,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Finding {
    description: String,
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    #[serde(rename = "Match")]
    match_: String,
    secret: String,
    file: String,
    symlink_file: String,
    commit: String,
    entropy: f32,
    author: String,
    email: String,
    date: String,
    message: String,
    tags: Vec<String>,
    #[serde(rename = "RuleID")]
    rule_id: String,
    fingerprint: String,
}

impl Finding {
    fn is_duplicate_of(&self, other: &Finding) -> bool {
        self.secret == other.secret && self.rule_id == other.rule_id
    }
}

struct PartitionResult<T> {
    unique: Vec<T>,
    duplicated: Vec<T>,
}

fn partition_findings(findings: Vec<Finding>) -> PartitionResult<Finding> {
    let mut unique = Vec::new();
    let mut duplicated = Vec::new();

    for finding in findings {
        if unique.iter().any(|other| finding.is_duplicate_of(other)) {
            duplicated.push(finding);
        } else {
            unique.push(finding);
        }
    }

    PartitionResult { unique, duplicated }
}

fn read_report<P: AsRef<Path>>(path: P) -> Result<Vec<Finding>> {
    info!("reading gitleaks report from {}", path.as_ref().display());

    let file = File::open(path)?;
    let findings = serde_json::from_reader(file)?;
    Ok(findings)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let report = read_report(&args.report_path)?;

    info!("gitleaks report contains {} findings", report.len());

    let PartitionResult { unique, duplicated } = partition_findings(report);

    info!(
        "{} unique findings, {} duplicates",
        unique.len(),
        duplicated.len()
    );

    let mut findings = if args.unique { unique } else { duplicated };

    match args.output {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(std::io::stdout(), &findings)?;
        }
        OutputFormat::Text => {
            findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));

            for finding in findings {
                println!("{}", finding.fingerprint);
            }
        }
    }

    Ok(())
}
