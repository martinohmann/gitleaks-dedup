use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use std::{fs::File, path::Path, path::PathBuf};
use tracing::info;

/// A program to split a gitleaks report into unique and duplicate findings.
#[derive(Parser, Debug)]
struct Args {
    /// Print unique findings rather than duplicates.
    #[arg(short = 'u', long)]
    unique: bool,
    /// The path the the gitleaks JSON report.
    report_path: PathBuf,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Finding {
    secret: String,
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

    findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));

    for finding in findings {
        println!("{}", finding.fingerprint);
    }

    Ok(())
}
