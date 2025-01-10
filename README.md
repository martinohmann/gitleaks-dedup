# gitleaks-dedup

A very simple tool to deduplicate findings from a [gitleaks][gitleaks] report.

## Use cases

When dealing with a large gitleaks report for a legacy codebase it can be quite
hard to see how many actual secrets were leaked due to duplicates. This tool
helps to surface unique and duplicate findings.

## Installation

As of now, there are no published releases, please install from git directly:

```sh
cargo install --git https://github.com/martinohmann/gitleaks-dedup.git
```

## Usage

Generate a gitleaks report (make sure to not use `--redact`):

```sh
gitleaks detect --no-color --verbose --source . --report-path gitleaks-report.json
```

Show the fingerprints of duplicate findings of the same secret:

```sh
gitleaks-dedup gitleaks-report.json
```

Show the fingerprints of the unique findings:

```sh
gitleaks-dedup gitleaks-report.json --unique
```

## License

If not stated otherwise, the source code inside this repository is licensed
under either of [Apache License, Version 2.0][apache-license] or [MIT
license][mit-license] at your option.

[gitleaks]: https://github.com/gitleaks/gitleaks
[apache-license]: https://github.com/martinohmann/gitleaks-dedup/blob/main/LICENSE-APACHE
[mit-license]: https://github.com/martinohmann/gitleaks-dedup/blob/main/LICENSE-MIT
