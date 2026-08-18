# CyberScope

A desktop security posture analyzer built in Java and JavaFX.

CyberScope automates parts of a security assessment: it performs network
reconnaissance using Nmap, parses the results into structured data, and will
progressively add system hardening checks, CVE mapping, a weighted posture
score, and PDF reporting.

> **Status: v0.0.1 — under active development.**
> This is a learning-driven build. Each version is a working, tested increment.

## Why this project exists

Commercial posture-assessment tools (Nessus, Qualys, OpenVAS) are effectively
black boxes to their users. CyberScope is an attempt to build the same class of
tool from first principles in order to understand the engineering underneath:
how a scanner is driven programmatically, how its output becomes structured
data, how findings map to known vulnerabilities, and how those findings are
aggregated into a defensible score.

## Current capability (v0.0.1)

- Maven project builds and runs
- Prints version banner

## Planned

| Version | Capability |
|---|---|
| v0.0.8 | CLI: validated target -> Nmap execution -> XML parsing -> port table |
| v0.1.0 | JavaFX interface over the same scan pipeline |
| v0.2   | Scan presets, CIDR ranges, cancellation |
| v0.3   | SQLite persistence and scan history |
| v0.4   | System hardening analyzer |
| v0.5   | CVE mapping |
| v0.6   | Weighted security posture score and dashboard |
| v0.8   | PDF assessment reports |

## Build and run

Requires JDK 21 or later, Maven 3.9+, and Nmap 7.x on the PATH.

mvn clean package java -cp target/classes com.cyberscope.App

## Authorised use only

CyberScope performs active network scanning. Scanning systems you do not own or
have explicit written permission to test is unlawful in most jurisdictions,
including under the Information Technology Act, 2000 (India).

See [SCOPE.md](SCOPE.md) for the targets used during development of this project.

## Licence

MIT — see [LICENSE](LICENSE).
