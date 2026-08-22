# CyberScope

A desktop security posture analyzer built with **Java, JavaFX, Maven, and Nmap**.

CyberScope automates parts of a security assessment workflow: it validates scan targets, safely constructs Nmap commands, executes reconnaissance, parses Nmap XML output into structured data, and will progressively add system hardening checks, CVE mapping, a weighted security posture score, and PDF reporting.

> **Status: v0.1.0 — Under active development**
>
> CyberScope is being developed incrementally. Each version introduces a small, working, tested part of the overall system.

---

## Why This Project Exists

Commercial security assessment platforms such as Nessus, Qualys, and OpenVAS can hide much of their internal complexity behind a polished interface.

CyberScope is an attempt to build a smaller version of that workflow from first principles.

The goal is not simply to create a scanner, but to understand the engineering and security decisions behind each stage:

- How an external security tool is driven programmatically
- How user-controlled input is validated
- How command arguments are constructed safely
- How Java processes and their streams work
- How Nmap output becomes structured application data
- How scan findings can be mapped to known vulnerabilities
- How individual findings can contribute to a security posture score
- How the final results can be presented in an assessment report

The project is intentionally developed in small stages so that every layer can be implemented, tested, and understood before moving to the next one.

---

Development Roadmap
Version	Capability
v0.0.x	Scanner foundation, target validation, Nmap execution, command construction, and result handling
v0.1.0	JavaFX interface over the scanning pipeline
v0.2	Scan presets, CIDR ranges, and cancellation
v0.3	SQLite persistence and scan history
v0.4	System hardening analyzer
v0.5	CVE mapping
v0.6	Weighted security posture score and dashboard
v0.8	PDF assessment reports

The roadmap may evolve as the project develops.

## First Milestone- v0.0.8(CLI-Based Scanning built around Nmap)

# Example Scan Report
# CyberScope scan report

Target      : 127.0.0.1
Scan type   : Quick - Top 100 ports, service and version detection
Started     : 2026-08-20 06:03:04 IST
Duration    : 6.7 s
Command     : nmap -sV -T4 -F -oX /tmp/cyberscope-scan-...xml 127.0.0.1

localhost (127.0.0.1)  [UP] 1 open port

PORT       STATE   SERVICE   VERSION
8080/tcp   open    http      SimpleHTTPServer 0.6 (Python 3.11.15)

Detection: probed (confidence 10)

1 host scanned, 1 up, 1 open port total

## Why the DETECTION column exists

Nmap reports a service one of two ways. With `-sV` it probes the port and
fingerprints the response (`method="probed"`). Without it, it looks the port
number up in `nmap-services` and guesses (`method="table"`).

Those are not the same claim. Scanning a Python `http.server` on port 8080
without `-sV`, Nmap reports `http-proxy` — the wrong service — with confidence
3/10. With `-sV` it reports `SimpleHTTPServer 0.6 (Python 3.11.15)`, confidence
10/10, plus a CPE identifier.

CyberScope shows which one you got, and prints a warning when any result was a
guess. When CVE mapping is added, only probed results will be eligible.

## Current Status — v0.1.0

CyberScope currently has the foundation of its scanning pipeline in place.

The project is still under active development. Higher-level security analysis, persistence, CVE mapping, scoring, and reporting are planned for later versions.

---
The current architecture is evolving around components such as:
JavaFX UI
    │
    ▼
Scan Workflow
    │
    ├── TargetValidator
    │
    ├── NmapCommandBuilder
    │
    └── NmapExecutor
             │
             ▼
           Nmap
             │
             ▼
         XML Output
             │
             ▼
        Result Parser
             │
             ▼
       Host / Port / Service

Testing
CyberScope is being developed with automated tests alongside the implementation.
Testing currently covers areas including:
Target validation
Malformed and malicious input
Command construction
Nmap process execution
Process timeouts
Nmap exit codes
XML output handling
Scan-result models

The goal is to keep each version working and tested before moving to the next layer.

Authorised Use Only
CyberScope performs active network scanning.

Only scan systems that you own or have explicit permission to test.

Scanning systems without authorization may be illegal depending on your jurisdiction.

## Security Decisions
- **Allow-list target validation.** Only IPv4 addresses and RFC 1123 hostnames are
  accepted. Alternate IP notations (`2130706433`, `0177.0.0.1`, `127.1`) are
  rejected, as are targets beginning with `-`, which Nmap would read as options
  such as `-iL` or `-oA`.
- **No shell involved.** `ProcessBuilder` receives an argument array, so there is
  no shell to inject into. The real risk is argument injection, which the
  validator addresses.
- **A closed set of scan profiles.** Nmap options come from an enum, so arbitrary
  flags cannot be requested.
- **XXE-hardened XML parsing.** External entity resolution is disabled and entity
  expansion is capped. Note that `disallow-doctype-decl` is deliberately *not*
  used, because Nmap emits `<!DOCTYPE nmaprun>` and that setting would reject
  Nmap's own output.
- **Secure temporary files.** Scan XML is written to a `Files.createTempFile` path
  (unpredictable name, atomic creation, mode 0600) and deleted on every exit path.
- **Authorisation gate.** Scans require explicit confirmation before any packets
  are sent.

## Requirements

- JDK 21 or later
- Maven 3.9+
- Nmap 7.x available on the `PATH`

## Build and Run

```bash
git clone https://github.com/c00k3r/CyberScope.git
cd CyberScope

# Desktop interface
mvn clean javafx:run

# Command line
mvn clean package
java -cp target/classes com.cyberscope.App <target>
```

| Exit code | Meaning |
|---|---|
| 0 | success |
| 2 | Nmap not installed |
| 3 | invalid target or arguments |
| 4 | scan or parse failed |

---

## Testing

```bash
mvn clean test
```

CyberScope is developed with automated tests alongside the implementation.
Coverage currently includes:

- Target validation, including malformed and malicious input
- Command construction
- Nmap process execution, timeouts, and exit codes
- XML parsing against captured Nmap output
- Scan-result models
- Report formatting
- Command-line argument handling and exit codes

The test fixtures include an XXE payload and an entity-expansion bomb, and the
suite asserts that both are rejected.

The goal is to keep each version working and tested before moving to the next
layer.

---

## Technology Stack

**Current**

| Component | Version |
|---|---|
| Java | 21+ |
| Maven | 3.9+ |
| JavaFX | 21.0.7 |
| JUnit | 5 |
| Nmap | 7.x (external) |

**Planned**

| Component | For |
|---|---|
| SQLite | Scan history and persistence |
| CVE data | Vulnerability mapping |
| Apache PDFBox | Assessment reports |

---

## Development Roadmap

| Version | Capability | Status |
|---|---|---|
| v0.0.x | Scanner foundation: target validation, command construction, Nmap execution, XML parsing, CLI reporting | Done |
| v0.1.0 | JavaFX interface over the scanning pipeline | Done |
| v0.2 | Scan presets, CIDR ranges, and cancellation | Next |
| v0.3 | SQLite persistence and scan history | Planned |
| v0.4 | System hardening analyzer | Planned |
| v0.5 | CVE mapping | Planned |
| v0.6 | Weighted security posture score and dashboard | Planned |
| v0.8 | PDF assessment reports | Planned |

The roadmap may evolve as the project develops.

---

## Project Philosophy

CyberScope is deliberately being built incrementally.

Rather than immediately creating a large application with many unfinished
features, each version introduces a focused piece of functionality and verifies it
with tests before the next layer is added.

The objective is to understand why the system works the way it does, not simply to
make it work.

---

## Authorised Use Only

CyberScope performs active network scanning.

Only scan systems that you own or have explicit permission to test. Scanning
systems without authorisation may be illegal depending on your jurisdiction,
including under Sections 43 and 66 of the Information Technology Act, 2000
(India).

Development and testing targets are documented in [SCOPE.md](SCOPE.md).

---

## Licence

MIT — see [LICENSE](LICENSE).
MDEOF
