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

Technology Stack
Core
Java 21+
Maven 3.9+
JavaFX
Nmap 7.x
Planned
SQLite
CVE data sources
PDF report generation

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

Development and testing targets are documented in:

SCOPE.md

Project Philosophy

CyberScope is deliberately being built incrementally.

Rather than immediately creating a large application with many unfinished features, each version introduces a focused piece of functionality and verifies it with tests before the next layer is added.

The objective is to understand why the system works the way it does, not simply to make it work.

Licence

MIT — see LICENSE.
