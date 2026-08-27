CyberScope
A security posture analyzer in Java. CyberScope drives Nmap programmatically, parses its XML into structured data, stores every scan, and compares scans over time — while keeping track of the difference between what it verified and what it merely inferred.

Show Image:
width="1100" height="580" alt="v040-diff" src="https://github.com/user-attachments/assets/686889b7-9127-41ed-a1d8-dcafa40b503e" />


Status: v0.4.0 — under active development. Built incrementally; every version is a small, working, tested slice. 306 tests currently pass.

What makes it different
Nmap tells you port 8080 is http. It will tell you that whether it probed the service and read a banner back, or whether it looked 8080 up in a table of common ports and guessed. Those are completely different levels of evidence, and the default output presents them identically.

Nmap does record the difference — method and conf attributes in its XML — and almost every tool that consumes Nmap throws them away.

CyberScope treats that provenance as primary data. Every result carries how it was determined and how confident Nmap was. It survives storage, it appears in reports, and from v0.4.0 it governs comparison: a service that goes from probed to inferred is reported as a change in what we know, never as a change in the host.

A guess promoted to a finding is how a security report falls apart under review. This is the layer that stops it.

Quick start
bash
git clone https://github.com/c00k3r/CyberScope.git
cd CyberScope
mvn clean package                     # builds target/cyberscope.jar

java -jar target/cyberscope.jar 127.0.0.1        # command line
mvn javafx:run                                   # desktop interface
Requires JDK 21+, Maven 3.9+, and Nmap 7.x on the PATH.

Scan only systems you own or have written authorisation to test. See Authorised use.

What it does today
Scanning

IPv4 addresses, RFC 1123 hostnames, and CIDR ranges up to /24
Two profiles (Quick, Standard), with the timeout budget scaled to the range size
Cancellation that terminates the Nmap process, not just the UI
Evidence tracking

Every service records probed or table, plus Nmap's confidence value
CPEs captured per service, ready for CVE mapping in v0.5
Reports and the UI warn whenever any result was inferred rather than probed
Complete coverage

Reads the <extraports> block Nmap uses to collapse ports it did not list individually
So a scan reports "100 ports scanned: 1 open, 99 closed", not "1 open port"
Knows the difference between a port that was closed and a port that was never scanned
History and comparison

Every scan persisted to SQLite at ~/.cyberscope/cyberscope.db, with schema migrations
Compare any two scans: ports opened and closed, versions moved, detection quality changed
Records which network interface each scan left by, so two scans of 10.0.0.5 taken from different networks are flagged rather than silently treated as one host
Two front ends, one engine

The GUI and CLI share the entire service layer. Nothing below ui/ imports JavaFX.
Why the DETECTION column exists
The obvious assumption is that -sV settles it: pass the flag and you get real service detection. It doesn't. -sV is a request, not a guarantee.

One nmap -sV run against three local ports:

port 5432   name=postgresql   method=table    conf=3
port 8080   name=http         method=probed   conf=10
port 9100   name=jetdirect    method=table    conf=3
8080 was a Python http.server. Nmap probed it and matched — SimpleHTTPServer 0.6 (Python 3.11.15), confidence 10, with a CPE.
5432 was a socket emitting random bytes. Nmap probed, couldn't match, and fell back to the port table. It reports postgresql.
9100 was also a Python http.server. Nmap's own nmap-service-probes contains Exclude T:9100-9107 — printer ports it refuses to probe, because sending probe data to a JetDirect port prints pages. So -sV never touched it, and it reports jetdirect.
Two of those three names are wrong, with version detection enabled for all of them.

Nmap marks the unconfirmed ones with a ? in terminal output. That ? is a character in a text stream, not a field. The moment you consume the XML programmatically — the entire point of a tool like this — you need method and conf as structured data, and everything downstream must refuse to treat conf=3 as evidence.

Comparing two scans
==============================================================================
 CyberScope scan comparison
==============================================================================
 Target    : 192.168.1.24
 Earlier   : 2026-08-20 09:14:00 IST   (Quick)
 Later     : 2026-08-27 18:03:00 IST   (Quick)
 Interval  : 7.4 days
==============================================================================

 CHANGES ON THE HOST
 -------------------
   + 3306/tcp opened  MySQL 8.0.36
   + 22/tcp version changed: OpenSSH 9.6p1 -> OpenSSH 9.8p1

 CHANGES IN WHAT WE KNOW
 -----------------------
   ~ 443/tcp no longer probed, only inferred  (confidence 10 -> 3)

   These are differences in detection quality, not in the host.
   The services may be unchanged; what changed is whether
   CyberScope was able to confirm them.

 NOT COMPARED
 ------------
   1 port was examined by only one of the two scans.
   Nothing can be said about it.
Three sections, because they are three different claims. The comparator applies four rules, each of which exists to stop it saying something it cannot know:

1. Coverage gate	A port is compared only if both scans observed it. A port one scan never looked at produces no change of any kind.
2. State	Once the gate passes, a differing state is a real change — whether it came from an individually listed port or from a collapsed summary. The TCP handshake happened either way.
3. Service	Compared only when both sides were actually probed. One probed and one inferred is a change in method, not in the host. Two table guesses agreeing prove nothing.
4. Path	If the two scans left by different network routes, the same address may not be the same machine, and the whole comparison is marked untrustworthy.
Rule 1 matters more than it looks. Comparing a Quick scan (100 ports) with a Standard scan (1000 ports) of an unchanged host reports zero changes and 900 uncompared ports. A naive diff would announce 900 newly-discovered ports.

Architecture
 ui/                        JavaFX. The only package that imports javafx.*
  │   CyberScopeApp · ScanView · HistoryPane · DiffView · ScanTask
  │
  ├──▶ service/scanner/     NmapDetector · NmapCommandBuilder · NmapExecutor
  │                         NmapXmlParser
  ├──▶ service/compare/     ScanComparator · ScanDiff · PortChange
  ├──▶ service/report/      ScanReportFormatter · ScanDiffFormatter
  │
  ├──▶ repository/          The only package that knows SQL exists
  │      DatabaseManager · ScanRepository            ──▶ SQLite
  │
  └──▶ model/  util/        Host · Port · Service · PortSummary · ScanType
                            TargetValidator · PortRanges · NetworkContext
One scan, end to end:

target string
   → TargetValidator      allow-list; rejects anything that is not an address
   → NetworkContext       which interface this will leave by (sends nothing)
   → NmapCommandBuilder   argument array from a closed enum of profiles
   → NmapExecutor         ProcessBuilder, no shell, hard timeout
   → Nmap                 writes XML to a mode-0600 temp file
   → NmapXmlParser        XXE-hardened DOM + XPath, including <extraports>
   → Host / Port / Service / PortSummary
   → ScanRepository       one transaction, four tables
   → report, UI, or ScanComparator
ui/ScanTask is the single bridge between JavaFX and the service layer. That constraint is why the CLI and GUI share every line of scanning, parsing, storage and comparison code.

Security decisions
Allow-list target validation. Only IPv4 addresses, RFC 1123 hostnames, and CIDR ranges to /24. Alternate notations (2130706433, 0177.0.0.1, 127.1) are rejected, as are targets beginning with -, which Nmap would read as options like -iL or -oA.
No shell involved. ProcessBuilder receives an argument array, so there is no shell to inject into. The real risk is argument injection, which the validator addresses.
A closed set of scan profiles. Nmap options come from an enum; arbitrary flags cannot be requested.
XXE-hardened XML parsing. External entity resolution disabled, entity expansion capped. disallow-doctype-decl is deliberately not used, because Nmap emits <!DOCTYPE nmaprun> and that setting would reject Nmap's own output.
Range parsing written for untrusted input. Length checked before parseInt, expansion size checked before the loop, hard 65,536-port ceiling — even though today's only caller is Nmap itself.
Nothing on the wire before authorisation. Network context is learned by connecting a UDP DatagramChannel, which transmits no packets: it only makes the kernel run its routing table. A scanner must not emit traffic to a target the user has not yet confirmed.
Secure temporary files. Scan XML goes to a Files.createTempFile path — unpredictable name, atomic creation, mode 0600 — deleted on every exit path.
No orphaned processes. Cancelling interrupts the worker, which unblocks Process.waitFor; the kill lives in a finally so the interrupt cannot skip it. Regression-tested by counting nmap processes after a cancel.
Parameterised SQL. Every statement is a PreparedStatement with bound parameters.
Foreign keys actually enforced. SQLite has foreign key checking off by default and the setting is per connection. PRAGMA foreign_keys = ON is applied on every connection, with a test asserting it — without it, deleting a scan silently orphans its hosts, ports and summaries.
Migrations are transactional and forward-only. The version is stamped inside the transaction, so a failure leaves the database where it started rather than half-upgraded. A database written by a newer version is refused, not opened.
Authorisation gate. Scans require explicit confirmation before any packets are sent: a checkbox in the GUI, a typed yes on the CLI.
Data and privacy
Location	~/.cyberscope/cyberscope.db
Permissions	file 0600, directory 0700
Contents	target addresses, hostnames, port states, service versions, CPEs, and the local interface each scan used
Transmitted	nothing — there is no network component beyond the scan itself
Scan history is a reconnaissance profile of somebody's network, so it is treated as sensitive by default. Remove one scan with cyberscope --delete <id> or the Delete button; remove everything by deleting the database file. Scan with --no-save to record nothing.

Command line
Usage: cyberscope [options] <target>
       cyberscope --history [--limit n]
       cyberscope --show <id>
       cyberscope --delete <id>
       cyberscope --diff <id> <id>
       cyberscope --compare <target>

Scan options:
  -s, --scan-type   quick (default) or standard
  -y, --yes         skip the interactive authorisation prompt
      --no-save     do not record this scan in the history

Comparison:
      --diff        compare two stored scans by id
      --compare     compare the two most recent scans of a target

History options:
  -n, --limit       how many rows --history shows (default 20)
      --db <path>   use a different database file
Exit code	Meaning
0	success
2	Nmap not installed
3	invalid target, argument, or unknown scan id
4	scan or parse failed
5	database error
A storage failure after a successful scan is reported on stderr but does not change the exit code — a script checking $? should not be told the scan failed when it didn't.

Example report
==============================================================================
 CyberScope scan report
==============================================================================
 Target      : 127.0.0.1
 Scan type   : Quick - Top 100 ports, service and version detection
 Started     : 2026-08-27 17:03:00 IST
 Duration    : 6.3 s
 Command     : nmap -sV -T4 -F -oX /tmp/cyberscope-scan-...xml 127.0.0.1
 Route       : 127.0.0.1 via lo
==============================================================================

 localhost (127.0.0.1)  [UP]
 100 ports scanned: 2 open, 98 closed

   PORT      STATE  SERVICE  VERSION                                DETECTION
   --------  -----  -------  -------------------------------------  ----------------
   3306/tcp  open   http     SimpleHTTPServer 0.6 (Python 3.11.15)  probed (conf 10)
   8080/tcp  open   http     SimpleHTTPServer 0.6 (Python 3.11.15)  probed (conf 10)

==============================================================================
 1 host scanned, 1 up, 2 open ports total
==============================================================================
Testing
bash
mvn clean test
306 tests. Coverage includes:

Target validation, including malformed and deliberately malicious input
Command construction and argument-injection cases
Nmap process execution, timeouts, exit codes, and cancellation
XML parsing against captured real Nmap output, including collapsed <extraports> blocks
Persistence: round trips, transaction rollback, cascade deletes, the foreign-key pragma
Schema migration against a database built to be exactly what the previous version left behind, with rows in it — a migration verified only against an empty database is verified against the one case that cannot go wrong
Every comparison rule, including tests that assert nothing is reported
Fixtures include an XXE payload and an entity-expansion bomb, and the suite asserts both are rejected. Several tests exist specifically to pin down bugs that were found and fixed; each carries a comment saying what it defends against.

The comparison tests passed on their first run, so each rule was then deleted in turn to confirm the suite noticed — the coverage gate, the state rule, the evidence classification and the path warning each break tests when removed.

Technology
Component	Version
Java	21+
Maven	3.9+
JavaFX	21.0.7
SQLite (sqlite-jdbc)	3.53.2.1
JUnit	5.14.4
Nmap	7.x (external)
No XML or JSON library: parsing uses the JDK's own DOM and XPath, hardened explicitly. Reporting will use Apache PDFBox when it arrives.

Roadmap
Version	Capability	Status
v0.0.x	Scanner foundation: validation, command construction, execution, XML parsing, CLI reporting	Done
v0.1.0	JavaFX interface over the scanning pipeline	Done
v0.2.0	Scan profiles, CIDR ranges, cancellation	Done
v0.3.0	SQLite persistence and scan history	Done
v0.3.1	Visual pass: stylesheet, semantic colour for evidence quality	Done
v0.4.0	Complete port coverage, schema migrations, network context, scan comparison	Done
v0.5	CVE mapping from captured CPEs — probed results only	Next
v0.6	Weighted posture score and dashboard, using comparison for trend	Planned
v0.7+	Live NVD lookups, PDF assessment reports, native packaging	Planned
The roadmap changes as the project does.

Not built yet
Stated plainly, because a security tool that overstates itself is worse than one that underdelivers:

No vulnerability detection. CyberScope identifies services; it does not yet know whether any of them are vulnerable.
Unprivileged scans only. SYN scanning needs root; CyberScope uses TCP connect scans.
TCP only. No UDP scanning, so 53/udp and 53/tcp are not distinguished anywhere.
One target per scan. No queueing, scheduling, or concurrency across targets.
Tested on Linux and WSL2 only.
Single user, no authentication. A local desktop tool, not a service.
Why this project exists
Building a scanner is not the interesting part — Nmap already exists and CyberScope uses it. The interesting part is everything that happens to a finding after it is found: how confident was it, is it still true next week, and can it be defended in a report.

Each version implements one layer and tests it before the next is added, so that every engineering and security decision along the way is one I can actually explain:

Driving an external tool safely from Java, without a shell
Validating input that becomes a command line
Handling processes, streams, timeouts and cancellation without leaking either
Turning tool output into structured data, without trusting the parser — and without assuming the tool reports everything it did
Persisting security data with integrity, migrations, and sensible file permissions
Keeping the provenance of a finding attached to the finding, across time as well as space
Authorised use only
CyberScope performs active network scanning, which sends real packets to real hosts.

Scan only systems you own or have explicit written permission to test. Unauthorised scanning may be unlawful depending on jurisdiction, including under Sections 43 and 66 of the Information Technology Act, 2000 (India), and the Computer Fraud and Abuse Act (US).

A VPN changes the source address a target logs. It does not change what is lawful.

Development and testing targets are documented in SCOPE.md.

Licence
MIT — see LICENSE.



