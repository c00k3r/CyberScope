CyberScope
A security posture analyzer in Java. CyberScope drives Nmap programmatically, parses its XML into structured data, stores every scan, compares scans over time, and maps detected services to CVEs — while keeping track of the difference between what it verified, what it merely inferred, and what it could not check at all.

<<<<<<< HEAD
Show Image:
width="1100" height="580" alt="v040-diff" src="https://github.com/user-attachments/assets/686889b7-9127-41ed-a1d8-dcafa40b503e" />

=======
Show Image
>>>>>>> v0.5.0-vuln-mapping

Status: v0.5.0 — under active development. Built incrementally; every version is a small, working, tested slice. 414 tests currently pass.

What makes it different
Nmap tells you port 8080 is http. It will tell you that whether it probed the service and read a banner back, or whether it looked 8080 up in a table of common ports and guessed. Those are completely different levels of evidence, and the default output presents them identically.

Nmap does record the difference — method and conf attributes in its XML — and almost every tool that consumes Nmap throws them away.

CyberScope treats that provenance as primary data. Every result carries how it was determined and how confident Nmap was. It survives storage, it appears in reports, it governs comparison, and from v0.5.0 it governs vulnerability lookup: a service Nmap only guessed at is never sent to the CVE index at all.

A guess promoted to a finding is how a security report falls apart under review. This is the layer that stops it.

Quick start
bash
git clone https://github.com/c00k3r/CyberScope.git
cd CyberScope
mvn clean package                     # builds target/cyberscope.jar

java -jar target/cyberscope.jar --update-cve-index   # ~100 MB, about a minute
java -jar target/cyberscope.jar 127.0.0.1            # command line
mvn javafx:run                                       # desktop interface
Requires JDK 21+, Maven 3.9+, and Nmap 7.x on the PATH.

Scan only systems you own or have written authorisation to test. See Authorised use.

Why "not in the index" is a result
This is the finding v0.5.0 was built around, and it is reproducible in one command.

Nmap identifies nginx as cpe:/a:igor_sysoev:nginx — after Igor Sysoev, who wrote it. The National Vulnerability Database files nginx under cpe:2.3:a:f5:nginx, because F5 acquired NGINX Inc. in 2019.

Indexing all 384,513 CVEs in NVD from 1999 to 2026 and counting:

igor_sysoev:nginx   ->   0 CVEs
f5:nginx            ->  41 CVEs
So the obvious pipeline — scan, take Nmap's CPE, look it up, print the results — returns an empty list for a web server with 41 known CVEs. Not an error. Not a warning. An empty list, which looks exactly like good news.

CyberScope reports four outcomes per service, and only the first can ever mean "clean":

Outcome	Meaning
mapped	We resolved a CPE and searched the index. Zero results here is a real answer.
not in the index	Nmap gave a product and version, but nothing is filed under that vendor at all.
no version	Nothing to look up. Every table-detected service lands here.
no index	The CVE index has not been built.
The last three are the ones every scanner examined while building this renders identically, as an absence of findings.

--------------------------------------------------------------------------
 NOT CHECKED -- 1 service
--------------------------------------------------------------------------
  80/tcp   igor_sysoev:nginx 1.24.0                     COULD NOT BE LOOKED UP
    The CVE index has nothing filed under igor_sysoev:nginx. This is not a
    statement about the host -- the lookup failed, so no question was
    answered.
Matching versions the way NVD actually writes them
NVD states "which versions are affected" in three structurally different ways. Measured across the 224,235 applicability entries in CVE-2024:

Shape	Share	Example
Version pinned in the CPE string	73.4%	cpe:2.3:a:f5:nginx:1.24.0
Version is *, bounds in sibling attributes	25.1%	versionStartIncluding: 8.6, versionEndIncluding: 9.8
Version is *, no bounds at all	1.5%	applies to every version ever released
Matching only the first drops a quarter of NVD's applicability data — including CVE-2024-6387, regreSSHion, unauthenticated remote code execution as root. There is no row anywhere in NVD saying openssh:9.6; the vulnerability is expressed as a range.

Honouring all three reproduces the NVD API's own answer exactly. OpenSSH 9.6 returns 19 CVEs from the live API and 19 from the local index, split 1 exact / 15 ranged / 3 all-versions.

Pinned versions are compared, not string-matched, because 9,175 of the 64,450 distinct pinned version strings in NVD (14.2%) are one release spelled several ways. This is a single real group:

1.0.1   1.0.01   1.0_1   1.0_01   1.0(1)   1.00.01   1.0-1   1.0.(1)   1.00.1
Nine spellings, nine different CNAs. String equality makes a CVE filed against 1.0(1) invisible to a host reporting 1.0.1.

Findings are ordered by evidence, then severity
That 1.5% "all versions" bucket is where the noise lives. For OpenSSH 9.6 it contributes a 2007 PAM/OPIE configuration issue, a rowhammer attack needing physical DRAM access, and CVE-2008-3844 — a 2008 compromise of Red Hat's build machines, which is not an OpenSSH bug at all. NVD scores that last one 9.3.

Sorted by severity, it lands above regreSSHion. So CyberScope sorts by match precision first: every range- and exact-matched finding comes before every unbounded one, and the report says which is which.

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

The same server on port 8080, scanned twice, side by side:

xml
<!-- nmap -p 8080 -->
<service name="http-proxy" method="table" conf="3"/>

<!-- nmap -sV -p 8080 -->
<service name="http" product="SimpleHTTPServer" version="0.6"
         extrainfo="Python 3.11.15" method="probed" conf="10">
  <cpe>cpe:/a:python:simplehttpserver:0.6</cpe>
</service>
No product, no version, no CPE — and the name it does give is wrong. That is why a table service is never sent to the CVE index: there is nothing to send, and the guess would be the thing you looked up.

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

The CVE index
CyberScope keeps a local, offline copy of the National Vulnerability Database. No API key, no rate limit, no network call at scan time, and reproducible results in front of an audience.

bash
cyberscope --update-cve-index     # build or refresh
cyberscope --cve-index-status     # what it holds and how old it is
Source	fkie-cad/nvd-json-data-feeds — NIST retired its own JSON feeds on 15 December 2023
Download	100.8 MB compressed, 28 year files, ~2.9 GB uncompressed
Result	384,513 CVEs, 2,093,452 applicability statements, 121,330 products, 327 MB
Build time	about 50 seconds; peak heap 95 MB, flat across all 28 years
Lookup	1.2 ms per product against the full index
Location	~/.cyberscope/cve-index.db, never committed, deletable at any time
The whole corpus is streamed in one pass — xz decompression feeds a pull parser, which feeds JDBC batches — because 2.9 GB cannot be held in memory, and a full rebuild never holds more than one CVE at a time.

Every report states how old the index is. The corpus grew by 584 CVEs in the one day between two builds made while writing v0.5.0, so "no findings" from a three-week-old index is a statement about the index, not about the host. Past seven days the report says so in the header.

A refresh builds into a staging file and replaces the live index atomically at the end. An interrupted refresh would otherwise leave products missing from the index — and a missing product returns an empty list, which reads as "no known vulnerabilities."

Architecture
 ui/                        JavaFX. The only package that imports javafx.*
  │   CyberScopeApp · ScanView · HistoryPane · DiffView · ScanTask · CveIndexTask
  │
  ├──▶ service/scanner/     NmapDetector · NmapCommandBuilder · NmapExecutor
  │                         NmapXmlParser
  ├──▶ service/compare/     ScanComparator · ScanDiff · PortChange
  ├──▶ service/vuln/        CpeMatcher · VulnerabilityService
  ├──▶ service/report/      ScanReportFormatter · ScanDiffFormatter
  │                         VulnReportFormatter
  │
  ├──▶ repository/          The only package that knows SQL exists
  │      DatabaseManager · ScanRepository            ──▶ cyberscope.db
  │      CveIndexManager · CveRepository · CveFeedLoader ──▶ cve-index.db
  │      CveLookup  (the interface service/vuln depends on)
  │
  └──▶ model/  util/        Host · Port · Service · PortSummary · ScanType
                            Cpe · VersionRange · MatchPrecision · Severity
                            Vulnerability · VulnAssessment · MappingOutcome
                            TargetValidator · PortRanges · NetworkContext
                            VersionOrder
One scan, end to end:

target string
   → TargetValidator      allow-list; rejects anything that is not an address
   → NetworkContext       which interface this will leave by (sends nothing)
   → NmapCommandBuilder   argument array from a closed enum of profiles
   → NmapExecutor         ProcessBuilder, no shell, hard timeout
   → Nmap                 writes XML to a mode-0600 temp file
   → NmapXmlParser        XXE-hardened DOM + XPath, including <extraports>
   → Host / Port / Service / PortSummary
   → VulnerabilityService probed services only, four outcomes, never a bare list
   → ScanRepository       one transaction, four tables
   → report, UI, or ScanComparator
ui/ScanTask is the single bridge between JavaFX and the service layer, and it is where the CVE lookup runs — a twelve-service host takes about 216 ms, and a /24 would be seconds, which on the FX thread is a frozen window.

service/vuln/ depends on the CveLookup interface rather than on CveRepository. That keeps the matcher testable without a 327 MB database, and leaves room for a live-NVD fallback as a second implementation rather than an edit to the matcher.

Security decisions
Allow-list target validation. Only IPv4 addresses, RFC 1123 hostnames, and CIDR ranges to /24. Alternate notations (2130706433, 0177.0.0.1, 127.1) are rejected, as are targets beginning with -, which Nmap would read as options like -iL or -oA.
No shell involved. ProcessBuilder receives an argument array, so there is no shell to inject into. The real risk is argument injection, which the validator addresses.
A closed set of scan profiles. Nmap options come from an enum; arbitrary flags cannot be requested.
XXE-hardened XML parsing. External entity resolution disabled, entity expansion capped. disallow-doctype-decl is deliberately not used, because Nmap emits <!DOCTYPE nmaprun> and that setting would reject Nmap's own output.
Bounded JSON parsing. The CVE feed is untrusted input from the network, so the parser caps string length and nesting depth explicitly rather than relying on library defaults.
No API keys anywhere. The offline index removes the need for an NVD API key entirely, and with it a whole category of accidental-commit risk.
Range parsing written for untrusted input. Length checked before parseInt, expansion size checked before the loop, hard 65,536-port ceiling.
Nothing on the wire before authorisation. Network context is learned by connecting a UDP DatagramChannel, which transmits no packets: it only makes the kernel run its routing table.
Secure temporary files. Scan XML goes to a Files.createTempFile path — unpredictable name, atomic creation, mode 0600 — deleted on every exit path.
No orphaned processes. Cancelling interrupts the worker, which unblocks Process.waitFor; the kill lives in a finally so the interrupt cannot skip it.
Parameterised SQL. Every statement is a PreparedStatement with bound parameters.
Foreign keys actually enforced. SQLite has foreign key checking off by default and the setting is per connection. PRAGMA foreign_keys = ON is applied on every connection, with a test asserting it.
Migrations are transactional and forward-only. The version is stamped inside the transaction, so a failure leaves the database where it started rather than half-upgraded.
An undecidable version comparison excludes rather than includes. A scanner that guesses toward a finding manufactures false positives, and a scanner nobody trusts gets switched off.
Authorisation gate. Scans require explicit confirmation before any packets are sent: a checkbox in the GUI, a typed yes on the CLI.
Data and privacy
Two databases, deliberately separate, because they have opposite properties.

cyberscope.db	cve-index.db
Contents	your scans: addresses, hostnames, port states, service versions, CPEs, and the interface each scan used	public NVD data
Size	kilobytes	~327 MB
Permissions	file 0600, directory 0700	inside the same 0700 directory
If lost	irreplaceable	rebuilt in about a minute
On corruption	reported, never silently deleted	discarded and rebuilt
Transmitted	nothing	nothing about your network is ever sent
The CVE index is downloaded from a public feed. Nothing about your scans, your network, or your targets is transmitted at any point. The lookup happens entirely on your machine.

Scan history is a reconnaissance profile of somebody's network, so it is treated as sensitive by default. Remove one scan with cyberscope --delete <id>; remove everything by deleting the database file. Scan with --no-save to record nothing. Delete the CVE index whenever you like — --update-cve-index rebuilds it.

Command line
Usage: cyberscope [options] <target>
       cyberscope --history [--limit n]
       cyberscope --show <id>
       cyberscope --delete <id>
       cyberscope --diff <id> <id>
       cyberscope --compare <target>
       cyberscope --update-cve-index
       cyberscope --cve-index-status

Scan options:
  -s, --scan-type   quick (default) or standard
  -y, --yes         skip the interactive authorisation prompt
      --no-save     do not record this scan in the history

Vulnerability mapping:
      --vulns       list every CVE rather than the top few per port
      --update-cve-index   download and rebuild the local CVE index
      --cve-index-status   show what the index holds and how old it is
      --cve-index <path>   use a different index file

Comparison:
      --diff        compare two stored scans by id
      --compare     compare the two most recent scans of a target

History options:
  -n, --limit       how many rows --history shows (default 20)
      --db <path>   use a different database file
Example report
 VULNERABILITIES
--------------------------------------------------------------------------
 Index: 384,513 CVEs covering 1999-2026, today (feed 29 Aug 2026, 00:00)

 8 open ports examined
     5 looked up          4 with findings, 1 with none
     2 could not be looked up
     1 had no version to look up

 ! 3 services could not be checked. Their absence from the list below is
   a gap in the lookup, not a clean bill of health.

--------------------------------------------------------------------------
 NOT CHECKED -- 3 services
--------------------------------------------------------------------------
  80/tcp   igor_sysoev:nginx 1.24.0                     COULD NOT BE LOOKED UP
    The CVE index has nothing filed under igor_sysoev:nginx. This is not a
    statement about the host -- the lookup failed, so no question was
    answered.
  8080/tcp   http-proxy                                 NO VERSION DETECTED
    The service was guessed from the port number (http-proxy), not probed.
    A table lookup carries no version and no CPE, so no vulnerability
    question can be asked. Re-run with service detection to change this.

--------------------------------------------------------------------------
 FINDINGS -- 4 services
--------------------------------------------------------------------------
  22/tcp   openbsd:openssh 9.6                          CRITICAL  19 found
    CVE-2026-60002   CRITICAL  9.4   in range < 10.4
        ssh in OpenSSH before 10.4 can have a use-after-free when a ser...
    CVE-2024-6387    HIGH      8.1   in range >= 8.6, <= 9.8
        A security regression (CVE-2006-5051) was discovered in OpenSSH...
    ... 16 more, of which 3 NVD files against every version
  443/tcp   f5:nginx 1.24.0                             HIGH  2 found
    CVE-2023-44487   HIGH      7.5   in range >= 1.9.5, <= 1.25.2
        The HTTP/2 protocol allows a denial of service (server resource...

--------------------------------------------------------------------------
 LOOKED UP, NOTHING FILED -- 1 service
--------------------------------------------------------------------------
   21/tcp  vsftpd_project:vsftpd 3.0.5

 110 finding(s) in total; 3 of them rest on an 'all versions' claim.
 Run with --vulns for the complete list.
Testing
bash
mvn clean test
414 tests. Coverage includes:

Target validation, including malformed and deliberately malicious input
Command construction and argument-injection cases
Nmap process execution, timeouts, exit codes, and cancellation
XML parsing against captured real Nmap output, including collapsed <extraports> blocks
Persistence: round trips, transaction rollback, cascade deletes, the foreign-key pragma
Schema migration against a database built to be exactly what the previous version left behind, with rows in it — a migration verified only against an empty database is verified against the one case that cannot go wrong
CPE parsing in both bindings, including the 229 NVD products whose names contain an escaped colon
Version ordering, including the cases where no correct answer exists (1.0rc1 is before 1.0; 9.6p1 is after 9.6; same shape, opposite meaning)
CVE index build from a generated feed served over loopback, and the guarantee that a failed refresh leaves the previous index byte-for-byte unchanged
Every comparison rule, and every mapping outcome, including tests that assert nothing is reported
Fixtures include an XXE payload and an entity-expansion bomb, and the suite asserts both are rejected. Several tests exist specifically to pin down bugs that were found and fixed; each carries a comment saying what it defends against.

Rules are mutation-tested. When a suite passes on its first run, each load-bearing rule is deleted in turn to confirm the tests notice. In v0.5.0 that found two untested guards and, in one case, proved the implementation itself was wrong — pinned versions had been string-matched, which silently hides CVEs filed under a differently-punctuated spelling of the same release.

Technology
Component	Version
Java	21+
Maven	3.9+
JavaFX	21.0.7
SQLite (sqlite-jdbc)	3.53.2.1
XZ (org.tukaani)	1.10
Jackson Core	2.18.2
JUnit	5.14.4
Nmap	7.x (external)
XML parsing uses the JDK's own DOM and XPath, hardened explicitly. JSON uses jackson-core streaming only — no databind, no annotations, no reflection — because a 2.9 GB corpus can be neither bound to objects nor read as a tree. XZ is not optional: the NVD feed publishes .xz and nothing else, and the JDK has no XZ decoder.

Roadmap
Version	Capability	Status
v0.0.x	Scanner foundation: validation, command construction, execution, XML parsing, CLI reporting	Done
v0.1.0	JavaFX interface over the scanning pipeline	Done
v0.2.0	Scan profiles, CIDR ranges, cancellation	Done
v0.3.0	SQLite persistence and scan history	Done
v0.3.1	Visual pass: stylesheet, semantic colour for evidence quality	Done
v0.4.0	Complete port coverage, schema migrations, network context, scan comparison	Done
v0.5.0	Offline CVE index, CPE matching, four mapping outcomes	Done
v0.6	Weighted posture score and dashboard, using comparison for trend	Next
v0.7+	Vendor alias resolution, live NVD fallback, PDF assessment reports	Planned
The roadmap changes as the project does.

Not built yet
Stated plainly, because a security tool that overstates itself is worse than one that underdelivers:

No vendor alias resolution. igor_sysoev:nginx is reported as unresolved rather than silently rewritten to f5:nginx. An alias table is a claim that two identifiers denote the same thing, and a wrong entry produces confident false findings — the worst failure mode a security tool has. When it arrives it will be a visible, sourced layer with its own precision label, not a silent rewrite.
No exploitability assessment. A CVE matching a version does not mean the host is exploitable: configuration, compilation flags and mitigations all matter and none of them are visible from a banner.
No OS-level CVE mapping. Service CPEs only; Nmap's -O output is not consumed yet.
Unprivileged scans only. SYN scanning needs root; CyberScope uses TCP connect scans.
TCP only. No UDP scanning, so 53/udp and 53/tcp are not distinguished anywhere.
One target per scan. No queueing, scheduling, or concurrency across targets.
Tested on Linux and WSL2 only.
Single user, no authentication. A local desktop tool, not a service.
Why this project exists
Building a scanner is not the interesting part — Nmap already exists and CyberScope uses it. The interesting part is everything that happens to a finding after it is found: how confident was it, is it still true next week, does a public advisory apply to it, and can any of it be defended in a report.

Each version implements one layer and tests it before the next is added, so that every engineering and security decision along the way is one I can actually explain:

Driving an external tool safely from Java, without a shell
Validating input that becomes a command line
Handling processes, streams, timeouts and cancellation without leaking either
Turning tool output into structured data, without trusting the parser — and without assuming the tool reports everything it did
Persisting security data with integrity, migrations, and sensible file permissions
Streaming a 2.9 GB dataset through a 95 MB heap and indexing it for millisecond lookups
Joining two datasets on an identifier neither of them agrees on, and reporting the failures instead of dropping them
Keeping the provenance of a finding attached to the finding, across time as well as space
Authorised use only
CyberScope performs active network scanning, which sends real packets to real hosts.

Scan only systems you own or have explicit written permission to test. Unauthorised scanning may be unlawful depending on jurisdiction, including under Sections 43 and 66 of the Information Technology Act, 2000 (India), and the Computer Fraud and Abuse Act (US).

A VPN changes the source address a target logs. It does not change what is lawful.

Development and testing targets are documented in SCOPE.md.

Licence
MIT — see LICENSE.

