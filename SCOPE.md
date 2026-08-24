# Authorised Testing Scope

CyberScope performs active network scanning. Active scanning against systems
you do not own or have explicit written permission to test is unlawful in most
jurisdictions, including under Sections 43 and 66 of the Information Technology
Act, 2000 (India).

This file records the only targets used during the development and testing of
this project.

## Authorised targets

| Target | Basis for authorisation |
|---|---|
| `127.0.0.1` / `localhost` | Loopback interface of the developer's own WSL2 Debian instance. |
| Locally started test listeners (e.g. `python3 -m http.server`) | Processes started by the developer, on the developer's own machine. |
| Docker containers on the developer's own host | Owned and operated by the developer. |
| `scanme.nmap.org` | Provided by the Nmap Project explicitly for scan testing, within the usage limits stated by that project. |
| The developer's own Windows host and home network devices | Owned by the developer. |

## Explicitly out of scope

Institutional, hostel, campus, employer, public and third-party networks are
NOT authorised targets and are never scanned during development of this project.

## Note for reviewers

Screenshots and sample output in this repository are produced against the
targets listed above. No scan results from third-party networks are committed
to this repository.

### Data retention

From v0.3.0 CyberScope stores completed scans in a local SQLite database at
`~/.cyberscope/cyberscope.db` (directory 0700, file 0600). Stored data includes
target addresses, hostnames, port states, detected service versions and CPEs.
Nothing is transmitted anywhere. Delete individual scans with
`cyberscope --delete <id>`, or all of them by removing the database file.
Scanning with `--no-save` records nothing.