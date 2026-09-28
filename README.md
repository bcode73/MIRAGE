# MIRAGE

MIRAGE is an adversary emulation harness for testing whether a blue team can catch anti-forensic activity. It performs the kind of timeline and artifact tampering that real intruders lean on to slow down an investigation. It changes file timestamps, plants registry artifacts, and disables event log channels. The difference between MIRAGE and the malware it imitates is everything that happens around those actions. Every operation runs under a signed engagement, every change is written to a tamper evident journal, and every change can be rolled back exactly the way it was.

The goal is not to hide from the SOC. It is the opposite. MIRAGE gives the SOC something concrete to detect, then hands the operator a report that spells out what was done, when, on which host, and which detections should have fired. If one of those techniques slipped past the sensors, that silence is the finding you take back to the customer.

If you came here looking for a tool that fabricates evidence against a person or quietly erases its own tracks, this is not that tool, and the design actively works against using it that way. See "What MIRAGE will not do" below.

## Table of contents

- [The idea in one paragraph](#the-idea-in-one-paragraph)
- [What MIRAGE will not do](#what-mirage-will-not-do)
- [How the backbone works](#how-the-backbone-works)
- [Requirements and installation](#requirements-and-installation)
- [The engagement profile](#the-engagement-profile)
- [Command reference](#command-reference)
- [A full walkthrough](#a-full-walkthrough)
- [The audit journal](#the-audit-journal)
- [The purple team report](#the-purple-team-report)
- [Reverting an engagement](#reverting-an-engagement)
- [Techniques and ATT&CK mapping](#techniques-and-attck-mapping)
- [Platform notes](#platform-notes)
- [Project layout](#project-layout)
- [Development and tests](#development-and-tests)
- [Safety, authorization, and the law](#safety-authorization-and-the-law)

## The idea in one paragraph

Real attackers timestomp files, tamper with the registry, and turn logging off so that responders waste time. Defenders are supposed to notice all three. MIRAGE lets a red or purple team reproduce those behaviors on a lab host during a sanctioned engagement, records each action so the team can prove exactly what it did, and reverses everything at the end so the host is left clean. The report it produces is written for the defenders: each emulated action is mapped to a MITRE ATT&CK technique and paired with the telemetry that should have caught it.

## What MIRAGE will not do

These are deliberate limits baked into the code, not just guidance:

- It does not fabricate artifacts designed to implicate a specific person or application. The registry module tags every key it touches with a clear marker (see below) so nothing it plants can be passed off later as genuine user activity.
- It does not forge Security channel events such as counterfeit 4624 logon records. Minting convincing fake telemetry serves evidence planting, not detection testing.
- It does not clear or delete real event logs. A log clear is destructive and cannot be reversed, which breaks the one promise the tool is built around.

Anti-forensic emulation is legitimate. Manufacturing false evidence or destroying real evidence is not, and no engagement paperwork makes it so. MIRAGE is scoped to the first thing and away from the second.

## How the backbone works

Three ideas hold the whole tool together. Every module is built on top of them, and nothing touches a target except through this path.

**1. Authorization.** Before anything happens, MIRAGE loads an engagement profile. That file is the single source of truth for what is allowed: who authorized the work, the time window it is valid for, the hosts it may run on, the ATT&CK techniques that are in play, and the exact file paths, registry keys, and log channels that are in scope. The checks default to deny. If a target is not explicitly listed, the action is refused. Deny rules always beat allow rules, and a small built in denylist (for example the SAM and SECURITY hives) cannot be switched off by a profile.

**2. Auditing.** Every action is appended to a journal on disk, one JSON object per line. Each entry stores the action, the ATT&CK technique, the target, a snapshot of the state before the change, the state after, a timestamp, the operator, and the SHA-256 hash of the previous entry. That last part forms a hash chain, so editing, reordering, or deleting any past entry breaks verification. If you supply an HMAC key, each entry is also signed, which means someone who rewrites the whole file still cannot forge valid signatures without the key. The journal is a deliverable, not something to clean up.

**3. Reversibility.** Because every action captures its before state, MIRAGE can put the target back. Reverting does not erase anything from the journal. It restores the original state and then appends a new "reverted" entry, so the record shows both the change and its rollback from end to end.

A dry run mode sits on top of all this. In dry run, MIRAGE runs the authorization checks and records what it would have done, but never touches the target. It is the default for a fresh profile, on the theory that you should have to opt in to making real changes.

## Requirements and installation

MIRAGE runs on Python 3.9 or newer. The runtime uses only the Python standard library, so `requirements.txt` is intentionally empty. There is nothing to pip install to use it.

```bash
git clone https://github.com/bcode73/MIRAGE.git
cd MIRAGE
python -m src.main --help
```

For real engagements MIRAGE targets Windows, because the registry and event log backends and the file creation time backend rely on Windows APIs. You can still develop, demo, and run the full test suite on Linux or macOS, where in memory and portable backends stand in for the Windows specific pieces. See [Platform notes](#platform-notes) for the details.

The only extra dependency is for running the tests:

```bash
pip install -r requirements-dev.txt   # installs pytest
python -m pytest
```

## The engagement profile

The profile is a JSON file. Nothing runs without it. Here is a complete example, matching `examples/engagement.example.json`:

```json
{
  "engagement_id": "ACME-2026-RT-014",
  "client": "ACME Corp",
  "operator": "j.doe@redteam.example",
  "authorized_by": "s.smith@acme.example (CISO)",
  "roe_reference": "SOW-2026-014 / RoE v3, signed 2026-09-01",
  "starts_at": "2026-09-27T00:00:00Z",
  "expires_at": "2026-10-04T00:00:00Z",
  "allowed_hosts": ["LAB-WIN10-01", "LAB-WIN10-02"],
  "techniques": ["T1070.006", "T1112", "T1562.002"],
  "dry_run_default": true,
  "scope": {
    "allowed_paths": [
      "C:/RedTeamLab/*",
      "C:/Users/Public/Documents/*"
    ],
    "allowed_registry_keys": [
      "hkcu/software/microsoft/windows/currentversion/explorer/recentdocs/*",
      "hkcu/software/microsoft/windows/currentversion/explorer/typedurls/*"
    ],
    "allowed_channels": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "denied_paths": [
      "C:/Users/*/Desktop/*"
    ],
    "denied_registry_keys": [],
    "denied_channels": []
  },
  "metadata": {
    "notes": "Purple-team detection validation. Revert everything before EOE.",
    "detection_owner": "soc@acme.example"
  }
}
```

What each field means:

- `engagement_id`, `client`, `operator`, `authorized_by`, `roe_reference`: required identity and paperwork fields. They are stamped into every journal entry, which is how an action ties back to a real, authorized piece of work. All five must be non empty.
- `starts_at`, `expires_at`: the validity window, in ISO 8601. A trailing `Z` is accepted, and a timestamp without a timezone is treated as UTC. MIRAGE refuses to do anything before the start or after the expiry, so the window doubles as a built in kill switch. The expiry has to be after the start.
- `allowed_hosts`: a list of hostnames the tool may run on. Case does not matter. A single `"*"` entry allows any host, which is convenient in a throwaway lab but something you would normally pin down for a real engagement.
- `techniques`: the ATT&CK technique IDs that are authorized. Listing a parent authorizes its sub techniques, so `T1562` also permits `T1562.002`. Anything not covered is refused.
- `dry_run_default`: whether actions plan without applying unless you say otherwise. Defaults to `true` when omitted.
- `scope`: the allow and deny lists for file paths, registry keys, and log channels. Entries can be exact values, `*` globs, or prefixes, and matching is case insensitive with forward slashes. Deny always wins over allow, and unlisted targets are refused by default. The SAM and SECURITY registry hives are always denied regardless of what you put here.
- `metadata`: an optional free form object for your own notes. It is carried into the report header.

## Command reference

Every command is invoked as `python -m src.main <command> [options]`. Running `python src/main.py <command>` works too.

The engagement options below are shared by the commands that need them:

- `--profile PATH`: the engagement profile JSON.
- `--journal PATH`: the audit journal file (JSON lines). It is created on first write.
- `--hmac-key-env NAME`: read the journal signing key from this environment variable.
- `--hmac-key-file PATH`: read the journal signing key from this file. The key is never passed on the command line, so it does not leak into your shell history or the process list.

The action commands also take `--dry-run` or `--no-dry-run` to override the profile default for that one run.

**timestomp** (file timestamps, T1070.006)

```bash
# Set all three timestamps (created, modified, accessed) to one moment
python -m src.main timestomp backdate --profile eng.json --journal run.jsonl \
    "C:/RedTeamLab/secret.txt" 2024-01-15 --no-dry-run

# Change only some timestamps, leave the rest alone
python -m src.main timestomp set --profile eng.json --journal run.jsonl \
    "C:/RedTeamLab/secret.txt" --modified 2024-01-15T09:30:00Z --no-dry-run

# Copy another file's timestamps onto the target so it blends in
python -m src.main timestomp match --profile eng.json --journal run.jsonl \
    "C:/RedTeamLab/secret.txt" "C:/Windows/System32/kernel32.dll" --no-dry-run
```

**registry** (registry artifacts, T1112)

```bash
# Set an arbitrary value (defaults to REG_SZ; use --type for others)
python -m src.main registry set --profile eng.json --journal run.jsonl \
    "HKCU\\Software\\Test\\App" Downloaded "C:/RedTeamLab/tool.exe" --no-dry-run

# Delete a value (the original is captured first, so revert restores it)
python -m src.main registry remove --profile eng.json --journal run.jsonl \
    "HKCU\\Software\\Test\\App" Downloaded --no-dry-run

# Plant a RecentDocs artifact, the classic MRU target
python -m src.main registry recent-doc --profile eng.json --journal run.jsonl \
    report.pdf "C:/Users/Public/report.pdf" --no-dry-run
```

**eventlog** (log channel state, T1562.002)

```bash
# Disable a channel to emulate an attacker blinding a sensor
python -m src.main eventlog disable --profile eng.json --journal run.jsonl \
    "Microsoft-Windows-Sysmon/Operational" --no-dry-run

# Turn it back on
python -m src.main eventlog enable --profile eng.json --journal run.jsonl \
    "Microsoft-Windows-Sysmon/Operational" --no-dry-run
```

**revert** (roll everything back)

```bash
python -m src.main revert --profile eng.json --journal run.jsonl
```

By default revert keeps going if one action fails and reports the failures at the end, exiting non zero if any did not revert. Pass `--strict` to stop at the first failure instead.

**report** (generate the purple team report)

```bash
# Write all three formats into a directory
python -m src.main report --journal run.jsonl --profile eng.json --out ./out

# Or print one format to stdout
python -m src.main report --journal run.jsonl --format md
```

**verify** (check the journal has not been tampered with)

```bash
python -m src.main verify --journal run.jsonl --hmac-key-env MIRAGE_KEY
```

**info** (summarize the engagement and journal)

```bash
python -m src.main info --profile eng.json --journal run.jsonl
```

Commands exit `0` on success and `2` on an error such as a scope violation, an expired engagement, a bad profile, or a missing file. The error message goes to stderr and tells you what went wrong.

## A full walkthrough

Here is a typical loop on a lab host, from setup to clean handoff. Assume `eng.json` is the profile above (edited so `allowed_hosts` matches your lab box and `dry_run_default` is `false`), and `run.jsonl` is the journal for this run.

```bash
# 1. Sanity check the engagement before touching anything
python -m src.main info --profile eng.json --journal run.jsonl

# 2. Optionally sign the journal so it cannot be altered without detection
export MIRAGE_KEY="$(head -c 32 /dev/urandom | base64)"

# 3. Backdate a planted file
python -m src.main timestomp backdate --profile eng.json --journal run.jsonl \
    --hmac-key-env MIRAGE_KEY "C:/RedTeamLab/secret.txt" 2024-01-15

# 4. Plant a RecentDocs entry and disable a log channel
python -m src.main registry recent-doc --profile eng.json --journal run.jsonl \
    --hmac-key-env MIRAGE_KEY report.pdf "C:/Users/Public/report.pdf"
python -m src.main eventlog disable --profile eng.json --journal run.jsonl \
    --hmac-key-env MIRAGE_KEY "Microsoft-Windows-Sysmon/Operational"

# 5. Give the SOC time to detect, then confirm the journal is intact
python -m src.main verify --journal run.jsonl --hmac-key-env MIRAGE_KEY

# 6. Produce the report for the debrief
python -m src.main report --journal run.jsonl --profile eng.json --out ./out

# 7. Put the host back exactly as you found it
python -m src.main revert --profile eng.json --journal run.jsonl \
    --hmac-key-env MIRAGE_KEY
```

After step 7 the file timestamps, the registry value, and the log channel are all back to their original state, and the journal contains both the original actions and their matching reverted entries.

## The audit journal

The journal is a plain JSON lines file, which makes it easy to read, grep, and diff. Each line is one action. A single timestomp entry looks roughly like this (formatted here for readability, one line in the file):

```json
{
  "seq": 0,
  "timestamp": "2026-09-27T23:36:44.512000+00:00",
  "engagement_id": "ACME-2026-RT-014",
  "operator": "j.doe@redteam.example",
  "action": "timestomp.set",
  "technique": "T1070.006",
  "target": "C:/RedTeamLab/secret.txt",
  "status": "applied",
  "before": {"accessed_ns": 1790552203508174646, "modified_ns": 1790552976311388970, "created_ns": null},
  "after":  {"accessed_ns": 1705309200000000000, "modified_ns": 1705309200000000000, "created_ns": null},
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "reverts_seq": null,
  "entry_hash": "…",
  "signature": "…"
}
```

The `entry_hash` covers the content of the entry, and `prev_hash` points at the previous entry's hash, so the entries form a chain. When you open a journal, MIRAGE re-derives the whole chain and, if you gave it a key, checks every signature. If anything does not line up, it refuses to continue and tells you which entry is off. That check runs on every command that reads the journal, so tampering surfaces the moment you next touch the file.

Statuses you will see: `planned` for a dry run, `applied` for a real change, `reverted` for a rollback entry, and `failed` for an attempt that did not complete.

## The purple team report

The report is the artifact you actually hand to the defenders. It reads the journal, maps each action to its ATT&CK technique, and lays out what the SOC should have observed. It comes in three shapes:

- **Markdown** for the human readable debrief. It opens with the engagement header, then an ATT&CK coverage table, then a section per action listing the data sources, the exact Windows and Sysmon event IDs to look for, the observable artifacts, and detection guidance.
- **JSON** for tooling. Diff it against your SIEM alerts to find the gaps automatically.
- **ATT&CK Navigator layer** for a quick visual of which techniques were exercised, ready to import into the MITRE ATT&CK Navigator.

`report --out ./out` writes all three as `mirage-report.md`, `mirage-report.json`, and `mirage-report.navigator.json`. The read is simple: any emulated action with no matching detection is a coverage gap and a finding.

## Reverting an engagement

Reverting walks the applied actions newest first and restores each one from its recorded before state. A timestomp goes back to the original timestamps, a registry value goes back to its old data (or is deleted if it did not exist before), and a disabled channel is switched back on. Each rollback is written to the journal as its own `reverted` entry, so nothing about the history is lost.

Revert is designed to work in a fresh process, not just the one that made the changes. When you run the `revert` command, MIRAGE rebuilds the reverter for every module from code, so you can apply changes in one session and roll them back later from another. On a real Windows target this is seamless because the registry and file system hold the state between runs.

## Techniques and ATT&CK mapping

MIRAGE ships with three modules today, each mapped to a Defense Evasion technique:

| Module | Technique | What it emulates |
| --- | --- | --- |
| `timeline_spoofer` | T1070.006 Timestomp | Rewriting a file's created, modified, and accessed times |
| `registry_planter` | T1112 Modify Registry | Planting or removing explorer MRU artifacts such as RecentDocs and TypedURLs |
| `event_injector` | T1562.002 Disable Windows Event Logging | Turning a log channel off and back on |

The report also carries detection metadata for the parent techniques T1070 and T1562 and for T1070.001 (clearing logs) so the mapping stays useful as the tool grows.

## Platform notes

MIRAGE is built for Windows targets, but it is written so you are not stuck on Windows to work on it.

- **Timestamps.** The portable backend uses `os.utime` and can set modified and accessed times on any operating system. Setting the creation time needs the Windows `SetFileTime` API, so the created timestamp is read on other platforms but only written on Windows. The Windows backend is imported lazily, so the module loads fine on Linux and macOS.
- **Registry.** Real work uses the standard library `winreg` module on Windows. On other platforms an in memory backend stands in, which is what the test suite exercises.
- **Event log.** Real work shells out to `wevtutil` on Windows. Elsewhere an in memory backend tracks channel state for tests and demos.

The in memory backends are for development and testing. They do not persist between separate command invocations, so a real revert across two runs depends on the real backends, which is exactly the situation on a Windows target.

## Project layout

```
MIRAGE/
├── src/
│   ├── __init__.py            # package exports
│   ├── engagement.py          # engagement profile and scope enforcement
│   ├── audit.py               # hash chained journal and revert engine
│   ├── context.py             # the backbone every action runs through
│   ├── attack.py              # ATT&CK detection catalog
│   ├── report.py              # purple team report (json, markdown, navigator)
│   ├── timeline_spoofer.py    # timestomp module (T1070.006)
│   ├── registry_planter.py    # registry module (T1112)
│   ├── event_injector.py      # event log module (T1562.002)
│   ├── errors.py              # exception hierarchy
│   └── main.py                # command line orchestrator
├── tests/                     # pytest suite
├── examples/
│   └── engagement.example.json
├── requirements.txt           # empty; runtime is standard library only
├── requirements-dev.txt       # pytest
└── pyproject.toml             # pytest configuration
```

## Development and tests

The test suite runs anywhere Python 3.9 or newer is installed, with no Windows required, thanks to the portable and in memory backends.

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The tests cover the authorization gates, scope precedence and the built in denylist, journal integrity and tamper detection, HMAC signing, the apply and dry run and revert round trips for all three modules, and the report output in every format. If you add a module, follow the same shape: run it through `EngagementContext`, capture a before state, register a reverter, and give it an ATT&CK technique so the report picks it up.

## Safety, authorization, and the law

This is offensive tooling. Run it only against systems you own or have explicit, written permission to test, and only inside the scope your rules of engagement define. In practice that means isolated lab machines or hosts that are named in a signed statement of work.

A few things worth saying plainly:

- The registry and file operations need appropriate privileges. On a live host that means an administrator context.
- Keep the engagement profile honest. The whole safety model rests on the scope, the host list, and the time window being accurate. A profile that allows everything gives up most of what makes this tool safe to run.
- Revert before you leave. The journal proves what you did, and the revert command undoes it. Both are part of a clean engagement, not optional extras.

Using this tool to frame someone, to tamper with evidence in a real investigation, or against systems you are not authorized to touch is illegal, and it is not what MIRAGE is for. You are responsible for how you use it.
