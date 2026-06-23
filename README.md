# MIRAGE - Forensic Timeline Manipulator & Event Gaslighter

**MIRAGE** is a unique, Python-based post-exploitation tool that weaponizes the *trust* forensic investigators place in Windows artifacts. Instead of deleting logs (which alerts the SOC), MIRAGE injects perfectly crafted, fake forensic evidence—backdating file timestamps, injecting fake security logon events, and planting gaslighting registry entries to frame innocent processes. 

The result: The blue team spends days investigating a ghost, destroying the integrity of their incident response.

## ⚠️ DISCLAIMER
This tool is intended **STRICTLY for authorized security testing, red-team engagements, and internal educational laboratories only**. Unauthorized use of this tool to frame individuals, evade law enforcement, or manipulate evidence in production environments is illegal and a federal crime. The author assumes zero liability for misuse or illegal activities performed with this software. By using this tool, you agree to comply with all applicable local, state, national, and international laws.

## 🚀 FEATURES
- **Timeline Spoofing**: Modifies the `$MFT` and file metadata (Modified, Accessed, Created timestamps) to backdate or future-date specific files using Windows `SetFileTime` API.
- **False Positive Injection**: Injects fake Event ID 4624 (successful logons) into the Windows Security Event Log using `wevtutil`, using randomized IP addresses and usernames to distract the SOC.
- **Registry Gaslighting**: Plants false entries into the user's `RecentDocs` and `TypedURLs` registry keys, making specific innocent applications look like the threat actor's primary tool.
- **Auto-Revert Timer**: Sets an internal countdown timer to automatically revert all changes after a specified number of hours, leaving zero forensic trace of the manipulation.

## 📦 INSTALLATION
This tool runs exclusively on Windows and uses built-in Python modules and native Windows binaries. No external pip dependencies are required. Ensure you are running Python 3.6+.

## 🎯 USAGE

**Execute MIRAGE against a target file to backdate it, inject a fake login, and plant a fake recent document:**
```powershell
python src\main.py --target-file "C:\Users\Public\Documents\secret.txt" --backdate 2024-01-15 --inject-logon --plant-recent
Set MIRAGE to automatically revert the timeline after 4 hours (3600 seconds):

powershell
python src\main.py --target-file "C:\Users\Public\Documents\secret.txt" --backdate 2024-01-15 --revert 14400
Run all modules in headless/quiet mode (no console output):

powershell
python src\main.py --target-file "C:\Users\Public\Documents\secret.txt" --backdate 2024-01-15 --inject-logon --plant-recent --quiet
📁 PROJECT STRUCTURE
text
mirage/
├── src/
│   ├── __init__.py
│   ├── timeline_spoofer.py    # Manipulates $MFT and file timestamps (SetFileTime)
│   ├── event_injector.py      # Injects fake 4624 login events into Security logs
│   ├── registry_planter.py    # Plants false entries into RecentDocs & TypedURLs
│   └── main.py                # CLI orchestrator & Auto-revert timer
├── README.md                  # This file
└── .gitignore
📄 OUTPUT / ARTIFACTS
No persistent files are written to disk.

All operations occur in memory and local Windows Event Logs.

If the --revert flag is used, all injected events and registry entries are automatically purged after the designated time.

🛡️ ETHICAL GUARDRAILS
Absolute rule: Run this ONLY on isolated, offline virtual machines or standalone lab laptops you own.

This tool requires Administrator privileges to modify the $MFT timestamps and write to the Security Event Log.

The --revert flag is mandatory in live engagements to ensure complete cleanup.

Never use this to intentionally frame co-workers, contractors, or civilians.

🔍 HOW IT WORKS
Timeline Spoofer: Takes a target file path and a fake date. It uses Python's ctypes to call Windows CreateFile and SetFileTime APIs to directly rewrite the Modified, Access, and Creation timestamps in the NTFS Master File Table.

Event Injector: Generates a random IP address and a dummy username. It shells out to wevtutil to write a custom event into the Windows Security event log, matching the exact JSON schema of Event 4624.

Registry Planter: Opens the Windows Registry hive for HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs and TypedURLs and inserts a binary/string entry pointing to a fully qualified file path of an innocent application.

Auto-Revert: At the moment of execution, a multithreaded timer begins. Once it reaches zero, it reverts the targeted file's timestamps back to their original values, deletes the injected log events, and cleans the registry keys.

🧹 CLEANUP
If you have not set the --revert timer, you can manually force a cleanup by running the same command with the --clean flag:

powershell
python src\main.py --clean --target-file "C:\Users\Public\Documents\secret.txt"
