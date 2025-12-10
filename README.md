# DE&TH Detection Repo
Repository for the Detection Engineering & Threat Hunting (DE&TH) course. Within this project there are detectors for file detections via YARA, network detections via Snort, and a wider range of use-cases available in the SigmaHQ project.

## Overview
This repository contains detection content used during the DE&TH course by Level Effect. It focuses on:
- File-based detections using YARA rules (see `yara/`)
- Host/network detections expressed for Sigmas (see `sigma/`) and Snort.

## Repository layout
- `sigma/` — Sigma rules, templates, and helpers related to SigmaHQ translation
- `yara/` — YARA rules and signatures for file-based detections

## Getting started
1. Clone the repository:

```sh
git clone https://github.com/p-o-s-t/death.git
cd death
```

2. Inspect YARA rules in `yara/` and test with your local `yara` binary:

```
yara -r yara/ <target-file-or-directory>
```

3. For Sigma rules, use PySigma converter (from SigmaHQ) to translate rules to your SIEM backend. Example (assuming `sigmacli` is installed):

```
sigmacli -t splunk -c <schema> sigma/<rule>.yml
```

## Examples
- Add a sample YARA rule and a sample log event for Sigma in `examples/` to make the repo easier to use for newcomers.