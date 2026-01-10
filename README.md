# DE&TH Detection Repo
Repository for the Detection Engineering & Threat Hunting (DE&TH) course. Within this repository there are detectors for file detections via YARA, network detections via Snort, and SIEM-agnostic queries using Sigma.

**NOTE:** The rules in this repository are intended for education and not meant to be pulled into a production environment.

## Overview
This repository contains detection content used during the DE&TH course by Level Effect. It focuses on:
- File-based detections using YARA rules (see `yara/`)
- Host/network detections expressed for Sigmas (see `snort/`) and Snort.
- Event-based or behavior-based detections using Sigma. (see `sigma/`)

## Getting started
1. Clone the repository:

```sh
git clone https://github.com/p-o-s-t/lvl_effect_death.git
cd lvl_effect_death
```

2. Inspect YARA rules in `yara/` and test with your local `yara` binary:

```sh
yara -r yara/ <target-file-or-directory>
```

3. For Sigma rules, use PySigma converter (from SigmaHQ) to translate rules to your SIEM backend. Example (assuming `sigmacli` is installed):

```sh
sigmacli -t splunk -c <schema> sigma/<rule>.yml
```


## Tools Used
- yarGen
  - [Python](https://github.com/Neo23x0/yarGen)
  - [Go](https://github.com/Neo23x0/yarGen-go) 
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
