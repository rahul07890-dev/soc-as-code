# SOC-as-Code Framework

## Overview

The **SOC-as-Code Framework** is an automated, research-grade system for validating, testing, classifying, and governing cybersecurity detection rules (Sigma/YARA).
This project treats detection rules as version-controlled software artifacts and applies CI/CD practices to ensure correctness, maintainability, and measurable detection quality.

The system includes a **universal log generator**, a **full Sigma evaluator**, a **rule validator**, a **classification and scoring engine**, and **diagnostic tooling**—all integrated with GitHub Actions for automated governance.

---

## Technologies Used

* **Python 3.x** — Core implementation language.
* **Universal Synthetic Log Generator** — Multi-platform log simulation engine (Windows, Linux, AWS, Azure, Okta, OneLogin, M365, Google Workspace, Proxy, Network, OpenCanary, etc.).
* **Sigma Rule Engine (SOCSimulator)** — Full pattern evaluator with support for Sigma modifiers.
* **JSON/YAML Processing** — For rule parsing, report generation, and classification.
* **GitHub Actions** — CI/CD pipeline for automated validation.
* **Regex, Pattern Matching, and Nested Field Evaluation** — For deep rule matching accuracy.

---

## Directory Structure

```
soc-as-code/
├── .github/
│   └── workflows/
│       └── validate-rules.yml          # CI/CD pipeline for rule validation
│
├── rules/
│   ├── sigma/                          # Sigma rule definitions
│   └── yara/                           # YARA rule definitions
│
├── validator/
│   ├── validate_rules.py               # Core rule validator
│   ├── generate_logs.py                # Synthetic log generator
│   ├── generate_report.py              # Markdown summary report builder
│   ├── compare_and_classify.py         # Rule scoring + classification engine
│   ├── check_results.py                # CI interpretation + pass/fail logic
│   ├── diagnose_rules.py               # Local diagnostics for debugging rules
│   ├── test_single_rule.py             # Full local pipeline test for a single rule
│   └── __init__.py
│
├── test.py                             # SOCSimulator: Sigma evaluator + alert generation
├── requirements.txt                    # Python dependencies
└── README.md                           # Project documentation
```

---

## Requirements

* **Python 3.9 or higher**
* **pip** + virtual environment recommended
* GitHub Actions (optional, for automated CI/CD)
* YAML-compatible Sigma rules & optional YARA rules

---

## Dependencies

Install all required packages using:

```bash
pip install -r requirements.txt
```

Libraries include:

* **pyyaml** — Rule parsing
* **regex** — Pattern interpretation
* **json** — Log data processing
* **datetime** — Report metadata
* **pathlib** — Consistent file handling

---

## How It Works

### Core Components

---

### 1. Universal Synthetic Log Generator (`generate_logs.py`)

Generates **positive** (matching) and **negative** (non-matching) synthetic logs for each rule.

Supports more than **50+ log source types**, including:

* Windows process/file events
* Linux process activity
* AWS CloudTrail
* Azure ActivityLogs / PIM
* Okta, OneLogin
* Microsoft 365
* Google Workspace
* Proxy/Web logs
* Network telemetry
* OpenCanary honeypot events

**Special logic:**
New rules (e.g., IDs starting with `SIG-900`) intentionally produce **zero synthetic logs** to prevent score manipulation.

---

### 2. Sigma Rule Evaluator (`SOCSimulator`, in `test.py`)

A complete Sigma detection engine implementing:

* Field modifiers:
  `|contains`, `|startswith`, `|endswith`, `|re`, `|base64`, `|all`, `|exists`, `|gt`, `|lt`, etc.
* Wildcards & regex-like expressions
* Nested field matching (`actor.email`, `process.name`, etc.)
* Boolean detection conditions
* Multi-selection merging

This enables **academically reproducible** rule evaluation.

---

### 3. Rule Validator (`validate_rules.py`)

Processes each rule by:

1. Loading synthetic logs
2. Executing Sigma matching logic
3. Recording match data
4. Saving structured results (`detections.json`, `validation_results.json`)
5. Providing metadata for downstream scoring

---

### 4. Classification & Scoring Engine (`compare_and_classify.py`)

Compares:

* **Baseline detections** (previous known-good state)
* **Current detections** (introduced by new rule)

Extracts rule identifiers from YAML:

* ID
* Title
* Filename

Each rule receives a **0–100 score** based on:

* True-positive improvement
* False-positive regression
* Precision delta
* Detection consistency
* Identifier correctness

Grades:

* **EXCELLENT** – major positive impact
* **GOOD** – improves detection quality
* **NEUTRAL** – no major effect
* **CONCERNING** – potential issues
* **BAD** – harmful or faulty rule

Produces:

* `classification_report.json`
* Human-readable Markdown summary (`summary.md`)

---

### 5. Diagnostic Tools

* **`diagnose_rules.py`**
  Shows why a rule did not match logs, expected fields, actual fields, and suggested fixes.

* **`test_single_rule.py`**
  Runs the **entire pipeline** for one rule from:
  log generation → validation → classification → report summary.

These tools dramatically simplify research workflows and debugging experiments.

---

## Setup Instructions

1. **Clone this repository**

```bash
git clone https://github.com/rahul07890-dev/soc-as-code.git
cd soc-as-code
```

2. **Create and activate virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Run local validation**

```bash
python validator/validate_rules.py --rules rules/sigma --synthetic synthetic_logs/ --mode current
```

5. **(Optional) Enable GitHub Actions**
   Simply push to GitHub — the included workflow will auto-run.

---

## Features

* Automated validation of Sigma & YARA rules
* Synthetic log generation for realistic test scenarios
* Precision-based scoring and classification
* CI/CD pipeline with automated pass/fail
* Diagnostic tooling for debugging rule quality
* Baseline drift detection
* Human-readable and machine-readable reporting

---

## TODO / Improvements

* Add real log ingestion for hybrid precision evaluation
* Enhance ATT&CK technique validation and mapping
* Expand OneLogin/Okta/M365 schema coverage
* Improve anomaly scoring and statistical baselining
* Add Sigma→SIEM translator validation (Elastic, Splunk, Sentinel)
* Add machine learning–assisted rule tuning

---

## Contribution

Pull requests are welcome.
For major changes, please open an issue to discuss your proposal, experiment, or research direction.

---

## License

This project is released under the **MIT License** (or add your preferred license).

---

## Acknowledgments

* Sigma HQ community
* Open-source detection engineering ecosystem
* Security researchers contributing to rule standardization
* Academic research in SOC automation and evaluative frameworks

---

**SOC-as-Code transforms detection engineering into a structured, testable, and research-ready discipline.**
