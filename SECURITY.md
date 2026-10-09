# Security & Dual-Use Compliance Policy

## 1. Purpose and Scope
FinDroid-BD is an academic and defensive cybersecurity research dataset and static-analysis pipeline designed exclusively for:
- Academic and educational instruction in mobile security and threat intelligence.
- Machine-learning classification benchmarking for benign vs. malicious mobile financial software.
- Reproducible feature engineering for defensive security tooling.

This repository complies fully with the **GitHub Acceptable Use Policies** regarding [Dual-Use Security Research and Proof-of-Concept Content](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies).

## 2. No Executable Malware or Weaponized Payloads
- **No live malware binaries, weaponized payloads, or functional exploit code are hosted, distributed, or mirrored in this repository.**
- All sample identifiers consist strictly of cryptographic hashes (SHA-256), package metadata, extracted static feature matrices, CSV/Parquet files, and SQLite relational tables.
- Raw APK binaries are strictly excluded from the Git tree and all release assets via automated release sanitizers and  controls.

## 3. Responsible Use Disclaimer
This repository and its associated datasets must not be used for malicious purposes, unauthorised penetration testing, malware redistribution, or any activity that compromises user privacy or security. 

## 4. Reporting Security Vulnerabilities & Inquiries
If you discover a security concern, inadvertent exposure of sensitive data, or have questions regarding data provenance, please contact the maintainer directly:

- **Maintainer:** Ilias Sami
- **Email:** iliassami57@gmail.com
- **Response Time:** We aim to review and respond to inquiries within 48 hours.
