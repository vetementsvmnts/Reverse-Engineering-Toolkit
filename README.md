# RE Toolkit

A reverse engineering toolkit for analyzing ELF binaries on Kali Linux.

## Features

- File info + hashes (MD5, SHA1, SHA256)
- Security mitigations (checksec-style)
- ELF structure (sections, segments)
- Imports / Exports / Symbols
- String extraction with smart categorization
- Entropy analysis (packing detector)
- Disassembly with integer password detection (via Capstone)
- Anti-debug detection
- CVE lookup via the NVD API

## Install

```bash
git clone https://github.com/vetementsvmnts/Reverse-Engineering-Toolkit.git
cd Reverse-Engineering-Toolkit
python3 -m venv venv
source venv/bin/activate
pip install -e .
