# STAV — Super Tiny Anti-Virus

**A lightweight, command-line malware scanner for Linux.**

STAV is a small C-based security tool designed to scan files and directories using SHA-256 hash matching. Its goal is simple: keep the scanner lightweight, make it easy to use from the terminal, and avoid unnecessary complexity.

It uses a local malware hash database to identify files whose SHA-256 fingerprints match known entries.

---

## Overview

STAV focuses on a straightforward scanning workflow:

- Scan individual files or entire directories.
- Calculate SHA-256 hashes using OpenSSL.
- Compare file hashes against a local malware database.
- Display detected threats and their available names.
- Use memory-mapped database files to reduce database loading overhead.
- Optionally check for recent malware database updates through the MalwareBazaar API.

STAV is designed for Linux systems and is written in C.

## How detection works

STAV uses hash-based detection.

For each scanned file, it calculates its SHA-256 hash and checks whether that hash exists in its malware database.

If a match is found, the file is reported as a known threat.

This approach is useful for identifying files that have already been catalogued, but it has limitations:

- Modified malware may have a different hash.
- Unknown malware cannot be identified unless its hash is present in the database.
- A matching hash identifies a known sample; it does not provide behavioral analysis.

STAV is not intended to replace a full-featured endpoint security solution.

## Requirements

- Linux
- GCC
- Make
- OpenSSL development libraries
- libcurl development libraries
- Jansson development libraries

On Ubuntu and Linux Mint, install the required packages with:

```bash
sudo apt update
sudo apt install gcc make libssl-dev libcurl4-openssl-dev libjansson-dev
```

## Installation

Clone the repository:

```bash
git clone https://github.com/TneverD/STAV.git
cd STAV
```

Make the installer executable:

```bash
chmod +x install.sh
```

Run it:

```bash
./install.sh
```

The installer compiles the source code and installs the executable at:

```text
/usr/local/bin/stav
```

## Usage

Start STAV:

```bash
stav
```

Scan a file:

```bash
stav scan /path/to/file
```

Scan a directory:

```bash
stav scan /path/to/directory
```

Replace the example paths with the actual file or directory you want to scan.

## Malware database

STAV uses a local database containing SHA-256 hashes of known malware samples.

The default data directory is:

```text
~/.local/share/stav/
```

Main database files:

| File | Description |
|---|---|
| `malware.sha256` | Text-based SHA-256 database |
| `malware.sha256.bin` | Binary database used for faster lookup |
| `malware.names` | Available malware names and signatures |

The database is separate from the scanner executable.

## Database updates

STAV includes an update mechanism that can communicate with the MalwareBazaar API.

API access requires an API key from [abuse.ch](https://auth.abuse.ch/).

The API key is stored at:

```text
~/.config/stav/api_key
```

Network access is required for online update operations. Local scanning uses the local database.

## Project structure

```text
STAV/
├── stav.c
├── install.sh
└── README.md
```

## Design goals

STAV is built around a few practical goals:

- **Small:** Keep the codebase and runtime overhead low.
- **Fast:** Avoid unnecessary work during database lookup and scanning.
- **Simple:** Provide a terminal-based workflow without requiring a graphical interface.
- **Independent:** Keep the local malware database separate from the application.
- **Transparent:** Report hash matches rather than claiming to detect every kind of malware.

## Limitations

STAV currently relies on SHA-256 database matching. It does not provide:

- Behavioral malware analysis
- Heuristic or AI-based detection
- Real-time filesystem protection
- Guaranteed detection of unknown malware
- Automatic removal or disinfection of infected files

A clean scan only means that no matching hash was found in the database used for that scan.

---

**STAV — Super Tiny Anti-Virus**

*A small scanner with a focused job.*
