# KariDNS & dag Distribution Guide

This document describes how to install and use KariDNS and its accompanying toolset (`dag`, `karictl`, `karicheck`) across supported operating systems.

---

## 1. Distribution Matrix

| OS / Platform | Artifact Format | Included Binaries / Assets | Installation Method |
|---|---|---|---|
| **FreeBSD** (14.x / 15.x) | `.pkg` | `karidns`, `karictl`, `karicheck`, `dag`, sample configs, rc.d script | `pkg install` / `pkg add` |
| **Linux (RPM)** (RHEL/Fedora/Rocky) | `.rpm` | `dag` | `dnf install` / `rpm -ivh` |
| **Linux (DEB)** (Ubuntu/Debian) | `.deb` | `dag` | `dpkg -i` / `apt install` |
| **Linux (Generic)** | `.tar.gz` | `dag` (standalone binary) | Extract & copy to `/usr/local/bin` |
| **macOS** | `.dmg`, `.tar.gz` | `dag` (Universal Binary: arm64 + x86_64) | Mount DMG / CLI install |
| **Homebrew** | Formula (`dag.rb`) | `dag` | `brew install <user>/tap/dag` |

---

## 2. FreeBSD Installation (`pkg`)

### 2.1 Installing from Pre-built Package
Download the appropriate package for your FreeBSD release from GitHub Releases and install as root (`su -`):
- **FreeBSD 14.x:** `karidns-?.?.?-FreeBSD-14-amd64.pkg`
- **FreeBSD 15.x:** `karidns-?.?.?-FreeBSD-15-amd64.pkg`

```sh
# Switch to root
su -

# For FreeBSD 14.x
pkg add karidns-?.?.?-FreeBSD-14-amd64.pkg

# For FreeBSD 15.x
pkg add karidns-?.?.?-FreeBSD-15-amd64.pkg
```

### 2.2 Installed Components
- **Binaries:**
  - `/usr/local/sbin/karidns` (Authoritative DNS daemon)
  - `/usr/local/bin/karictl` (Dynamic control tool)
  - `/usr/local/bin/karicheck` (Configuration & zone syntax checker)
  - `/usr/local/bin/dag` (DNS query client & fuzzer)
- **Configuration & Zones:**
  - `/usr/local/etc/karidns/karidns.conf.sample`
  - `/usr/local/etc/karidns/karictl.conf.sample`
  - `/usr/local/etc/karidns/zones/example.local.zone.sample`
- **Service Management:**
  - `/usr/local/etc/rc.d/karidns`

### 2.3 Starting the Service
1. Copy configuration:
   ```sh
   cp /usr/local/etc/karidns/karidns.conf.sample /usr/local/etc/karidns/karidns.conf
   ```
2. Enable and start:
   ```sh
   sysrc karidns_enable="YES"
   service karidns start
   ```

---

## 3. Linux Installation (`dag`)

### 3.1 RPM-based (RHEL, Fedora, Rocky, AlmaLinux, openSUSE)
```sh
sudo rpm -ivh dag-?.?.?-1.x86_64.rpm
```

### 3.2 DEB-based (Ubuntu, Debian, Linux Mint)
```sh
sudo dpkg -i dag_?.?.?_amd64.deb
```

### 3.3 Tarball (Generic Linux)
```sh
tar -xzf dag-?.?.?-linux-x86_64.tar.gz
sudo cp dag-?.?.?/dag /usr/local/bin/
```

---

## 4. macOS Installation (`dag`)

### 4.1 Homebrew (Recommended)
You can install `dag` directly via Homebrew from the GitHub release formula:

```sh
# Option 1: Direct install from release Formula
brew install https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag.rb

# Option 2: Via Homebrew Tap repository
brew tap NoelMinamino/karidns
brew install dag

# Or in a single command
brew install NoelMinamino/karidns/dag
```

### 4.2 Standalone DMG
1. Download the DMG for your architecture from GitHub Releases:
   - **Apple Silicon (M1/M2/M3/M4):** `dag-?.?.?-macos-arm64.dmg`
   - **Intel:** `dag-?.?.?-macos-x86_64.dmg`
2. Double click to mount the DMG.
3. Copy `bin/dag` to `/usr/local/bin`:
   ```sh
   sudo cp /Volumes/DAG/bin/dag /usr/local/bin/
   ```

---

## 5. Using `dag` (DNS Anomaly Generator)

`dag` is a lightweight, high-performance DNS test client and protocol inspector.

```sh
# Standard UDP Query
dag example.local A @127.0.0.1

# TCP Query with DNSSEC & EDNS
dag example.local A @127.0.0.1 +tcp +dnssec +edns

# Multi-server benchmark & verification
dag example.local A @8.8.8.8,1.1.1.1,9.9.9.9

# Anomaly testing / packet fuzzing
dag example.local A @127.0.0.1 --break id_zero
```
