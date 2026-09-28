# KariDNS & dag Distribution Guide

This document describes how to install and use KariDNS and its accompanying toolset (`dag`, `karictl`, `karicheck`) across supported operating systems. Release packages are built by the GitHub Actions release workflow (`.github/workflows/release.yml`) with the scripts under `packaging/`, and are published on [GitHub Releases](https://github.com/NoelMinamino/KariDNS/releases). They are built for the baseline instruction set of their architecture (`MARCH_FLAGS=`), so they run on any compatible CPU.

In the commands below, replace `?.?.?` with the release version (for example `0.4.2`).

---

## 1. Distribution Matrix

| OS / Platform | Artifact | Included Binaries / Assets | Installation Method |
|---|---|---|---|
| **FreeBSD** 14.x / 15.x (amd64) | `karidns-?.?.?-FreeBSD-14-amd64.pkg`, `karidns-?.?.?-FreeBSD-15-amd64.pkg` | `karidns`, `karictl`, `karicheck`, `dag`, sample configs, rc.d script | `pkg add` |
| **Linux (RPM)** RHEL 9 / Rocky / AlmaLinux / Fedora (x86_64) | `dag-?.?.?-1.el9.x86_64.rpm` | `dag` | `dnf install` / `rpm -ivh` |
| **Linux (DEB)** Ubuntu / Debian (amd64) | `dag_?.?.?_amd64.deb` | `dag` | `dpkg -i` |
| **Linux (Generic)** x86_64 | `dag-?.?.?-linux-x86_64.tar.gz` | `dag` (standalone binary) | Extract & copy to `/usr/local/bin` |
| **macOS** Apple Silicon (arm64) | `dag-?.?.?-macos-arm64.dmg`, `dag-?.?.?-macos-arm64.tar.gz` | `dag` (arm64 binary) | Mount DMG / extract tarball |
| **Homebrew** (macOS, Linux) | Formula `dag.rb` in `NoelMinamino/homebrew-tap` | `dag` (built from the source tarball) | `brew install NoelMinamino/tap/dag` |
| **Windows** x86_64 | `dag-v?.?.?-windows-x86_64.zip` | `dag.exe` and the MinGW runtime DLLs it needs | Extract & copy to a directory in `%PATH%` |

Each release also contains `SHA256SUMS.txt` (see [§7](#7-verifying-downloads)).

No macOS x86_64 (Intel) package is built at present; on Intel Macs, install with Homebrew or build from source (`make dag`).

---

## 2. FreeBSD Installation (`pkg`)

### 2.1 Installing from Pre-built Package
Download the appropriate package for your FreeBSD release from GitHub Releases and install as root (`su -`). The package depends on `libidn2`; `pkg add` of a downloaded file does not fetch it from the package repository, so install it first:

```sh
# Switch to root
su -

# Runtime dependency (skip if already installed)
pkg install -y libidn2

# For FreeBSD 14.x
pkg add https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/karidns-?.?.?-FreeBSD-14-amd64.pkg

# For FreeBSD 15.x
pkg add https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/karidns-?.?.?-FreeBSD-15-amd64.pkg
```

Use `pkg add -f` to replace an already installed version in place.

### 2.2 Installed Components
- **Binaries:**
  - `/usr/local/sbin/karidns` (Authoritative DNS daemon)
  - `/usr/local/bin/karictl` (Control channel client)
  - `/usr/local/bin/karicheck` (Configuration & zone syntax checker)
  - `/usr/local/bin/dag` (DNS query client & fuzzer)
- **Configuration & Zones:**
  - `/usr/local/etc/karidns/karidns.conf.sample`
  - `/usr/local/etc/karidns/karictl.conf.sample`
  - `/usr/local/etc/karidns/zones/example.local.zone.sample`
- **Service Management:**
  - `/usr/local/etc/rc.d/karidns`

### 2.3 Starting the Service
1. Copy the configuration and sample zone, then edit them (`user`, `group`, secrets, zones):
   ```sh
   cp /usr/local/etc/karidns/karidns.conf.sample /usr/local/etc/karidns/karidns.conf
   cp /usr/local/etc/karidns/zones/example.local.zone.sample /usr/local/etc/karidns/zones/example.local.zone
   ```
2. Enable and start:
   ```sh
   sysrc karidns_enable="YES"
   service karidns start
   ```

The rc.d script supports these `rc.conf` variables:

| Variable | Default | Description |
|---|---|---|
| `karidns_enable` | `NO` | Start `karidns` at boot. |
| `karidns_config` | `/usr/local/etc/karidns/karidns.conf` | Configuration file. |
| `karidns_flags` | `${karidns_config}` | Arguments passed to `karidns`. |

Before starting, the script validates the configuration with `karicheck conf`, creates `/var/run/karidns` (root:wheel, 0755) and `/var/log/named` (owned by the `bind` user, or `named` if `bind` does not exist). `service karidns reload` runs `karictl reload` (or sends `SIGHUP` when `karictl` is not installed), and `service karidns checkconf` runs `karicheck conf`.

---

## 3. Linux Installation (`dag`)

The RPM is built in a Rocky Linux 9 container (glibc 2.34); the DEB and the tarball are built on the Ubuntu release runner.

### 3.1 RPM-based (RHEL 9, Rocky Linux 9, AlmaLinux 9, Fedora)
```sh
sudo dnf install https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag-?.?.?-1.el9.x86_64.rpm

# Or with a downloaded file
sudo rpm -ivh dag-?.?.?-1.el9.x86_64.rpm
```

### 3.2 DEB-based (Ubuntu, Debian)
```sh
curl -LO https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag_?.?.?_amd64.deb
sudo dpkg -i dag_?.?.?_amd64.deb
```

### 3.3 Tarball (Generic Linux)
The tarball contains a `dag-?.?.?/` directory with `dag`, `LICENSE`, `README.md`, `dag.md` and `dag_replay.md`:
```sh
curl -LO https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag-?.?.?-linux-x86_64.tar.gz
tar -xzf dag-?.?.?-linux-x86_64.tar.gz
sudo cp dag-?.?.?/dag /usr/local/bin/
```

---

## 4. macOS Installation (`dag`, Apple Silicon)

### 4.1 Generic Tarball (.tar.gz)
```sh
curl -LO https://github.com/NoelMinamino/KariDNS/releases/download/v?.?.?/dag-?.?.?-macos-arm64.tar.gz
tar -xzf dag-?.?.?-macos-arm64.tar.gz
sudo cp dag-?.?.?/dag /usr/local/bin/
```

### 4.2 Standalone DMG (.dmg)
1. Download `dag-?.?.?-macos-arm64.dmg` from GitHub Releases.
2. Double click to mount the DMG (volume name `DAG`). It contains `bin/dag`, `INSTALL.txt`, `LICENSE`, `README.md`, `dag.md` and `dag_replay.md`.
3. Copy `bin/dag` to `/usr/local/bin`:
   ```sh
   sudo cp /Volumes/DAG/bin/dag /usr/local/bin/
   ```

### 4.3 Homebrew Tap
The release workflow publishes the formula to `NoelMinamino/homebrew-tap`. It builds `dag` from the release source tarball and depends on `openssl@3` and `zlib` (`libidn2` is optional, `--with-libidn2`):
```sh
brew install NoelMinamino/tap/dag
```

---

## 5. Windows Installation (`dag.exe`)

1. Download `dag-v?.?.?-windows-x86_64.zip` from [GitHub Releases](https://github.com/NoelMinamino/KariDNS/releases).
2. Extract the archive. The `dag-v?.?.?-windows-x86_64` folder contains `dag.exe`, the MinGW runtime DLLs it needs, `README.md`, `LICENSE` and `docs/`. Keep the DLLs next to `dag.exe` and add that folder to your `%PATH%` (or copy all of them into a directory in `%PATH%`).
3. Test query in Command Prompt or PowerShell:
   ```cmd
   dag.exe example.com A @192.0.2.53
   ```

---

## 6. Using `dag` (DNS Anomaly Generator)

`dag` is a lightweight, high-performance DNS test client and protocol inspector. See [`dag(1)`](dag.md) for all options.

```sh
# Standard UDP Query
dag example.local A @127.0.0.1

# TCP Query with DNSSEC & EDNS
dag example.local A @127.0.0.1 +tcp +dnssec +edns

# Query several servers and compare the answers
dag example.local A @192.0.2.1,198.51.100.1,203.0.113.1

# Anomaly testing / packet fuzzing (local test servers only)
dag example.local A @127.0.0.1 --break qdcount=2
```

---

## 7. Verifying Downloads

Each release has a `SHA256SUMS.txt` file with the SHA-256 checksums of all release assets. Download it into the same directory as the packages and check them:

```sh
# FreeBSD
sha256 -c "$(grep ' karidns-?.?.?-FreeBSD-15-amd64.pkg$' SHA256SUMS.txt | cut -d' ' -f1)" karidns-?.?.?-FreeBSD-15-amd64.pkg

# Linux
sha256sum --ignore-missing -c SHA256SUMS.txt

# macOS
shasum -a 256 --ignore-missing -c SHA256SUMS.txt
```

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)
