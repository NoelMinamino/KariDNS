# Building KariDNS: ./configure and make

## NAME

**building** — how `./configure` and `make` build the programs of KariDNS, what each option does, and what `make` alone still does.

## SYNOPSIS

```sh
./configure [--prefix=DIR] [--sysconfdir=DIR] [--libexecdir=DIR] [--with-db-drivers=auto|none|sqlite3|postgresql|"sqlite3 postgresql"]
            [--with-idn2=auto|yes|no] [--with-openssl=DIR] [--march=native|none|V] [CC=cc] [CFLAGS=...] [LDFLAGS=...]
make                  # karidns, dag, karictl, karicheck, karidns-tapstat
make karidns-dbloader karidns-zone
make distclean        # make clean, and remove config.mk and config.log
```

## DESCRIPTION

`configure` is a hand-written POSIX `sh` script in the top directory (no autoconf, no m4). It runs on the `sh` of FreeBSD, Linux (dash, bash) and macOS, and in MSYS2 (MinGW is used for `dag` only). It builds in the source tree. It writes two files:

- **`config.mk`**: plain `NAME = value` lines that every `make` reads (`-include config.mk` at the top of the `Makefile`);
- **`config.log`**: every command it ran to test a library, and what the compiler said.

It finds the compiler (`CC`, else `cc`, `gcc` or `clang`), proves with a small test program that OpenSSL and zlib compile and link (every build needs them), and looks for the optional libraries. Run `make clean` after a new `./configure`: the objects of an earlier build do not know the new options.

### Options

| Option | Meaning |
|---|---|
| `--prefix=DIR` | Recorded as `PREFIX` in `config.mk` for the packaging scripts, and the base of the defaults of `--sysconfdir` and `--libexecdir`. It is compiled in as `-DKARIDNS_PREFIX` (only when it is not `/usr/local`) for one name: the FreeBSD ca_root_nss bundle `PREFIX/share/certs/ca-root-nss.crt` that `dag` looks for. `make install` puts the files under it (see INSTALLING). Default `/usr/local`. |
| `--sysconfdir=DIR` | The directory the tools look in for their configuration when they are not told where: `DIR/karidns/karidns.conf` (`karicheck`, `karidns-zone`), `DIR/karidns/karictl.conf` (`karictl`), the example in the help of `karidns-dbloader`. It is compiled in as `-DKARIDNS_SYSCONFDIR="DIR"` (`dns_utils.h`). `dag` looks for its CA bundle (`+tls-ca` without a file) at `DIR/ssl/cert.pem`, as one of its fixed places (below). Default `PREFIX/etc`; the sources default to `/usr/local/etc`, and only another directory adds a flag, so the default build is the build without `configure`. The rc scripts, the packages and the manuals keep the FreeBSD layout (`/usr/local/etc`). Only letters, digits and `_ . / + @ -` are allowed. |
| `--libexecdir=DIR` | Where `karidns` finds the database loader when `loader-path` is not set: `DIR/karidns-dbloader` (`KARIDNS_DB_DEFAULT_LOADER_PATH` in `dns_config_parser.h`; `karicheck conf` and the server both use it). Compiled in as `-DKARIDNS_LIBEXECDIR="DIR"`. Default `PREFIX/libexec`. The FreeBSD packages install the loader in `/usr/local/libexec` and the manuals say so; a package for another layout passes `--libexecdir`. |
| `--with-db-drivers=LIST` | The drivers of `karidns-dbloader` and `karidns-zone`: `auto` (the default: the drivers whose library is found), `none`, `sqlite3`, `postgresql`, or both (`"sqlite3 postgresql"` or `sqlite3,postgresql`). A driver that is named and not found is an error. `make DB_DRIVERS=...` on the command line still wins over `config.mk`. |
| `--with-idn2=auto\|yes\|no` | libidn2 for `dag` (internationalized names). `yes` is an error when it is not found; `auto` (the default) says so in the summary. `--with-idn2` is `yes`, `--without-idn2` is `no`. |
| `--with-openssl=DIR` | OpenSSL is in `DIR/include` and `DIR/lib`. The default is the system's, or the Homebrew one on macOS. The `Makefile` always searches `/usr/local` and the Homebrew directories first (`BREW_CFLAGS`, `BREW_LDFLAGS`): with a second copy of OpenSSL there, put your directory first in `CFLAGS` and `LDFLAGS`. |
| `--march=native\|none\|V` | `native` (the default): `-march=native`, the CPU of the build host. `none`: the baseline of the architecture, for a package that runs on other machines. `V`: `-march=V`. A default `native` that the compiler refuses becomes `none` with a line in the summary; a value that was asked for and is refused is an error. |
| `CC`, `CFLAGS`, `LDFLAGS` | From the environment or as arguments. They are saved in `config.mk`; the flags of the `Makefile` are added to them. |

### The CA bundle of dag

`dag +tls-ca` without a file loads the default store of OpenSSL (it honours `SSL_CERT_FILE`), then the first readable file of a fixed list: `/etc/ssl/cert.pem`, `SYSCONFDIR/ssl/cert.pem`, `PREFIX/share/certs/ca-root-nss.crt`, `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem`. `+tls-ca=FILE` names one file. Only the two names under `/usr/local` follow the options (FreeBSD ports: `/usr/local/etc/ssl/cert.pem` is the link of the ca_root_nss package); the others are the places of Linux distributions and stay. There is no `--with-ca-bundle`: the list is searched when `dag` runs, so a build needs no file name, and `SSL_CERT_FILE` or `+tls-ca=FILE` covers any other place. Windows and macOS have no entries of their own; they use the OpenSSL store.

### Libraries

| Library | Used by | Missing |
|---|---|---|
| OpenSSL (`libssl`, `libcrypto`), zlib | everything | error |
| libidn2 | `dag` | with `auto` the summary says so; `yes` is an error |
| SQLite3 (`sqlite3.h`, `libsqlite3`) | the `sqlite3` driver | with `auto` no such driver; named: error |
| libpq (`pkg-config libpq`, else `pg_config`) | the `postgresql` driver | with `auto` no such driver; named: error |

## WHAT MAKE DOES WITHOUT CONFIGURE

Without `config.mk` the `Makefile` finds the same things itself with shell commands at the top of the file (`NAME_PROBE != command`, then `NAME ?= $(NAME_PROBE)`), as it always did: on FreeBSD and Linux, with BSD make or GNU make 4, `make` alone behaves as before. `config.mk` sets the same names first, so the result of a probe is not used. GNU make 3.81, the `make` of macOS, has no `!=`: it needs `./configure` (its `config.mk` is how it gets the version, the Homebrew paths and the libpq flags).

The compile and link commands are the same with and without `config.mk` for the same options. `tests/run_configure_test.sh` checks that with `make -n` for `karidns dag karicheck karictl karidns-dbloader karidns-zone` (and that `--prefix`, `--sysconfdir` and `--libexecdir` add only their `-D`, and what the headers give with them), together with the options, the errors for a missing library, `--help` and `make distclean`.

A few things are not in `config.mk` on purpose:

- **`DBLOADER_DRV_*` and `DBSQ_*`**, the sources, flags and libraries of the drivers, which `make` derives from `DB_DRIVERS` each time, so that `make DB_DRIVERS=...` works after `./configure` (CI does that for the coverage build).
- **`HDRS`, `ALL_C`, the coverage tools**: file lists and developer targets.
- **The release number**: `VERSION_FILE` in `config.mk` is the file `VERSION` at the time of `./configure`. `make set-version V=x.y.z` (`docs/RELEASING.md`) writes the new number there too; if `VERSION` is edited by other means, run `./configure` again.

## INSTALLING

`make install` puts the programs, the sample configuration, the manual pages and the manuals where the options of `./configure` say (0.7). The `Makefile` holds the one list of what goes where (the block "Installation"); the FreeBSD packages are made from it (`make install DESTDIR=<stage>`, then the package lists exactly the staged files), and `tests/run_install_test.sh` compares a staged tree with `tests/install_manifest.txt`. An install target never builds: build first, as the user that owns the tree, then install (as root for a real installation, or into `DESTDIR` as anybody).

```sh
./configure                         # its summary shows the DB drivers it found ("DB drivers    sqlite3")
make                                # karidns, dag, karictl, karicheck, karidns-tapstat
make karidns-dbloader karidns-zone  # only when ./configure found DB drivers: make install installs these too then
make install                        # as root
make install DESTDIR=/tmp/stage     # staged: the files land under /tmp/stage/usr/local/...
make uninstall                      # removes what make install put there
```

`make` (`all`) does not build the two database programs: they link a database library, and `make` without `./configure` takes `DB_DRIVERS=sqlite3`, so `all` would fail on a host without SQLite3 (the dag builds of Linux, macOS and Windows among them). `make install` installs them whenever `DB_DRIVERS` is not empty (with `./configure`: the drivers it found). Each install target checks every file it is going to install before it copies the first one: when one is not built, nothing is installed and the message names what to build (`karidns-dbloader: make karidns-dbloader karidns-zone (or leave the database parts out: DB_DRIVERS=)`, `man/dag.1: make man`, ...). To install without the database parts, `make install DB_DRIVERS=` (or `./configure --with-db-drivers=none`). `tests/run_install_test.sh` runs this sequence in a copy of the sources (with a stub compiler).

| Target | Installs | Where (defaults) |
|---|---|---|
| `install-server` | `karidns`; `karictl`, `karicheck`, `karidns-tapstat`; the rc script; `karidns.conf.sample`, `karictl.conf.sample`, `zones/example.test.zone.sample` | `SBINDIR` (`PREFIX/sbin`); `BINDIR` (`PREFIX/bin`); `RCDIR` (`PREFIX/etc/rc.d`); `SYSCONFDIR/karidns` |
| `install-dag` | `dag` (what the dag packages of Linux, macOS and Homebrew ship) | `BINDIR` |
| `install-db` | `karidns-dbloader`; `karidns-zone`; the SQL files of the drivers in `DB_DRIVERS` | `LIBEXECDIR`; `BINDIR`; `DATADIR/db` (`PREFIX/share/karidns/db`) |
| `install-signer`, `install-webadmin` | the Node.js programs with `node_modules` (run `npm ci --omit=dev --ignore-scripts` in `signer/` or `webadmin/` first), the wrapper, the rc script, the sample configuration | `LIBEXECDIR/karidns-signer/`, `LIBEXECDIR/karidns-webadmin/`; `SBINDIR`; `RCDIR`; `SYSCONFDIR/karidns` |
| `install-man-X` | the manual pages of X (`server`: karidns(8), karidns.conf(5), karictl(8), karicheck(8), karidns-tapstat(1); `dag`: dag(1), dag-replay(1); `db`: karidns-dbloader(8), karidns-zone(8); `signer`, `webadmin`) | `MANDIR/manN` (`PREFIX/share/man`) |
| `install-docs-X` | the Markdown manuals of X | `DOCDIR` (`PREFIX/share/doc/karidns`) |
| `install` | `install-server`, `install-dag`, `install-man` and `install-docs` of both, and `install-db` with its pages and manuals when `DB_DRIVERS` is not empty | |

Every target has an `uninstall-...` twin; `make uninstall` is the twin of `make install`. Uninstalling removes the files the install target puts there, then the directories of KariDNS that are left empty: `SYSCONFDIR/karidns` (and `zones` in it), `DATADIR`, `DOCDIR`, `LIBEXECDIR/karidns-signer` and `LIBEXECDIR/karidns-webadmin` and what is below them (`INST_OWN` in the Makefile; one of these is taken only when its last component starts with `karidns`, so `DOCDIR=/usr/share/doc` is never removed). `PREFIX` itself, `bin`, `share/man/man8` and the like are never removed, also when their path holds `karidns` (`PREFIX=/opt/karidns-0.7`), and neither is a file it did not install (a `karidns.conf` you made stays, and so does its directory). The Node.js trees (`lib`, `ui`, `node_modules` of the signer and the WebAdmin) are removed as the installed directories are, whatever `signer/` or `webadmin/` holds now (a later `npm ci` with another lock leaves nothing stale); an installed tree that is or holds a symbolic link is refused before anything is removed.

- **Directories.** `PREFIX`, `SYSCONFDIR` and `LIBEXECDIR` come from `config.mk` (the defaults of `./configure` without it); `BINDIR`, `SBINDIR`, `DATADIR`, `DOCDIR`, `MANDIR` and `RCDIR` follow `PREFIX` and can be set on the command line like any of them (`make install MANDIR=/usr/share/man`). `DESTDIR` is put before every path. The rc scripts and the wrappers of the signer and the WebAdmin name `/usr/local` paths inside: they are for the FreeBSD layout, whatever `PREFIX` is.
- **Modes and owners.** Programs and scripts `BINMODE` (`0555`; the Debian package uses `0755`), samples `0644`, manual pages, manuals, SQL files and the files of the Node.js programs `0444` (directories `0755`). As root the files belong to root (uid and gid 0); as anybody else to that user: a package is built unprivileged and its list names root:wheel itself.
- **Configuration.** Only the samples are installed (`*.sample`); an existing configuration is never overwritten. Copy the sample and edit it (docs/distribution.md).
- **Manual pages.** `MANCOMPRESS=yes` installs `NAME.gz` (`gzip -9n`), `no` the page as it is; the default `auto` compresses on FreeBSD, as the ports do. The pages are generated from the Markdown manuals and committed under `man/` (`make man`, docs/RELEASING.md), so installing needs no tool beyond `gzip`.
- **BSD make and GNU make.** The install targets work with both (`tests/run_install_test.sh` runs each make it finds).

## EXAMPLES

```sh
./configure
./configure --march=none --with-db-drivers=none
./configure --sysconfdir=/etc --with-db-drivers="sqlite3 postgresql"
./configure --prefix=/usr --sysconfdir=/etc --libexecdir=/usr/libexec
./configure --with-openssl=/usr/local/opt/openssl@3 CFLAGS="-g -O1"
```

A package build (for example `packaging/freebsd/build_pkg.sh`) runs `./configure --march=none ...` instead of `MARCH_FLAGS=` on the `make` line.

## SEE ALSO

[RELEASING.md](RELEASING.md), [distribution.md](distribution.md), `tests/run_configure_test.sh`, `tests/run_install_test.sh`, the top of the `Makefile` and its block "Installation", `packaging/install.sh`.

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)
