# Building KariDNS: ./configure and make

## NAME

**building** — how `./configure` and `make` build the programs of KariDNS, what each option does, and what `make` alone still does.

## SYNOPSIS

```sh
./configure [--prefix=DIR] [--sysconfdir=DIR] [--with-db-drivers=auto|none|sqlite3|postgresql|"sqlite3 postgresql"]
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
| `--prefix=DIR` | Recorded as `PREFIX` in `config.mk` for the packaging scripts. The `Makefile` has no `install` target: the packages and Homebrew stage the files themselves. Default `/usr/local`. |
| `--sysconfdir=DIR` | The directory the tools look in for their configuration when they are not told where: `DIR/karidns/karidns.conf` (`karicheck`, `karidns-zone`), `DIR/karidns/karictl.conf` (`karictl`), the example in the help of `karidns-dbloader`. It is compiled in as `-DKARIDNS_SYSCONFDIR="DIR"` (`dns_utils.h`). Default `PREFIX/etc`; the sources default to `/usr/local/etc`, and only another directory adds a flag, so the default build is the build without `configure`. The rc scripts, the packages and the manuals keep the FreeBSD layout (`/usr/local/etc`). Only letters, digits and `_ . / + @ -` are allowed. |
| `--with-db-drivers=LIST` | The drivers of `karidns-dbloader` and `karidns-zone`: `auto` (the default: the drivers whose library is found), `none`, `sqlite3`, `postgresql`, or both (`"sqlite3 postgresql"` or `sqlite3,postgresql`). A driver that is named and not found is an error. `make DB_DRIVERS=...` on the command line still wins over `config.mk`. |
| `--with-idn2=auto\|yes\|no` | libidn2 for `dag` (internationalized names). `yes` is an error when it is not found; `auto` (the default) says so in the summary. `--with-idn2` is `yes`, `--without-idn2` is `no`. |
| `--with-openssl=DIR` | OpenSSL is in `DIR/include` and `DIR/lib`. The default is the system's, or the Homebrew one on macOS. The `Makefile` always searches `/usr/local` and the Homebrew directories first (`BREW_CFLAGS`, `BREW_LDFLAGS`): with a second copy of OpenSSL there, put your directory first in `CFLAGS` and `LDFLAGS`. |
| `--march=native\|none\|V` | `native` (the default): `-march=native`, the CPU of the build host. `none`: the baseline of the architecture, for a package that runs on other machines. `V`: `-march=V`. A default `native` that the compiler refuses becomes `none` with a line in the summary; a value that was asked for and is refused is an error. |
| `CC`, `CFLAGS`, `LDFLAGS` | From the environment or as arguments. They are saved in `config.mk`; the flags of the `Makefile` are added to them. |

### Libraries

| Library | Used by | Missing |
|---|---|---|
| OpenSSL (`libssl`, `libcrypto`), zlib | everything | error |
| libidn2 | `dag` | with `auto` the summary says so; `yes` is an error |
| SQLite3 (`sqlite3.h`, `libsqlite3`) | the `sqlite3` driver | with `auto` no such driver; named: error |
| libpq (`pkg-config libpq`, else `pg_config`) | the `postgresql` driver | with `auto` no such driver; named: error |

## WHAT MAKE DOES WITHOUT CONFIGURE

Without `config.mk` the `Makefile` finds the same things itself with shell commands at the top of the file (`NAME_PROBE != command`, then `NAME ?= $(NAME_PROBE)`), as it always did: on FreeBSD and Linux, with BSD make or GNU make 4, `make` alone behaves as before. `config.mk` sets the same names first, so the result of a probe is not used. GNU make 3.81, the `make` of macOS, has no `!=`: it needs `./configure` (its `config.mk` is how it gets the version, the Homebrew paths and the libpq flags).

The compile and link commands are the same with and without `config.mk` for the same options. `tests/run_configure_test.sh` checks that with `make -n` for `karidns dag karicheck karictl karidns-dbloader karidns-zone` (and that a `--sysconfdir` adds only its `-D`), together with the options, the errors for a missing library, `--help` and `make distclean`.

A few things are not in `config.mk` on purpose:

- **`DBLOADER_DRV_*` and `DBSQ_*`**, the sources, flags and libraries of the drivers, which `make` derives from `DB_DRIVERS` each time, so that `make DB_DRIVERS=...` works after `./configure` (CI does that for the coverage build).
- **`HDRS`, `ALL_C`, the coverage tools**: file lists and developer targets.
- **The release number**: `VERSION_FILE` in `config.mk` is the file `VERSION` at the time of `./configure`. `make set-version V=x.y.z` (`docs/RELEASING.md`) writes the new number there too; if `VERSION` is edited by other means, run `./configure` again.

## EXAMPLES

```sh
./configure
./configure --march=none --with-db-drivers=none
./configure --sysconfdir=/etc --with-db-drivers="sqlite3 postgresql"
./configure --with-openssl=/usr/local/opt/openssl@3 CFLAGS="-g -O1"
```

A package build (for example `packaging/freebsd/build_pkg.sh`) runs `./configure --march=none ...` instead of `MARCH_FLAGS=` on the `make` line.

## SEE ALSO

[RELEASING.md](RELEASING.md), [distribution.md](distribution.md), `tests/run_configure_test.sh`, the top of the `Makefile`.

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)
