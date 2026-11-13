# KariDNS release number and release procedure

## NAME

**RELEASING** — where the release number of KariDNS lives, how to change it, and how a release is tagged and built.

## THE RELEASE NUMBER

The file **`VERSION`** at the top of the source tree is the one source of the release number: one line, three numbers, `x.y.z` (for example `0.6.0`). Every program of the tree reports it:

| Component | How it gets the number |
|---|---|
| `karidns`, `dag`, `karicheck`, `karictl`, `karidns-dbloader`, `karidns-zone` (C) | The `Makefile` reads `VERSION` and compiles it in (`-DKARIDNS_VERSION`); after `./configure` it reads the copy in `config.mk` (`VERSION_FILE`), which `make set-version` keeps in step. Every object depends on `VERSION`, so a new number rebuilds them. `make VERSION=x.y.z` overrides it for one build. Built without the `Makefile`, they say `dev`. |
| `karidns-signer`, `karidns-webadmin` (Node.js) | They read the `version` of their own `package.json` when they start (`node/lib/version.js`); the packages install it next to the program. |
| The web interface (`webadmin/ui/`) | `GUI_VERSION` in `webadmin/ui/js/version.js`: the files are served to a browser as they are, so they cannot read anything. The page compares it with the service's number and asks for a reload when they differ. |
| The packages (`packaging/*/build_*.sh`) | The first argument, or the file `VERSION` when it is left out or empty (`packaging/version.sh`). A different number is allowed for a test build and is warned about. |

`package.json`, `package-lock.json` (of `signer/` and `webadmin/`) and `webadmin/ui/js/version.js` keep **copies** of the number, because npm and the browser need them there. Do not edit them by hand: `make set-version` writes all of them. `tests/run_version_test.sh` (in `tests/run_all_suite.sh`, and in the release workflow before anything is built) fails when a copy differs from `VERSION`, when some other source holds a number of its own, or when a built program reports another number.

## CHANGING THE NUMBER

From the top of the source tree:

```sh
make set-version V=0.6.2          # or: sh tools/set_version.sh 0.6.2
sh tests/run_version_test.sh
git diff --stat                   # VERSION, signer/ and webadmin/ package.json and package-lock.json, webadmin/ui/js/version.js
```

`set-version` takes three numbers only (no `v`, no suffix such as `-rc1`). It changes the package's own version in the lock files and leaves the versions of the dependencies alone.

A `config.mk` written by `./configure` (`docs/building.md`) holds the number it read; `tools/set_version.sh` updates that line when the file exists, so the next `make` builds the new number. Run `./configure` again if `VERSION` was changed any other way.

## MANUAL PAGES

The manual pages (`man/*.1`, `man/*.5`, `man/*.8`) are generated from the Markdown manuals in `docs/` and committed, so that building and packaging need no converter. **Run `make man` after changing a manual** and commit the pages with it:

```sh
make man                          # man/generate.sh: perl man/md2man.pl for each page; needs perl
git status man/                   # the pages whose text changed (their date becomes today's)
sh tests/run_md2man_test.sh       # fresh pages, mandoc -T lint, the converter's fixtures
```

`man/generate.sh` names the pages and the options of each (`karidns.conf(5)` is the configuration part of `docs/karidns.md`, which `karidns(8)` then leaves out); `man/md2man.pl` understands the Markdown the manuals use (its header lists it). A page keeps its date while its text is unchanged. CI fails when a committed page is not what `make man` makes of the manual, or when `mandoc -T lint` finds anything at WARNING or worse. Check a page in a terminal with `mandoc -T utf8 -O width=80 man/karictl.8 | less`.

## THE PACKAGES

| Platform | Script | Built from |
|---|---|---|
| FreeBSD | `packaging/freebsd/build_pkg.sh [--db none\|sqlite3\|postgresql\|both]`, `build_signer_pkg.sh`, `build_webadmin_pkg.sh` | `./configure --march=none`, `make`, then `make install-... DESTDIR=<stage>`; the package lists every staged file with its mode and root:wheel (`packaging/freebsd/pkg_files.sh`) |
| Linux | `packaging/linux/build_linux_pkgs.sh` (tar.gz, deb, rpm with `packaging/linux/dag.spec`) | `make dag`; the deb and the rpm with `make install-dag install-man-dag DESTDIR=...` |
| macOS | `packaging/macos/build_dmg.sh` (dmg, tar.gz) | `make dag`; `dag`, `man/dag.1` and the manuals copied |
| Homebrew | `packaging/homebrew/update_formula.sh <tag>` (writes `Formula/dag.rb` from `dag.rb.template`) | the tag's source tarball; the formula runs `./configure` and `make dag` |
| Windows | `packaging/windows/build_windows_zip.sh` | `make dag` (MinGW) |

What goes where is the `Makefile`'s list (docs/building.md "INSTALLING"); a file that a package should hold is added there, and `tests/install_manifest.txt` with it. The release workflow builds every package on its platform and checks it:

- **FreeBSD** (14 and 15, in a VM): the plain package is installed with `pkg add` (the libraries are the base system's OpenSSL, no AVX-512, the files are there, `dag` answers); the three database packages one after the other (the loader and `karidns-zone` report the drivers of the package); the signer and the WebAdmin on top of `karidns-sqlite3` (the user, the wrapper, `--version`).
- **Linux**: the rpm in a Rocky Linux container, the deb and the tarball on Ubuntu, each installed and run.
- **macOS**: the tarball and the dmg; **Homebrew**: the formula is written for the tag.

Before a release, on the FreeBSD build host (an ordinary user; nothing is installed):

```sh
sh tests/run_install_test.sh      # make install against tests/install_manifest.txt (BSD make, GNU make), uninstall, other
                                  # directories, and that the packages list exactly what make install stages
sh tests/run_md2man_test.sh
sh tests/run_signer_pkg_test.sh; sh tests/run_webadmin_pkg_test.sh
```

To look at a package without installing it: `pkg info -F <file>`, `pkg info -l -F <file>` (the files), `pkg info -R -F <file>` (the whole manifest: scripts, conflicts, provides, requires), `tar -tvf <file>` (modes and owners).

## MAKING A RELEASE

1. On a branch: `make set-version V=x.y.z`, update the documents that name the release, `make man` (and commit the pages that changed), run the tests (the full suite on the FreeBSD build host), open a pull request and merge it.
2. Tag the merge commit on `main` with **`v` + the number** and push the tag:

   ```sh
   git tag vx.y.z
   git push origin vx.y.z
   ```

3. The release workflow (`.github/workflows/release.yml`) starts with the job "Check the tag against the file VERSION": it runs `tests/run_version_test.sh` and **refuses a tag that is not `v` + the number of `VERSION`** (the fix is `make set-version`, a new commit, and the tag on that commit). Then it builds and tests the packages of every platform with the number without its `v` (each build runs `./configure --march=none`: the baseline instruction set, not the CPU of the build host), and publishes a draft release with the files and `SHA256SUMS.txt`.
4. Check the draft release and publish it.

A manual run of the release workflow (`workflow_dispatch`, with a version typed in) is a test build: a number other than `VERSION` only gives a warning.

## SEE ALSO

[distribution.md](distribution.md) (the packages and how to install them), [building.md](building.md) (`make install`), `tests/run_version_test.sh`, `tools/set_version.sh`, `packaging/version.sh`, `man/generate.sh`, `tests/run_install_test.sh`, `tests/run_md2man_test.sh`.

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)
