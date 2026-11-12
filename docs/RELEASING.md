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
make set-version V=0.6.1          # or: sh tools/set_version.sh 0.6.1
sh tests/run_version_test.sh
git diff --stat                   # VERSION, signer/ and webadmin/ package.json and package-lock.json, webadmin/ui/js/version.js
```

`set-version` takes three numbers only (no `v`, no suffix such as `-rc1`). It changes the package's own version in the lock files and leaves the versions of the dependencies alone.

A `config.mk` written by `./configure` (`docs/building.md`) holds the number it read; `tools/set_version.sh` updates that line when the file exists, so the next `make` builds the new number. Run `./configure` again if `VERSION` was changed any other way.
## MAKING A RELEASE

1. On a branch: `make set-version V=x.y.z`, update the documents that name the release, run the tests (the full suite on the FreeBSD build host), open a pull request and merge it.
2. Tag the merge commit on `main` with **`v` + the number** and push the tag:

   ```sh
   git tag vx.y.z
   git push origin vx.y.z
   ```

3. The release workflow (`.github/workflows/release.yml`) starts with the job "Check the tag against the file VERSION": it runs `tests/run_version_test.sh` and **refuses a tag that is not `v` + the number of `VERSION`** (the fix is `make set-version`, a new commit, and the tag on that commit). Then it builds and tests the packages of every platform with the number without its `v` (each build runs `./configure --march=none`: the baseline instruction set, not the CPU of the build host), and publishes a draft release with the files and `SHA256SUMS.txt`.
4. Check the draft release and publish it.

A manual run of the release workflow (`workflow_dispatch`, with a version typed in) is a test build: a number other than `VERSION` only gives a warning.

## SEE ALSO

[distribution.md](distribution.md) (the packages and how to install them), `tests/run_version_test.sh`, `tools/set_version.sh`, `packaging/version.sh`.

---

## AUTHORS

Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)
