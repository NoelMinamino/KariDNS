# version.sh - the release number of a package, sourced by the packaging scripts (run from the top of the source tree):
#
#     VERSION_ARG="${1:-}"; . packaging/version.sh
#
# VERSION is VERSION_ARG without a leading "v" (a tag such as v0.6.0), or the file VERSION when no number is given (docs/RELEASING.md).
# A number other than the file's is allowed (test runs of the release workflow) but warned about: karidns-signer and karidns-webadmin
# report the number of their package.json, which `make set-version` keeps equal to the file.

VERSION_FILE=$( { tr -d ' \r\n' < VERSION; } 2>/dev/null || true)
VERSION="${VERSION_ARG:-$VERSION_FILE}"
VERSION="${VERSION#v}"
if [ -z "$VERSION" ]; then
    echo "packaging: no version given and no file VERSION (run the script from the top of the source tree)" >&2
    exit 2
fi
if [ "$VERSION" != "$VERSION_FILE" ]; then
    echo "WARNING: packaging version ${VERSION}, but the file VERSION says ${VERSION_FILE:-nothing} (make set-version V=${VERSION} before a release)" >&2
fi
