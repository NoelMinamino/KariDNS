#!/bin/sh
# apt-install.sh PACKAGE...: apt-get install on a GitHub Ubuntu runner that survives a package mirror it cannot reach.
#
# The runners read the mirror list /etc/apt/apt-mirrors.txt (azure.archive.ubuntu.com first).  When that name cannot be
# resolved, apt-get update only warns ("Failed to fetch"), and apt-get install then fails for lack of package lists.  So:
# update up to three times; if some lists still could not be fetched, use archive.ubuntu.com and update again.
set -eu

# The packages come from the Ubuntu archive only.  The runner image also lists the repositories of its own tools (packages.microsoft.com, ...): one
# that answers 403 or is no longer signed makes every apt-get update fail, and the job with it (CI main run 45926251540, 2026-11-27: exit 100 on
# packages.microsoft.com).  A source file that names neither the Ubuntu archive nor the runner's mirror list (ubuntu.sources: mirror+file:
# /etc/apt/apt-mirrors.txt) is left out for this job.
for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] || continue
    grep -q -E 'ubuntu\.com|apt-mirrors\.txt' "$f" && continue
    echo "apt-install.sh: leaving out $f (not the Ubuntu archive)"
    sudo mv "$f" "$f.apt-install-off"
done

fetched=no
for try in 1 2 3; do
    out=$(sudo apt-get update -o Acquire::Retries=3 2>&1) || true
    printf '%s\n' "$out"
    if ! printf '%s\n' "$out" | grep -q -E '^(W|E): (Failed to fetch|Some index files failed)'; then
        fetched=yes
        break
    fi
    echo "apt-install.sh: some package lists could not be fetched (try $try of 3)"
    [ "$try" -lt 3 ] && sleep 15
done

if [ "$fetched" = no ]; then
    echo "apt-install.sh: using http://archive.ubuntu.com/ubuntu/ instead of the runner's mirror list"
    if [ -f /etc/apt/apt-mirrors.txt ]; then
        echo "http://archive.ubuntu.com/ubuntu/" | sudo tee /etc/apt/apt-mirrors.txt >/dev/null
    fi
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
        [ -f "$f" ] && sudo sed -i 's#http://azure\.archive\.ubuntu\.com/#http://archive.ubuntu.com/#g' "$f"
    done
    sudo apt-get update -o Acquire::Retries=3
fi

sudo apt-get install -y -o Acquire::Retries=3 "$@"
