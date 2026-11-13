# pkg_files.sh - sourced by the FreeBSD package scripts (build_pkg.sh, build_signer_pkg.sh, build_webadmin_pkg.sh).
#
#   pkg_stage STAGE TARGET...   make TARGET... with DESTDIR=STAGE and the paths of the packages (PREFIX /usr/local; the manual pages gzip'ed)
#   pkg_files STAGE             the `files` of +MANIFEST for everything under STAGE
#
# A package lists exactly what `make install` staged (the Makefile, "Installation", is the one list of what goes where): every regular file of
# the stage, sorted, with the mode it was installed with (packaging/install.sh sets it) and the owner root:wheel (a package is built by an
# ordinary user, so the owner comes from the list, not from the stage).  A name outside [A-Za-z0-9_./+@-], a symbolic link or anything else
# that is neither a regular file nor a directory is an error.

pkg_stage() {
    _st=$1
    shift
    make DESTDIR="$_st" PREFIX=/usr/local SYSCONFDIR=/usr/local/etc LIBEXECDIR=/usr/local/libexec MANCOMPRESS=yes "$@"
}

pkg_files() {
    _st=$1
    _odd=$(cd "$_st" && find . ! -type f ! -type d)
    if [ -n "$_odd" ]; then
        echo "ERROR: the stage holds what is neither a regular file nor a directory: $_odd" >&2
        return 1
    fi
    _list=$(cd "$_st" && find . -type f | sed 's|^\.||' | LC_ALL=C sort)
    if [ -z "$_list" ]; then
        echo "ERROR: nothing was staged in $_st" >&2
        return 1
    fi
    if printf '%s\n' "$_list" | grep -q '[^A-Za-z0-9_./+@-]'; then
        echo "ERROR: a staged file name holds a character the package list does not take: $(printf '%s\n' "$_list" | grep '[^A-Za-z0-9_./+@-]' | head -1)" >&2
        return 1
    fi
    _sep=""
    for _f in $_list; do
        _m=$(stat -f %Lp "$_st$_f") || return 1
        printf '%s    "%s": { uname: "root", gname: "wheel", perm: "%04d" }' "$_sep" "$_f" "$_m"
        _sep=",
"
    done
    echo
}
