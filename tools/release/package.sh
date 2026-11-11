#!/usr/bin/env bash
# tools/release/package.sh: build, check and pack Deepwave release archives from a clean clone
# of the public repository. It publishes nothing: it only writes files under OUTDIR.
#
#   tools/release/package.sh --version 0.1.0 --sui-release 1.83.1 --commit <sha> OUTDIR
#
# Required:
#   --version X.Y.Z        Deepwave's own version; must equal `version` in src/node/ops.zig
#   --sui-release A.B.C    the sui-node release this build matches (named in README.md)
#   --commit SHA           the public commit to build, 12 to 40 hex characters; HEAD must be it
# Optional:
#   --optimize MODE        safe (default, the documented production build) or fast
#   --cpu MODEL            Linux x86_64 CPU baseline (default x86_64_v2)
#   --extra-cpu MODEL      one more Linux x86_64 archive for this baseline, named with its
#                          suffix, for example --extra-cpu x86_64_v3 adds ...-ubuntu-x86_64-v3.tgz
#                          (repeatable)
#   --platforms "LIST"     any of: ubuntu-x86_64 ubuntu-aarch64 macos-arm64
#                          (default: both Linux platforms, plus macos-arm64 on a macOS host)
#   --network NAME         network in the archive name (default mainnet)
#   --repo-url URL         the public repository (default https://github.com/tidedata/deepwave)
#   --src DIR              the checkout to build (default: the checkout holding the current directory)
#   --repro                build ubuntu-x86_64 a second time from empty caches and compare
#   --jobs N               compile jobs (default 4)
#   --forbid-file FILE     extra strings that must not appear in any binary or archive, one per line
#   --allow-file FILE      strings a leak-scan hit may be part of (public text in the source), one per line
#   --offline              skip the check that the commit is on the public repository's default branch
# Environment:
#   RELEASE_BUILD_WRAP     command put in front of every compiler run (a load limiter, for example)
#   RELEASE_TOOLCHAIN_CACHE  directory holding (or receiving) the pinned Zig toolchain
#                          (default OUTDIR/work/toolchain); build caches are always fresh
#
# Output in OUTDIR:
#   deepwave-v<version>-<network>-v<sui-release>-<platform>.tgz   one per platform
#   SHA256SUMS       sha256 of every archive
#   MANIFEST.txt     sha256 of every file inside every archive and of each uncompressed tar stream
#   CHECKS.txt       the output of every check below
#   work/            toolchain, caches, logs and unpacked stages (safe to delete)
#
# What is pinned so that two machines produce the same bytes from the same commit: the Zig
# toolchain (tools/bootstrap.sh checks its sha256), an explicit target, CPU and optimize mode, an
# explicit -Dgit-sha, an emptied environment (LC_ALL=C, TZ=UTC, HOME inside OUTDIR), empty build
# caches, umask 022, debug information removed (it holds source paths), tar written by this script
# in ustar format with sorted names, owner 0/root, the commit time as mtime, and a gzip header with
# no name and no time. Not pinned: the gzip compressed bytes depend on the host's zlib, so compare
# machines with MANIFEST.txt (binaries and tar streams), and the macOS archive needs Apple's strip
# and codesign, so it is only built on macOS.
set -euo pipefail

die() { echo "package.sh: $*" >&2; exit 1; }
say() { echo "== $*"; }

VERSION= SUI_RELEASE= COMMIT= OPT=safe CPU=x86_64_v2 EXTRA_CPUS= PLATFORMS= NETWORK=mainnet
REPO_URL=https://github.com/tidedata/deepwave SRC= REPRO=0 JOBS=4 FORBID_FILE= ALLOW_FILE= OFFLINE=0 OUT=
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION=${2:?}; shift 2 ;;
    --sui-release) SUI_RELEASE=${2:?}; shift 2 ;;
    --commit) COMMIT=${2:?}; shift 2 ;;
    --optimize) OPT=${2:?}; shift 2 ;;
    --cpu) CPU=${2:?}; shift 2 ;;
    --extra-cpu) EXTRA_CPUS="$EXTRA_CPUS ${2:?}"; shift 2 ;;
    --platforms) PLATFORMS=${2:?}; shift 2 ;;
    --network) NETWORK=${2:?}; shift 2 ;;
    --repo-url) REPO_URL=${2:?}; shift 2 ;;
    --src) SRC=${2:?}; shift 2 ;;
    --repro) REPRO=1; shift ;;
    --jobs) JOBS=${2:?}; shift 2 ;;
    --forbid-file) FORBID_FILE=${2:?}; shift 2 ;;
    --allow-file) ALLOW_FILE=${2:?}; shift 2 ;;
    --offline) OFFLINE=1; shift ;;
    -h|--help) sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) [ -z "$OUT" ] || die "one output directory, got '$OUT' and '$1'"; OUT=$1; shift ;;
  esac
done
[ -n "$OUT" ] || die "usage: package.sh --version X.Y.Z --sui-release A.B.C --commit SHA [options] OUTDIR"
[ -n "$VERSION" ] && [ -n "$SUI_RELEASE" ] && [ -n "$COMMIT" ] || die "--version, --sui-release and --commit are required"
echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "--version must be X.Y.Z, got '$VERSION'"
echo "$SUI_RELEASE" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "--sui-release must be A.B.C, got '$SUI_RELEASE'"
echo "$COMMIT" | grep -Eq '^[0-9a-f]{12,40}$' || die "--commit must be 12 to 40 lowercase hex characters"
echo "$JOBS" | grep -Eq '^[1-9][0-9]*$' || die "--jobs must be a number"
# The optimize mode is always passed to the compiler and never left to its default (Debug).
case "$OPT" in
  safe|ReleaseSafe) OPT=safe ;;
  fast|ReleaseFast) OPT=fast ;;
  *) die "--optimize must be safe or fast, got '$OPT' (Debug and small builds are not released)" ;;
esac

umask 022
export LC_ALL=C LANG=C TZ=UTC
HOST_OS=$(uname -s) HOST_ARCH=$(uname -m)
[ -n "$PLATFORMS" ] || { PLATFORMS="ubuntu-x86_64 ubuntu-aarch64"; [ "$HOST_OS" = Darwin ] && PLATFORMS="$PLATFORMS macos-arm64"; }
for t in git python3 tar gzip; do command -v "$t" >/dev/null || die "$t is required"; done
if command -v sha256sum >/dev/null; then sha256() { sha256sum "$1" | cut -d' ' -f1; }
else sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi

# ---- 1. the checkout must be a clean clone of the public repository at the commit ----------
[ -n "$SRC" ] || SRC=$(git rev-parse --show-toplevel 2>/dev/null) || die "run inside the checkout or pass --src"
SRC=$(cd "$SRC" && pwd -P)
[ -f "$SRC/build.zig" ] && [ -f "$SRC/tools/env.sh" ] || die "$SRC is not a Deepwave checkout"
HEAD_SHA=$(git -C "$SRC" rev-parse HEAD)
case "$HEAD_SHA" in "$COMMIT"*) ;; *) die "HEAD is $HEAD_SHA, not --commit $COMMIT" ;; esac
SHA12=$(echo "$HEAD_SHA" | cut -c1-12)
norm_url() { echo "$1" | sed -e 's#^git@github\.com:#https://github.com/#' -e 's#^ssh://git@github\.com/#https://github.com/#' -e 's#\.git$##' -e 's#/$##'; }
ORIGIN=$(git -C "$SRC" remote get-url origin 2>/dev/null) || die "the checkout has no origin remote"
[ "$(norm_url "$ORIGIN")" = "$(norm_url "$REPO_URL")" ] || die "origin is $ORIGIN, expected $REPO_URL"
DIRTY=$(git -C "$SRC" status --porcelain --ignored)
[ -z "$DIRTY" ] || die "the checkout is not clean (changed, untracked or ignored files):
$DIRTY"
if [ "$OFFLINE" = 0 ]; then
  git -C "$SRC" fetch --quiet "$(norm_url "$REPO_URL")" || die "cannot fetch $REPO_URL (pass --offline to skip this check)"
  git -C "$SRC" merge-base --is-ancestor "$HEAD_SHA" FETCH_HEAD || die "$HEAD_SHA is not on the default branch of $REPO_URL"
fi
grep -q "^pub const version = \"$VERSION\";" "$SRC/src/node/ops.zig" || die "src/node/ops.zig does not declare version $VERSION"
grep -q "sui-node $SUI_RELEASE" "$SRC/README.md" || die "README.md does not name sui-node $SUI_RELEASE"
COMMIT_TIME=$(git -C "$SRC" log -1 --format=%ct "$HEAD_SHA")

mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd -P)
case "$OUT/" in "$SRC"/*) die "the output directory must be outside the checkout" ;; esac
WORK=$OUT/work
rm -rf "$WORK/build" "$WORK/stage" "$WORK/home"; mkdir -p "$WORK/build" "$WORK/stage" "$WORK/home" "$WORK/logs"
BASE=deepwave-v$VERSION-$NETWORK-v$SUI_RELEASE
CHECKS=$OUT/CHECKS.txt; MANIFEST=$OUT/MANIFEST.txt
: > "$CHECKS"; : > "$MANIFEST"; rm -f "$OUT/SHA256SUMS" "$OUT/$BASE"-*.tgz
check() { echo "$*" | tee -a "$CHECKS"; }

# ---- 2. helper (ELF facts, leak scan, the tar and gzip writer) ------------------------------
HELPER=$WORK/relpack.py
cat > "$HELPER" <<'PY'
import gzip, hashlib, io, re, struct, sys, tarfile

def elf(path):
    d = open(path, 'rb').read()
    if d[:4] != b'\x7fELF' or d[4] != 2 or d[5] != 1:
        sys.exit(f'{path}: not a 64-bit little-endian ELF file')
    e_type, e_machine = struct.unpack_from('<HH', d, 16)
    e_phoff, e_shoff = struct.unpack_from('<QQ', d, 32)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from('<HHHHH', d, 54)
    interp = ''
    for i in range(phnum):
        p_type, _, p_off, _, _, p_filesz = struct.unpack_from('<IIQQQQ', d, e_phoff + i * phentsize)
        if p_type == 3:
            interp = d[p_off:p_off + p_filesz].rstrip(b'\0').decode()
    secs = [struct.unpack_from('<IIQQQQIIQQ', d, e_shoff + i * shentsize) for i in range(shnum)]
    def cstr(tab, off):
        base = secs[tab][4] + off
        return d[base:d.index(b'\0', base)].decode()
    names = [cstr(shstrndx, s[0]) for s in secs] if secs else []
    needed, versions = [], []
    for s in secs:
        if s[1] == 6:  # SHT_DYNAMIC
            for o in range(s[4], s[4] + s[5], 16):
                tag, val = struct.unpack_from('<qQ', d, o)
                if tag == 1:
                    needed.append(cstr(s[6], val))
        if s[1] == 0x6ffffffe:  # SHT_GNU_verneed
            o = s[4]
            for _ in range(s[7]):
                _, cnt, _, aux, nxt = struct.unpack_from('<HHIII', d, o)
                a = o + aux
                for _ in range(cnt):
                    _, _, _, name, anext = struct.unpack_from('<IHHII', d, a)
                    versions.append(cstr(s[6], name))
                    a += anext
                o += nxt
    glibc = sorted({tuple(int(x) for x in v[6:].split('.')) for v in versions if re.fullmatch(r'GLIBC_[0-9.]+', v)})
    print('type=' + {2: 'EXEC', 3: 'DYN'}.get(e_type, str(e_type)))
    print('machine=' + {62: 'x86_64', 183: 'aarch64'}.get(e_machine, str(e_machine)))
    print('interp=' + interp)
    print('needed=' + ','.join(needed))
    print('glibc_max=' + ('.'.join(str(x) for x in glibc[-1]) if glibc else 'none'))
    print('debug_sections=' + (','.join(n for n in names if n.startswith(('.debug', '.zdebug'))) or 'none'))
    print('symtab=' + ('yes' if '.symtab' in names else 'no'))

def strip(src, dst):
    """Drops every section that is not loaded (debug info, symbol table, comment) and writes a
    new section table. The loaded part of the file, every byte the kernel and the dynamic loader
    read, is copied unchanged, so addresses in a crash report match an unstripped build of the
    same commit."""
    d = open(src, 'rb').read()
    if d[:4] != b'\x7fELF' or d[4] != 2 or d[5] != 1:
        sys.exit(f'{src}: not a 64-bit little-endian ELF file')
    e_phoff, e_shoff = struct.unpack_from('<QQ', d, 32)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from('<HHHHH', d, 54)
    cut = e_phoff + phnum * phentsize
    for i in range(phnum):
        p_type, _, p_off, _, _, p_filesz = struct.unpack_from('<IIQQQQ', d, e_phoff + i * phentsize)
        if p_filesz:
            cut = max(cut, p_off + p_filesz)
    secs = [list(struct.unpack_from('<IIQQQQIIQQ', d, e_shoff + i * shentsize)) for i in range(shnum)]
    str_off = secs[shstrndx][4]
    keep, remap = [], {}
    for i, s in enumerate(secs):
        alloc = s[2] & 2
        if i == 0 or alloc:
            if alloc and s[1] != 8 and s[4] + s[5] > cut:
                sys.exit(f'{src}: loaded section {i} lies outside the loaded segments')
            remap[i] = len(keep)
            keep.append(s)
        elif s[4] < cut:
            sys.exit(f'{src}: section {i} to drop lies inside the loaded part of the file')
    names = bytearray(b'\0')
    for s in keep[1:]:
        name = d[str_off + s[0]:d.index(b'\0', str_off + s[0])]
        s[0] = len(names)
        names += name + b'\0'
        if s[6]:
            s[6] = remap[s[6]]
        if s[1] in (4, 9) or s[2] & 0x40:  # REL, RELA or SHF_INFO_LINK: sh_info is a section index
            s[7] = remap[s[7]]
    shstr_name = len(names)
    names += b'.shstrtab\0'
    out = bytearray(d[:cut])
    shstr_at = len(out)
    out += names
    out += b'\0' * (-len(out) % 8)
    shoff = len(out)
    keep.append([shstr_name, 3, 0, 0, shstr_at, len(names), 0, 0, 1, 0])
    for s in keep:
        out += struct.pack('<IIQQQQIIQQ', *s)
    struct.pack_into('<Q', out, 40, shoff)
    struct.pack_into('<HH', out, 60, len(keep), len(keep) - 1)
    open(dst, 'wb').write(out)

EMAIL = re.compile(rb'[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,10}(?![A-Za-z0-9])')

def scan(patterns_file, allow_file, paths):
    pats = [l.rstrip(b'\r\n') for l in open(patterns_file, 'rb') if l.strip()]
    allow = [l.rstrip(b'\r\n') for l in open(allow_file, 'rb') if l.strip()] if allow_file != '-' else []
    hits = 0
    def context(d, i, n):
        a, b = i, i + n
        while a > 0 and i - a < 80 and 32 <= d[a - 1] < 127: a -= 1
        while b < len(d) and b - i < 160 and 32 <= d[b] < 127: b += 1
        return d[a:b]
    for path in paths:
        d = open(path, 'rb').read()
        found = []
        for p in pats:
            i = d.find(p)
            while i != -1:
                found.append((i, p, context(d, i, len(p))))
                i = d.find(p, i + 1)
        for m in EMAIL.finditer(d):
            found.append((m.start(), b'<email>', context(d, m.start(), len(m.group()))))
        n = 0
        for i, p, ctx in sorted(found):
            if any(a in ctx for a in allow):
                continue
            n += 1
            if n <= 20:
                print(f'HIT {path} offset {i} pattern {p.decode("latin1")}: {ctx.decode("latin1")}')
        print(f'{path}: {n} hits ({len(d)} bytes, {len(pats)} strings and the email pattern)')
        hits += n
    sys.exit(1 if hits else 0)

def pack(out, mtime, items):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as t:
        for name, path, mode in sorted(items):
            data = open(path, 'rb').read()
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime, ti.type = len(data), mode, mtime, tarfile.REGTYPE
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = 'root'
            t.addfile(ti, io.BytesIO(data))
    raw = raw.getvalue()
    with open(out, 'wb') as f:
        with gzip.GzipFile(filename='', mode='wb', compresslevel=9, fileobj=f, mtime=0) as g:
            g.write(raw)
    print(hashlib.sha256(raw).hexdigest())

def listing(path):
    bad = 0
    head = open(path, 'rb').read(10)
    flags, gz_mtime = head[3], struct.unpack_from('<I', head, 4)[0]
    print(f'gzip header: name field {"present" if flags & 8 else "absent"}, mtime {gz_mtime}')
    bad += (flags & 8 != 0) + (gz_mtime != 0)
    with tarfile.open(path, 'r:gz') as t:
        for m in t.getmembers():
            print(f'{m.mode:04o} {m.uid}/{m.gid} {m.uname}/{m.gname} mtime={m.mtime} {m.size:>10} {m.name}')
            bad += (m.uid != 0) + (m.gid != 0) + (m.uname != 'root') + (m.gname != 'root')
            bad += ('/' in m.name) + (not m.isfile())
        if len({m.mtime for m in t.getmembers()}) != 1: bad += 1
    sys.exit(1 if bad else 0)

cmd = sys.argv[1]
if cmd == 'elf': elf(sys.argv[2])
elif cmd == 'strip': strip(sys.argv[2], sys.argv[3])
elif cmd == 'scan': scan(sys.argv[2], sys.argv[3], sys.argv[4:])
elif cmd == 'pack': pack(sys.argv[2], int(sys.argv[3]), [(a.split('=')[0], a.split('=')[1], int(a.split('=')[2], 8)) for a in sys.argv[4:]])
elif cmd == 'list': listing(sys.argv[2])
else: sys.exit('relpack.py: elf|strip|scan|pack|list')
PY
helper() { python3 -I "$HELPER" "$@"; }

# ---- 3. toolchain: the repository's pinned Zig, through its own bootstrap ---------------------
TOOLCACHE=${RELEASE_TOOLCHAIN_CACHE:-$WORK/toolchain}
mkdir -p "$TOOLCACHE"; TOOLCACHE=$(cd "$TOOLCACHE" && pwd -P)
# env.sh names the toolchain version and, on macOS, the SDK the linker can read.
ZIG=$(cd "$SRC" && ZUI_CACHE=$TOOLCACHE bash -c '. tools/env.sh && [ -x "$ZUI_ZIG" ] || tools/bootstrap.sh >&2; echo "$ZUI_ZIG"')
[ -x "$ZIG" ] || die "no toolchain at $ZIG"
ZIG_DIR=$(dirname "$ZIG")
ZIG_VERSION=$("$ZIG" version)

# ---- 4. leak patterns: where this build ran and who ran it ------------------------------------
PATTERNS=$WORK/forbidden.txt
{
  printf '%s\n' '/Users/' '/home/' '/private/' '/var/folders/' '/root/' 'zig-global' 'zig-local' '/lib/std/'
  printf '%s\n' "$SRC" "$OUT" "$TOOLCACHE" "${HOME:-/nonexistent-home}"
  u=$(id -un); printf '/%s/\n%s@\n' "$u" "$u"
  h=$(hostname 2>/dev/null || true); [ -z "$h" ] || printf '%s\n%s\n' "$h" "${h%%.*}"
  [ -z "$FORBID_FILE" ] || cat "$FORBID_FILE"
} | awk 'length($0) >= 3 && !seen[$0]++' > "$PATTERNS"

# ---- 5. build ---------------------------------------------------------------------------------
# build NAME TARGET CPU: an empty-cache build of the node and the tool into $WORK/build/NAME/bin.
build() {
  local name=$1 target=$2 cpu=$3 dir=$WORK/build/$1 log=$WORK/logs/$1.log
  rm -rf "$dir"; mkdir -p "$dir"
  local args="node tool -Doptimize=$OPT -Dtarget=$target -Dgit-sha=$SHA12 -j$JOBS --prefix $dir/out --summary all --verbose"
  [ -z "$cpu" ] || args="$args -Dcpu=$cpu"
  say "build $name: zig build $args"
  # shellcheck disable=SC2086
  ( cd "$SRC" && ${RELEASE_BUILD_WRAP:-} env -i PATH=/usr/bin:/bin HOME="$WORK/home" LC_ALL=C TZ=UTC \
      ${SDKROOT:+SDKROOT=$SDKROOT} ZIG_GLOBAL_CACHE_DIR="$dir/zig-global" ZIG_LOCAL_CACHE_DIR="$dir/zig-local" \
      nice -n 10 "$ZIG" build $args ) > "$log" 2>&1 || { tail -40 "$log" >&2; die "build $name failed, log: $log"; }
  # Every compile for the target must carry the mode asked for; none may be Debug.
  grep -E 'build-(exe|obj|lib) ' "$log" | grep -e " -target $target " > "$dir/compiles.txt" || die "build $name: no target compiles in $log"
  if grep -v -e " -O$OPT " "$dir/compiles.txt" | grep -q .; then die "build $name: a compile ran without -O$OPT, log: $log"; fi
  [ -x "$dir/out/bin/deepwave" ] && [ -x "$dir/out/bin/deepwave-tool" ] || die "build $name: binaries missing"
  mkdir -p "$dir/bin"
  local b
  for b in deepwave deepwave-tool; do
    case "$target" in
      *-linux-*) helper strip "$dir/out/bin/$b" "$dir/bin/$b" ;;
      *-macos*)  cp "$dir/out/bin/$b" "$dir/bin/$b"; strip -S -x "$dir/bin/$b" 2>/dev/null
                 codesign --force --sign - --identifier "$b" "$dir/bin/$b" 2>/dev/null ;;
    esac
    chmod 0755 "$dir/bin/$b"
  done
}

# run_here FILE ARGS...: run a built binary when this machine can.
can_run() {
  case "$1" in
    ubuntu-x86_64*) [ "$HOST_OS" = Linux ] && [ "$HOST_ARCH" = x86_64 ] ;;
    ubuntu-aarch64) [ "$HOST_OS" = Linux ] && [ "$HOST_ARCH" = aarch64 ] ;;
    macos-arm64) [ "$HOST_OS" = Darwin ] && [ "$HOST_ARCH" = arm64 ] ;;
  esac
}

# pack_platform PLATFORM NAME CPU_NOTE: checks the binaries of build NAME and writes the archive.
pack_platform() {
  local plat=$1 name=$2 cpu_note=$3 dir=$WORK/build/$2 stage=$WORK/stage/$1 archive=$OUT/$BASE-$1.tgz b
  rm -rf "$stage"; mkdir -p "$stage"
  cp "$dir/bin/deepwave" "$dir/bin/deepwave-tool" "$stage/"
  check ""; check "#### $plat ($BASE-$plat.tgz)"
  for b in deepwave deepwave-tool; do
    check "-- $b: $(wc -c < "$stage/$b" | tr -d ' ') bytes, sha256 $(sha256 "$stage/$b")"
    if command -v file >/dev/null; then check "file: $(file -b "$stage/$b")"; fi
    case "$plat" in
      ubuntu-*)
        helper elf "$stage/$b" > "$dir/$b.elf"; sed 's/^/elf: /' "$dir/$b.elf" | tee -a "$CHECKS"
        local want_machine=${plat#ubuntu-}; want_machine=${want_machine%%-v*}
        grep -qx "machine=$want_machine" "$dir/$b.elf" || die "$plat $b: wrong machine"
        grep -qx "debug_sections=none" "$dir/$b.elf" || die "$plat $b: debug sections left in"
        local gmax; gmax=$(sed -n 's/^glibc_max=//p' "$dir/$b.elf")
        [ "$gmax" != none ] || die "$plat $b: no GLIBC version references found"
        [ "$(printf '%s\n2.35\n' "$gmax" | sort -t. -k1,1n -k2,2n | tail -1)" = 2.35 ] || die "$plat $b: needs glibc $gmax, above 2.35"
        ;;
      macos-*)
        otool -l "$stage/$b" | grep -A4 LC_BUILD_VERSION | sed 's/^/otool: /' | tee -a "$CHECKS"
        otool -L "$stage/$b" | sed 1d | sed 's/^/otool -L:/' | tee -a "$CHECKS"
        codesign --verify "$stage/$b" && check "codesign: valid (ad hoc)"
        ;;
    esac
  done
  if can_run "$plat"; then
    local v; v=$("$stage/deepwave" --version)
    check "run: deepwave --version -> $v"
    [ "$v" = "deepwave $VERSION-$SHA12" ] || die "$plat: --version printed '$v', expected 'deepwave $VERSION-$SHA12'"
    check "run: deepwave --protocol-range -> $("$stage/deepwave" --protocol-range)"
    # The usage text is the check: the node prints it for --help and the tool for any call without
    # --dir, and both exit with status 2 at this commit, so the status is recorded, not required.
    local rc=0
    "$stage/deepwave" --help > "$dir/help.txt" 2>&1 || rc=$?
    grep -q '^deepwave run --dir' "$dir/help.txt" || die "$plat: --help did not print the usage text"
    check "run: deepwave --help -> exit $rc, $(wc -l < "$dir/help.txt" | tr -d ' ') lines of usage"
    rc=0
    "$stage/deepwave-tool" --help > "$dir/tool-help.txt" 2>&1 || rc=$?
    grep -q '^deepwave-tool <command>' "$dir/tool-help.txt" || die "$plat: deepwave-tool did not print its usage text"
    check "run: deepwave-tool --help -> exit $rc, $(wc -l < "$dir/tool-help.txt" | tr -d ' ') lines of usage"
  else
    check "run: not run here (host is $HOST_OS $HOST_ARCH)"
  fi

  local items="deepwave=$stage/deepwave=0755 deepwave-tool=$stage/deepwave-tool=0755"
  if [ -f "$SRC/LICENSE" ]; then cp "$SRC/LICENSE" "$stage/LICENSE"; items="$items LICENSE=$stage/LICENSE=0644"
  else check "note: the repository has no LICENSE file, so the archive has none"; fi
  cp "$SRC/vendor/zstd/LICENSE" "$stage/LICENSE-zstd.txt"; cp "$ZIG_DIR/LICENSE" "$stage/LICENSE-zig.txt"
  items="$items LICENSE-zstd.txt=$stage/LICENSE-zstd.txt=0644 LICENSE-zig.txt=$stage/LICENSE-zig.txt=0644"
  local requires
  case "$plat" in
    ubuntu-x86_64*) requires="x86_64 Linux with glibc 2.35 or newer (Ubuntu 22.04, Ubuntu 24.04 or equivalent).
Compiled for the $cpu_note CPU baseline; faster code paths are picked at run time where the CPU has them." ;;
    ubuntu-aarch64) requires="aarch64 Linux with glibc 2.35 or newer (Ubuntu 22.04, Ubuntu 24.04 or equivalent).
The documentation names x86_64 Linux as the production platform; this build is provided as is." ;;
    macos-arm64) requires="macOS on Apple silicon (arm64). A development build: Linux is the production platform." ;;
  esac
  cat > "$stage/README.txt" <<EOF
Deepwave $VERSION (commit $SHA12)

Deepwave is a Sui full node and a drop-in replacement for sui-node. This build matches
sui-node $SUI_RELEASE ($NETWORK-v$SUI_RELEASE).

Platform
$requires
Hardware, from the documentation: 4 cores or more (AVX2 or newer), 16 GB RAM, local NVMe with
250 GB free.

Files
  deepwave           the full node
  deepwave-tool      operator commands for a stopped node directory
  LICENSE-zstd.txt   licence of the zstd code compiled into the binaries
  LICENSE-zig.txt    licence of the Zig standard library compiled into the binaries

Check the binary
  ./deepwave --version           prints: deepwave $VERSION-$SHA12
  ./deepwave --protocol-range    the protocol versions it supports
  ./deepwave --help              every command and flag

Run
  sudo install -m 0755 deepwave deepwave-tool /usr/local/bin/
  deepwave --config-path /path/to/fullnode.yaml      (sui-node's own fullnode.yaml)
Hardware, the systemd unit, the trust inputs and every flag are described in
$(norm_url "$REPO_URL")/blob/$HEAD_SHA/docs/install.md

Verify the download
  sha256sum -c SHA256SUMS --ignore-missing
EOF
  items="$items README.txt=$stage/README.txt=0644"
  # shellcheck disable=SC2086
  local tar_sha; tar_sha=$(helper pack "$archive" "$COMMIT_TIME" $items)
  {
    echo "$BASE-$plat.tgz"
    echo "  tar stream sha256 $tar_sha"
    for b in $(cd "$stage" && ls | sort); do echo "  $(sha256 "$stage/$b")  $b"; done
  } >> "$MANIFEST"
  check "-- archive: $(wc -c < "$archive" | tr -d ' ') bytes, sha256 $(sha256 "$archive"), tar stream sha256 $tar_sha"
  helper list "$archive" | sed 's/^/tar: /' | tee -a "$CHECKS"
  [ "${PIPESTATUS[0]}" = 0 ] || die "$plat: archive metadata is not fixed"
  # Leak scan: the binaries, the other packed files, and the unpacked tar stream itself.
  gzip -dc "$archive" > "$dir/archive.tar"
  local rc=0
  helper scan "$PATTERNS" "${ALLOW_FILE:--}" "$stage"/* "$dir/archive.tar" > "$dir/scan.txt" || rc=$?
  sed "s#$WORK/##" "$dir/scan.txt" | sed 's/^/leak scan: /' | tee -a "$CHECKS"
  rm -f "$dir/archive.tar"
  [ "$rc" = 0 ] || die "$plat: leak scan found forbidden strings, see $CHECKS"
}

suffix_of() { echo "$1" | sed -e 's/^x86_64_//' -e 's/[^A-Za-z0-9]/-/g'; }

check "Deepwave release check: version $VERSION, sui-node $SUI_RELEASE, commit $HEAD_SHA"
check "optimize $OPT, zig $ZIG_VERSION, built on $HOST_OS $HOST_ARCH, commit time $COMMIT_TIME"
check "checkout: clean, origin $(norm_url "$ORIGIN"), HEAD $HEAD_SHA$([ "$OFFLINE" = 1 ] && echo ' (public branch check skipped: --offline)')"
check "leak scan strings: $(wc -l < "$PATTERNS" | tr -d ' ') fixed strings (build paths, user, host, any --forbid-file) and the email pattern"

for plat in $PLATFORMS; do
  case "$plat" in
    ubuntu-x86_64)
      build x86_64-linux "x86_64-linux-gnu.2.35" "$CPU"
      pack_platform ubuntu-x86_64 x86_64-linux "$CPU"
      if [ "$REPRO" = 1 ]; then
        build x86_64-linux-again "x86_64-linux-gnu.2.35" "$CPU"
        check ""; check "#### reproducibility: ubuntu-x86_64 built twice from empty caches"
        for b in deepwave deepwave-tool; do
          one=$(sha256 "$WORK/build/x86_64-linux/bin/$b"); two=$(sha256 "$WORK/build/x86_64-linux-again/bin/$b")
          check "$b: $one / $two $([ "$one" = "$two" ] && echo MATCH || echo DIFFERENT)"
          [ "$one" = "$two" ] || REPRO_FAILED=1
        done
      fi
      for c in $EXTRA_CPUS; do
        build "x86_64-linux-$(suffix_of "$c")" "x86_64-linux-gnu.2.35" "$c"
        pack_platform "ubuntu-x86_64-$(suffix_of "$c")" "x86_64-linux-$(suffix_of "$c")" "$c"
      done ;;
    ubuntu-aarch64)
      build aarch64-linux "aarch64-linux-gnu.2.35" ""
      pack_platform ubuntu-aarch64 aarch64-linux "" ;;
    macos-arm64)
      [ "$HOST_OS" = Darwin ] || die "macos-arm64 is only packed on macOS (it needs Apple's strip and codesign)"
      build aarch64-macos "aarch64-macos.15.0" ""
      pack_platform macos-arm64 aarch64-macos "" ;;
    *) die "unknown platform $plat" ;;
  esac
done

[ -z "$(git -C "$SRC" status --porcelain --ignored)" ] || die "the build wrote into the checkout"
( cd "$OUT" && for f in "$BASE"-*.tgz; do echo "$(sha256 "$f")  $f"; done ) > "$OUT/SHA256SUMS"
check ""; check "#### SHA256SUMS"; tee -a "$CHECKS" < "$OUT/SHA256SUMS"
[ -z "${REPRO_FAILED:-}" ] || die "the two ubuntu-x86_64 builds differ, see $CHECKS"
say "done: $OUT"
