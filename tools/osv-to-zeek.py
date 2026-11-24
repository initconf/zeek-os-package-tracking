#!/usr/bin/env python3
"""
osv-to-zeek.py - build PkgCVE tables for detect-package-cve.zeek from OSV.dev

Downloads distro advisory data from the public OSV.dev bulk export
(https://osv-vulnerabilities.storage.googleapis.com/), keeps the packages
you care about, and writes a Zeek script that redefs:

    PkgCVE::osv_package_cves    "<distro>|<release>|<source pkg>" -> vector of CVERec
    PkgCVE::osv_binary_sources  "<distro>|<release>|<binary pkg>" -> source pkg
    PkgCVE::osv_generated_at    generation timestamp

Only the Python standard library is used. Typical cron usage:

    17 4 * * *  /path/to/tools/osv-to-zeek.py --quiet && zeekctl deploy

Data notes
  * The FULL ecosystem archives (Debian/all.zip ~80 MB, Ubuntu/all.zip
    ~800 MB) are used. The per-release archives (e.g. "Debian:12/all.zip")
    stopped updating in Oct 2024 - never use those. Every run checks the
    newest `modified` timestamp per feed and warns if it is stale.
  * Debian  - per-CVE records (DEBIAN-CVE-*, older CVE-*) keyed by SOURCE package. Binary names
              come from the release's Packages index (deb.debian.org).
  * Ubuntu  - per-CVE records (UBUNTU-CVE-*) keyed by source package, with
              the binary package list embedded. Ubuntu Pro/ESM ecosystems are
              skipped unless --ubuntu-pro is given.
  * Rocky / AlmaLinux / Red Hat - advisories (RLSA/ALSA/RHSA) keyed by
              BINARY rpm name. Binaries are folded onto a source-like name
              (longest sibling prefix: openssl-libs -> openssl).
  * CVEs that share a (package, fixed version) are grouped into one CVERec
    whose `cve` field is a comma separated list. This keeps the Zeek table
    small (the Debian kernel alone has ~4,700 CVEs but ~100 fix versions).

Everything downloaded is treated as untrusted data: it is only parsed as
JSON / deb822 text and every string written to Zeek is escaped.
"""

import argparse
import datetime as dt
import email.utils
import io
import json
import lzma
import math
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
DEBIAN_MIRROR = "https://deb.debian.org/debian"
DEBIAN_SECURITY = "https://security.debian.org/debian-security"
USER_AGENT = "osv-to-zeek/1.0 (zeek-os-package-tracking)"

DEBIAN_CODENAMES = {"10": "buster", "11": "bullseye", "12": "bookworm",
                    "13": "trixie", "14": "forky"}

DEFAULT_DISTROS = [
    "debian:12", "debian:13",
    "ubuntu:20.04", "ubuntu:22.04", "ubuntu:24.04",
    "rocky:8", "rocky:9", "rocky:10",
    "almalinux:8", "almalinux:9", "almalinux:10",
    "rhel:8", "rhel:9", "rhel:10",
]

# High-impact SOURCE package names. Debian/Ubuntu and RPM spellings both
# listed where they differ. Override with --packages FILE or --all-packages.
DEFAULT_PACKAGES = """
openssl openssh sudo glibc bash curl wget xz-utils xz
policykit-1 polkit systemd util-linux shadow pam
linux kernel
apache2 httpd nginx squid
bind9 bind dnsmasq unbound
samba cups dbus
openldap krb5 gnutls28 gnutls nss libssh
libxml2 libxslt expat zlib sqlite3 sqlite
git rsync tar
exim4 exim postfix
chrony ntpsec ntp
ghostscript imagemagick ImageMagick
mariadb postgresql
""".split()

# Binary packages that never matter on a production host. Dropping them
# keeps the binary->source alias table small.
NOISE_BINARY = re.compile(
    r"(-dbgsym|-dbg|-debuginfo|-debugsource|-doc|-docs|-udeb|-tests?|"
    r"-examples|-source|-javadoc)$|^lib.*-dev-doc$")

SEVERITIES = ["Negligible", "Low", "Medium", "High", "Critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_RANK["Unknown"] = SEV_RANK["Medium"]  # treated as Medium for filtering


def log(args, *a):
    if not args.quiet:
        print(*a, file=sys.stderr)


# ----------------------------------------------------------------------------
# Version comparison (dpkg algorithm; good enough to order rpm EVRs too)
# ----------------------------------------------------------------------------

def _order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_evr(v):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def vercmp(a, b):
    ea, ua, ra = _split_evr(a)
    eb, ub, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _verrevcmp(ua, ub)
    if r:
        return -1 if r < 0 else 1
    r = _verrevcmp(ra, rb)
    return (r > 0) - (r < 0)


def upstream_major_minor(v):
    _, up, _ = _split_evr(v)
    m = re.match(r"(\d+)(?:\.(\d+))?", up)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0))


# ----------------------------------------------------------------------------
# Severity
# ----------------------------------------------------------------------------

_CVSS3_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x):
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
              "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        c, i, a = (_CVSS3_W["CIA"][m[k]] for k in ("C", "I", "A"))
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        expl = 8.22 * _CVSS3_W["AV"][m["AV"]] * _CVSS3_W["AC"][m["AC"]] * pr * _CVSS3_W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _roundup(min(1.08 * (impact + expl), 10))
        return _roundup(min(impact + expl, 10))
    except (KeyError, ValueError):
        return None


def score_to_sev(s):
    if s is None:
        return None
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    if s > 0:
        return "Low"
    return "Negligible"


VENDOR_SEV = {
    # Ubuntu priority / Debian urgency
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "negligible": "Negligible", "unimportant": "Negligible",
    # Red Hat family advisory prefixes
    "important": "High", "moderate": "Medium",
}


def record_cvss_sev(rec):
    for s in rec.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            sev = score_to_sev(cvss3_score(s.get("score", "")))
            if sev:
                return sev
    return None


def rpm_advisory_sev(rec):
    m = re.match(r"\s*(Critical|Important|Moderate|Low)\s*:", rec.get("summary") or "", re.I)
    return VENDOR_SEV[m.group(1).lower()] if m else None


# ----------------------------------------------------------------------------
# Download helpers (conditional GET, atomic writes)
# ----------------------------------------------------------------------------

def fetch(args, url, dest):
    """Download url to dest unless the cached copy is current. Returns path."""
    if args.offline:
        if not os.path.exists(dest):
            raise SystemExit(f"--offline but {dest} is not cached")
        return dest
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if os.path.exists(dest):
        req.add_header("If-Modified-Since",
                       email.utils.formatdate(os.path.getmtime(dest), usegmt=True))
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dest), prefix=".dl-")
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
            os.replace(tmp, dest)
            lm = resp.headers.get("Last-Modified")
            if lm:
                t = email.utils.parsedate_to_datetime(lm).timestamp()
                os.utime(dest, (t, t))
            log(args, f"  downloaded {url}")
    except urllib.error.HTTPError as e:
        if e.code == 304:
            log(args, f"  unchanged  {url}")
        elif e.code == 404:
            log(args, f"  not found  {url}")
            return None
        else:
            raise
    return dest


def osv_zip(args, ecosystem):
    name = re.sub(r"[^A-Za-z0-9._-]", "_", ecosystem) + ".zip"
    url = f"{OSV_BUCKET}/{urllib.parse.quote(ecosystem)}/all.zip"
    return fetch(args, url, os.path.join(args.cache_dir, name))


def iter_zip_records(path):
    with zipfile.ZipFile(path) as zf:
        for n in zf.namelist():
            if not n.endswith(".json"):
                continue
            try:
                yield json.loads(zf.read(n))
            except (ValueError, UnicodeDecodeError):
                continue


def fixed_versions(affected):
    out = []
    for rg in affected.get("ranges") or []:
        if rg.get("type") not in ("ECOSYSTEM", None):
            continue
        for ev in rg.get("events") or []:
            if "fixed" in ev:
                out.append(ev["fixed"])
    return out


def cve_ids(rec):
    rid = rec.get("id", "")
    m = re.match(r"^(?:UBUNTU-|DEBIAN-)?(CVE-\d{4}-\d+)$", rid)
    if m:
        return [m.group(1)]
    ids = []
    for k in ("upstream", "aliases", "related"):
        for x in rec.get(k) or []:
            if re.match(r"^CVE-\d{4}-\d+$", x) and x not in ids:
                ids.append(x)
    return ids or [rid]


def short_desc(rec):
    s = (rec.get("summary") or rec.get("details") or "").strip()
    s = s.split("\n")[0]
    return s[:140]


def published_year(rec, cve):
    m = re.match(r"CVE-(\d{4})-", cve)
    if m:
        return int(m.group(1))
    p = rec.get("published", "")
    return int(p[:4]) if p[:4].isdigit() else 0


# ----------------------------------------------------------------------------
# Collected data model
# ----------------------------------------------------------------------------

class Collector:
    def __init__(self, args):
        self.args = args
        # (distro, rel, source) -> {cve: (fixed, sev, desc)}
        self.cves = {}
        # (distro, rel, binary) -> source
        self.aliases = {}
        self.stats = {}
        self.newest = {}   # feed -> newest "modified" timestamp seen

    def seen(self, feed, rec):
        m = rec.get("modified") or ""
        if m > self.newest.get(feed, ""):
            self.newest[feed] = m

    def want_pkg(self, source):
        return self.args.all_packages or source in self.args.package_set

    def sev_ok(self, sev):
        if sev is None:
            return not self.args.drop_unknown
        return SEV_RANK[sev] >= SEV_RANK[self.args.min_severity]

    def add(self, distro, rel, source, cve, fixed, sev, desc):
        key = (distro, rel, source)
        d = self.cves.setdefault(key, {})
        cur = d.get(cve)
        # Same CVE from several advisories: keep the EARLIEST fix.
        if cur is None or vercmp(fixed, cur[0]) < 0:
            d[cve] = (fixed, sev or "Unknown", desc)
        self.stats[distro + ":" + rel] = self.stats.get(distro + ":" + rel, 0) + 1

    def alias(self, distro, rel, binary, source):
        if binary == source or NOISE_BINARY.search(binary) or "-langpack-" in binary:
            return
        # Kernel packages with the ABI in the name (linux-image-6.1.0-18-amd64,
        # linux-modules-5.15.0-91-generic, ...) are mapped to "linux" by a
        # regex in detect-package-cve.zeek; listing every ABI would cost
        # thousands of entries.
        if source == "linux" and re.search(r"\d+\.\d+\.\d+-\d+", binary):
            return
        self.aliases.setdefault((distro, rel, binary), source)


# ----------------------------------------------------------------------------
# Debian
# ----------------------------------------------------------------------------

def debian_packages_index(args, codename):
    """binary -> (source, source_version) for main/amd64 + security pocket.

    The SOURCE version is used (from "Source: name (version)" when the
    binary is versioned differently, e.g. bpftool 7.1.0+6.1.192-2 is built
    from linux 6.1.192-2)."""
    out = {}
    urls = [f"{DEBIAN_MIRROR}/dists/{codename}/main/binary-amd64/Packages.xz",
            f"{DEBIAN_SECURITY}/dists/{codename}-security/main/binary-amd64/Packages.xz"]
    for i, url in enumerate(urls):
        dest = os.path.join(args.cache_dir, f"debian-{codename}-{i}-Packages.xz")
        if not fetch(args, url, dest):
            continue
        with lzma.open(dest, "rt", encoding="utf-8", errors="replace") as fh:
            pkg = src = ver = srcver = None
            for line in fh:
                if line.startswith("Package: "):
                    pkg = line[9:].strip()
                elif line.startswith("Source: "):
                    m = re.match(r"(\S+)(?:\s+\(([^)]+)\))?", line[8:].strip())
                    if m:
                        src, srcver = m.group(1), m.group(2)
                elif line.startswith("Version: "):
                    ver = line[9:].strip()
                elif line.strip() == "":
                    if pkg:
                        s = src or pkg
                        v = srcver or ver or "0"
                        prev = out.get(pkg)
                        if prev is None or vercmp(v, prev[1]) > 0:
                            out[pkg] = (s, v, ver or "0")
                    pkg = src = ver = srcver = None
    return out


def debian_release_info(args, rel):
    """(source -> binaries, source -> current version) for one release."""
    index = debian_packages_index(args, DEBIAN_CODENAMES[rel])
    src_bins, src_ver = {}, {}
    for b, (s, v, bv) in index.items():
        # Only alias binaries versioned like their source (bpftool from
        # linux is 7.x; comparing it with kernel fixes is meaningless).
        if upstream_major_minor(bv) == upstream_major_minor(v):
            src_bins.setdefault(s, set()).add(b)
        if s not in src_ver or vercmp(v, src_ver[s]) > 0:
            src_ver[s] = v
    # Signed kernel images are built from linux-signed-<arch>, not linux.
    for s in list(src_bins):
        if s.startswith("linux-signed-"):
            src_bins.setdefault("linux", set()).update(src_bins[s])
    return src_bins, src_ver


def collect_debian(args, col, releases):
    releases = [r for r in releases if r in DEBIAN_CODENAMES or
                log(args, f"unknown debian release {r}, skipping")]
    if not releases:
        return
    log(args, f"[Debian] releases {releases}")
    path = osv_zip(args, "Debian")
    if not path:
        return
    info = {rel: debian_release_info(args, rel) for rel in releases}
    ecos = {f"Debian:{rel}": rel for rel in releases}

    pruned = 0
    for rec in iter_zip_records(path):
        col.seen("Debian", rec)
        if not rec.get("id", "").startswith(("DEBIAN-CVE-", "CVE-")):
            continue  # DSA/DLA/DTSA duplicate the per-CVE records
        for a in rec.get("affected") or []:
            pkg = a.get("package") or {}
            rel = ecos.get(pkg.get("ecosystem"))
            if rel is None:
                continue
            source = pkg.get("name", "")
            if not col.want_pkg(source):
                continue
            fixes = fixed_versions(a)
            if not fixes:
                continue  # unfixed: nothing to compare against
            fixed = fixes[0]
            src_bins, src_ver = info[rel]
            # Prune fixes from before this release existed: Debian stable
            # keeps the upstream major.minor for the life of the release, so
            # a fix on an OLDER major.minor without a release marker was
            # already in the version that shipped.
            cur = src_ver.get(source)
            if cur and f"deb{rel}u" not in fixed:
                fm, cm = upstream_major_minor(fixed), upstream_major_minor(cur)
                if fm and cm and fm < cm:
                    pruned += 1
                    continue
            sev = record_cvss_sev(rec)
            if sev is None:
                urg = ((a.get("ecosystem_specific") or {}).get("urgency") or "").lower()
                sev = VENDOR_SEV.get(urg.rstrip("*"))
            if not col.sev_ok(sev):
                continue
            for cve in cve_ids(rec):
                if args.since and published_year(rec, cve) < args.since:
                    continue
                col.add("debian", rel, source, cve, fixed, sev, short_desc(rec))
            for b in src_bins.get(source, ()):
                col.alias("debian", rel, b, source)
    log(args, f"  pruned {pruned} pre-release fixes")


# ----------------------------------------------------------------------------
# Ubuntu
# ----------------------------------------------------------------------------

def ubuntu_ecosystems(args, rel):
    lts = rel.endswith(".04") and int(rel.split(".")[0]) % 2 == 0
    ecos = [f"Ubuntu:{rel}:LTS" if lts else f"Ubuntu:{rel}"]
    if args.ubuntu_pro:
        ecos.append(f"Ubuntu:Pro:{rel}:LTS")
    return ecos


def collect_ubuntu(args, col, releases):
    log(args, f"[Ubuntu] releases {releases}")
    path = osv_zip(args, "Ubuntu")
    if not path:
        return
    ecos = {e: rel for rel in releases for e in ubuntu_ecosystems(args, rel)}
    for rec in iter_zip_records(path):
        col.seen("Ubuntu", rec)
        if not rec.get("id", "").startswith("UBUNTU-CVE-"):
            continue  # USN-* duplicate the per-CVE records
        for a in rec.get("affected") or []:
            pkg = a.get("package") or {}
            rel = ecos.get(pkg.get("ecosystem"))
            if rel is None:
                continue
            source = pkg.get("name", "")
            if not col.want_pkg(source):
                continue
            fixes = fixed_versions(a)
            if not fixes:
                continue
            es = a.get("ecosystem_specific") or {}
            sev = VENDOR_SEV.get((es.get("ubuntu_priority") or "").lower()) or record_cvss_sev(rec)
            if not col.sev_ok(sev):
                continue
            for cve in cve_ids(rec):
                if args.since and published_year(rec, cve) < args.since:
                    continue
                col.add("ubuntu", rel, source, cve, fixes[0], sev, short_desc(rec))
            for b in es.get("binaries") or []:
                if isinstance(b, dict) and b.get("binary_name"):
                    col.alias("ubuntu", rel, b["binary_name"], source)


# ----------------------------------------------------------------------------
# RPM family (Rocky, AlmaLinux, Red Hat)
# ----------------------------------------------------------------------------

RPM_ECOSYSTEMS = {
    "rocky": ("Rocky Linux", re.compile(r"^Rocky Linux:(\d+)$")),
    "almalinux": ("AlmaLinux", re.compile(r"^AlmaLinux:(\d+)$")),
    # "Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:10.2"
    # (EUS/AUS/SAP streams are skipped - different version lines).
    "rhel": ("Red Hat", re.compile(r"^Red Hat:enterprise_linux:(\d+)(?:\.\d+)?(?::|$)")),
}


def rpm_source_for(binary, siblings):
    """Longest sibling that is a dash-prefix of binary (openssl-libs -> openssl)."""
    best = binary
    for s in siblings:
        if s != binary and binary.startswith(s + "-") and (best == binary or len(s) > len(best)):
            best = s
    return best


def collect_rpm(args, col, distro, releases):
    eco_name, eco_re = RPM_ECOSYSTEMS[distro]
    log(args, f"[{eco_name}] releases {sorted(releases)}")
    path = osv_zip(args, eco_name)
    if not path:
        return
    for rec in iter_zip_records(path):
        col.seen(eco_name, rec)
        by_rel = {}
        for a in rec.get("affected") or []:
            pkg = a.get("package") or {}
            m = eco_re.match(pkg.get("ecosystem", ""))
            if not m or m.group(1) not in releases:
                continue
            name = pkg.get("name", "")
            if NOISE_BINARY.search(name):
                continue
            fixes = fixed_versions(a)
            if fixes:
                by_rel.setdefault(m.group(1), {})[name] = fixes[0]
        if not by_rel:
            continue
        sev = rpm_advisory_sev(rec) or record_cvss_sev(rec)
        if not col.sev_ok(sev):
            continue
        cves = cve_ids(rec)
        desc = short_desc(rec)
        for rel, bins in by_rel.items():
            for b, fixed in bins.items():
                source = rpm_source_for(b, bins)
                if not col.want_pkg(source):
                    continue
                col.alias(distro, rel, b, source)
                for cve in cves:
                    if args.since and published_year(rec, cve) < args.since:
                        continue
                    col.add(distro, rel, source, cve, fixed, sev, desc)


# ----------------------------------------------------------------------------
# Zeek output
# ----------------------------------------------------------------------------

def zstr(s):
    s = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in str(s))
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_rows(args, col):
    """Group CVEs per (key, fixed) -> list of (fixed, cves, sev, desc)."""
    out = {}
    for key, cves in col.cves.items():
        groups = {}
        for cve, (fixed, sev, desc) in cves.items():
            groups.setdefault(fixed, []).append((cve, sev, desc))
        rows = []
        for fixed in sorted(groups, key=_cmp_key):
            items = sorted(groups[fixed], key=lambda x: (-SEV_RANK[x[1]], x[0]))
            worst_sev = items[0][1]
            ids = [c for c, _, _ in items]
            shown = ids[:args.max_cves_per_row]
            cve_field = ",".join(shown)
            if len(ids) > len(shown):
                cve_field += f",+{len(ids) - len(shown)} more"
            if len(ids) == 1:
                desc = items[0][2] or ids[0]
            else:
                desc = f"{len(ids)} CVEs; worst {items[0][0]}: {items[0][2]}"
            rows.append((fixed, cve_field, worst_sev, desc[:200]))
        out[key] = rows
    return out


class _cmp_key:
    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return vercmp(self.v, other.v) < 0


def write_zeek(args, col):
    rows = build_rows(args, col)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    n_rows = sum(len(v) for v in rows.values())
    lines = [
        "##! GENERATED by tools/osv-to-zeek.py - do not edit by hand.",
        f"##! Generated: {now}",
        f"##! Distros:   {', '.join(args.distros)}",
        f"##! Min severity: {args.min_severity}; packages: "
        + ("ALL" if args.all_packages else f"{len(args.package_set)} allowlisted"),
        f"##! {len(rows)} source packages, {n_rows} fix groups, {len(col.aliases)} binary aliases.",
        "##! Newest record per feed: " + ", ".join(f"{k} {v[:10]}" for k, v in sorted(col.newest.items())),
        "",
        f"redef PkgCVE::osv_generated_at = {zstr(now)};",
        "",
        "redef PkgCVE::osv_package_cves += {",
    ]
    for (distro, rel, source) in sorted(rows):
        recs = rows[(distro, rel, source)]
        lines.append(f"    [{zstr(f'{distro}|{rel}|{source}')}] = vector(")
        body = []
        for fixed, cve, sev, desc in recs:
            body.append(f"        PkgCVE::CVERec($cve={zstr(cve)}, $fixed_in={zstr(fixed)}, "
                        f"$severity={zstr(sev)}, $description={zstr(desc)}, $origin=\"osv\")")
        lines.append(",\n".join(body))
        lines.append("    ),")
    lines.append("};")
    lines.append("")
    lines.append("redef PkgCVE::osv_binary_sources += {")
    for (distro, rel, b), source in sorted(col.aliases.items()):
        if (distro, rel, source) in rows:
            lines.append(f"    [{zstr(f'{distro}|{rel}|{b}')}] = {zstr(source)},")
    lines.append("};")
    text = "\n".join(lines) + "\n"

    out_dir = os.path.dirname(os.path.abspath(args.output))
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".osv-", suffix=".zeek")
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, args.output)
    log(args, f"wrote {args.output}: {len(rows)} packages, {n_rows} rows, "
              f"{len(col.aliases)} aliases, {len(text) / 1e6:.1f} MB")


# ----------------------------------------------------------------------------

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--distros", default=",".join(DEFAULT_DISTROS),
                    help="comma list of distro:release (default: %(default)s)")
    ap.add_argument("--output", default=os.path.join(here, "..", "osv-package-cves.zeek"))
    ap.add_argument("--cache-dir", default=os.path.join(
        os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "zeek-osv"))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--packages", help="file with source package names (one per line, # comments)")
    g.add_argument("--all-packages", action="store_true",
                   help="every package (large: tens of MB of Zeek script)")
    ap.add_argument("--min-severity", default="medium",
                    choices=[s.lower() for s in SEVERITIES])
    ap.add_argument("--drop-unknown", action="store_true",
                    help="drop CVEs with no severity information (default: keep)")
    ap.add_argument("--since", type=int, default=0, help="only CVEs from this year on")
    ap.add_argument("--max-cves-per-row", type=int, default=50)
    ap.add_argument("--ubuntu-pro", action="store_true",
                    help="also include Ubuntu Pro/ESM fixed versions")
    ap.add_argument("--offline", action="store_true", help="use cached downloads only")
    ap.add_argument("--max-data-age-days", type=int, default=14,
                    help="warn if a feed's newest record is older than this")
    ap.add_argument("--strict", action="store_true",
                    help="exit 2 (after writing) when a feed is stale")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    args.min_severity = args.min_severity.capitalize()
    args.distros = [d.strip().lower() for d in args.distros.split(",") if d.strip()]
    if args.packages:
        with open(args.packages) as fh:
            args.package_set = {l.split("#")[0].strip() for l in fh} - {""}
    else:
        args.package_set = set(DEFAULT_PACKAGES)
    os.makedirs(args.cache_dir, exist_ok=True)

    col = Collector(args)
    wanted = {}
    for d in args.distros:
        distro, _, rel = d.partition(":")
        if distro in ("debian", "ubuntu") or distro in RPM_ECOSYSTEMS:
            wanted.setdefault(distro, set()).add(rel)
        else:
            log(args, f"unsupported distro {d}, skipping")
    for distro, rels in wanted.items():
        if distro == "debian":
            collect_debian(args, col, sorted(rels))
        elif distro == "ubuntu":
            collect_ubuntu(args, col, sorted(rels))
        else:
            collect_rpm(args, col, distro, rels)

    if not col.cves:
        raise SystemExit("no CVE data collected - refusing to overwrite output")

    # Feed freshness: OSV has silently frozen exports before.
    stale = []
    now = dt.datetime.now(dt.timezone.utc)
    for feed, newest in sorted(col.newest.items()):
        try:
            age = (now - dt.datetime.fromisoformat(newest[:19] + "+00:00")).days
        except ValueError:
            continue
        log(args, f"  feed {feed}: newest record {newest[:10]} ({age} days old)")
        if age > args.max_data_age_days:
            stale.append(f"{feed} ({age} days)")
    if stale:
        print(f"WARNING: stale OSV feeds: {', '.join(stale)}", file=sys.stderr)

    write_zeek(args, col)
    if stale and args.strict:
        sys.exit(2)


if __name__ == "__main__":
    main()
