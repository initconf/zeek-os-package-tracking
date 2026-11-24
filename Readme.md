# zeek-os-package-tracking

Passive inventory of operating systems and installed packages, built from the package-manager traffic Zeek already sees, with three security detectors on top:

- **End-of-life OS:** hosts running a release whose vendor support has ended, and the ones that keep running it for days.
- **Vulnerable package manager:** `apt`, `libdnf` or `dnf5` versions with known root-level CVEs.
- **Vulnerable package:** a host downloads a `.deb` or `.rpm` that the distro has since patched, matched against current CVE data from [OSV.dev](https://osv.dev/).

Linux and BSD systems fetch packages over plain HTTP (the packages are signed, so this is safe by design). The URL and User-Agent of each fetch name the OS release, the package and its exact version, so no agent or scan is needed.

Forked from [0xxon/zeek-os-package-tracking](https://github.com/0xxon/zeek-os-package-tracking), which provides the OS and package tracking. The detectors, the OSV generator and the fixes listed under [Changes from upstream](#changes-from-upstream) were added here.

## Install

Put this directory on your Zeek script path (for example in a directory listed in zeekctl's `SitePolicyPath`), then add to `local.zeek`:

```zeek
@load zeek-os-package-tracking
```

`__load__.zeek` loads the tracker, the three detectors and, if it has been generated, the OSV CVE table. Load it on all nodes: the tracking runs on workers, where the HTTP traffic is.

Then generate the CVE table once and schedule it (see [Keeping CVE data current](#keeping-cve-data-current)):

```sh
tools/osv-to-zeek.py
zeekctl deploy
```

Without the generated table the package still loads and uses only the small built-in CVE list.

## What it sees

| OS | Detected from |
|---|---|
| Debian, Ubuntu | APT requests: `dists/<suite>` gives the release, `pool/…/<pkg>_<ver>_<arch>.deb` gives packages. Includes `-security` and `-ports` mirrors. |
| RHEL, Rocky, AlmaLinux, CentOS Stream, Fedora | libdnf User-Agent (`libdnf (Rocky Linux 9.4; generic; Linux.x86_64)`) and `.rpm` downloads. Fedora uses HTTPS by default, so it is mostly invisible. |
| FreeBSD | `freebsd-update` and `pkg` requests |
| Windows | `Microsoft-CryptoAPI/<ver>` fetches from `crl.microsoft.com`. Windows 10, 11 and Server 2016+ all send 10.0 and cannot be told apart. |

## What you get

### Logs

| Log | One row per | Written by |
|---|---|---|
| `os_info.log` | host + OS + version + platform, once per `os_tracking_interval` (1 day) | `os-package-tracking.zeek`, `microsoft-os-tracking.zeek` |
| `package_info.log` | package download (name, version, previous version, OS release) | `os-package-tracking.zeek` |
| `eol_info.log` | EOL host + release, once per `eol_dedup_interval` (1 day) | `detect-eol-linux.zeek` |
| `eol_summary.log` | EOL host + release seen in the last 2 days, written daily: first/last seen, days active, persistence | `detect-eol-linux.zeek` |
| `pkgmgr_cve.log` | host + package manager + CVE, once per day | `detect-vulnerable-pkgmgr.zeek` |
| `package_cve.log` | vulnerable download: every unpatched CVE, the version that fixes them all, worst severity, CVE count, data origin | `detect-package-cve.zeek` |

Field-by-field descriptions are in [DETECTORS.md](./DETECTORS.md#field-reference).

### Notices

| Notice | Fires when | Suppressed per |
|---|---|---|
| `EOLLinux::EOL_Distro_Detected` | A host announces a release that is past its end-of-life date. Severity grows with time past EOL: Low under 90 days, Medium under a year, High under 3 years, then Critical. | host + distro + version, 1 day |
| `EOLLinux::EOL_Persistent_Host` | The same EOL host + release has been seen over at least `persistent_threshold` (7 days): a forgotten machine, not a one-off. Linux hosts are also marked `kernel_lpe_likely` for the May 2026 Copy Fail / Dirty Frag kernel LPEs. | host + distro + version, `summary_interval` (1 day) |
| `PkgMgrCVE::Vulnerable_Pkgmgr_Detected` | The package manager's own version (from its User-Agent) has a known CVE, such as apt CVE-2019-3462 (mirror MITM to root). Distro builds carrying a backported fix are skipped. | host + manager + CVE, 1 day |
| `PkgCVE::Vulnerable_Package_Detected` | A downloaded package version is older than the distro's fixed version for one or more CVEs (the OSV table holds Medium severity and above by default). | host + package + fixed version, 1 day |

Every detector has `raise_notice` (default `T`) to log without raising notices.

Example `package_cve.log` rows (from the test suite):

```
distro  package                     version             fixed_in            cve_count  severity  origin
debian  openssh-server              1:9.2p1-2+deb12u3   1:9.2p1-2+deb12u10  6          High      osv
debian  linux-image-6.1.0-18-amd64  6.1.76-1            6.1.192-1           8153       Critical  osv
ubuntu  openssh-server              1:8.9p1-3ubuntu0.1  1:8.9p1-3ubuntu0.18  21         Critical  osv
rocky   openssl-libs                3.0.7-27.el9.x86_64 1:3.5.9-1.el9_9     54         High      osv
```

## How it works

```
HTTP::log_http ──► os-package-tracking.zeek ──► os_info.log ──────► os_log_policy hook
  (cheap User-Agent          │                                       ├─► detect-eol-linux        ─► eol_info / eol_summary
   test first)               │                                       └─► detect-vulnerable-pkgmgr ─► pkgmgr_cve
                             └────────────────► package_info.log ─► package_log_policy hook
                                                                     └─► detect-package-cve      ─► package_cve
                                                                           ▲
                                                 osv-package-cves.zeek ────┘  (generated daily by tools/osv-to-zeek.py)
```

**Tracking.** `HTTP::log_http` runs for every HTTP transaction, so the handler checks the User-Agent with a substring test first and drops everything that is not APT, libdnf, FreeBSD or CryptoAPI before touching the URI. When a host announces its release (an APT `dists/` request, a libdnf User-Agent), that release is remembered for the host, so later package rows carry `os_version` even though `pool/` URLs don't name the release.

**Detectors.** The detectors never touch the tracker's code. They run in its log policy hooks, see each `os_info` / `package_info` record as it is written, and write their own logs. Each can be dropped by loading the files individually instead of the package.

**Matching a package to a CVE.** Distros backport fixes without changing the upstream version, so `openssh 9.2p1` can be patched or not depending on the `+deb12uN` suffix. Matching is therefore keyed by `distro|release|package` and compared with a dpkg/rpm-style version comparator (epochs, `~`, `+debNuM`, `ubuntuN.M`, `.elN_M`). For each download the lookup tries, in order:

1. the downloaded name (`openssl-libs`, `libssl3`);
2. its source package from the OSV alias table (`libssl3` → `openssl`, `libc6` → `glibc`, `openssh-server` → `openssh`);
3. `linux` for kernel packages with an ABI in the name (`linux-image-6.1.0-18-amd64`);
4. on RHEL-family systems, the source RPM name guessed from the binary name.

If the OSV table covers the package, the built-in rows for it are ignored. All matches for one download are collapsed into a single `package_cve.log` row and notice, so an old kernel gives one alert listing 8,000 CVEs instead of 8,000 alerts.

**Memory.** OS state is kept per host for one day; EOL state is kept for 30 days after a host was last seen; CVE tables are looked up in place, never copied. A Zeek process with the package and the default OSV table measured about 125 MB, 15 MB more than without the table, and starts in under a second.

## Keeping CVE data current

`detect-package-cve.zeek` has only a hand-written list of about 50 high-profile CVEs. Current data comes from `tools/osv-to-zeek.py` (Python 3, standard library only), which builds `osv-package-cves.zeek` from the OSV.dev full exports for Debian, Ubuntu, Rocky Linux, AlmaLinux and Red Hat.

```sh
tools/osv-to-zeek.py           # Debian 12/13, Ubuntu 20.04/22.04/24.04, Rocky/Alma/RHEL 8/9/10
tools/osv-to-zeek.py --help    # distros, package list, severity floor, ...
```

- **Coverage:** about 50 high-impact source packages (OpenSSH, OpenSSL, glibc, the kernel, sudo, curl, bind, …) at Medium severity and above. Default output: about 500 packages, 4,800 rows and 2,700 binary-name aliases in 1.6 MB. `--all-packages` takes everything.
- **Binary names:** from Debian's `Packages` index, the binary lists in Ubuntu's records, and sibling names in RPM advisories.
- **Freshness:** OSV's per-release archives (`Debian:12`, `Ubuntu:22.04:LTS`) stopped updating in October 2024, so the generator uses the full archives. It reports the newest record per feed and warns when one is older than 14 days; `--strict` then exits with status 2. The generation time is logged to `reporter.log` at startup.
- **Cost:** about 2 minutes and 135 MB of memory per run. Downloads are cached in `~/.cache/zeek-osv` and fetched again only when they change (Ubuntu's archive is about 800 MB).

The generated file is not tracked in git. Run it daily and redeploy so workers load the new table; with `--strict`, a stale feed skips the deploy:

```
17 4 * * *  /path/to/zeek-os-package-tracking/tools/osv-to-zeek.py --quiet --strict && zeekctl deploy
```

## Layout

```
__load__.zeek                  loads everything below; OSV table only if present
os-package-tracking.zeek       OS + package extraction; os_info.log, package_info.log, policy hooks
microsoft-os-tracking.zeek     Windows version from CryptoAPI CRL fetches
detect-eol-linux.zeek          EOL date table, per-host persistence, eol_info / eol_summary
detect-vulnerable-pkgmgr.zeek  apt / libdnf / dnf5 CVE table with backport exceptions
detect-package-cve.zeek        version comparator, alias lookup, built-in CVE table, package_cve
osv-package-cves.zeek          generated CVE table (not in git)
tools/osv-to-zeek.py           generator for osv-package-cves.zeek
tmp/test_*.zeek                tests
DETECTORS.md                   heuristics, CVE tables, log fields, all tunables
```

## Tuning

```zeek
redef OSPTracking::track_hosts = LOCAL_HOSTS;  # default ALL_HOSTS also tracks public mirrors you serve
redef EOLLinux::persistent_threshold = 7day;   # days of sightings before EOL_Persistent_Host
redef EOLLinux::eol_table += { ["mydistro|99"] = "2099-01-01" };
redef PkgCVE::collapse_matches = F;            # one package_cve row per CVE group instead of per download
redef PkgCVE::max_cves_in_row = 50;            # cap on CVE IDs listed in one row (cve_count keeps the total)
redef PkgCVE::package_cves += { ["debian|12|nginx"] = vector(PkgCVE::CVERec($cve="CVE-…", $fixed_in="…", $severity="High", $description="…")) };
```

The full list, with defaults, is in [DETECTORS.md](./DETECTORS.md).

## Tests

```sh
for t in tmp/test_*.zeek; do zeek $t; done
```

| Test | Covers |
|---|---|
| `test_eol` | EOL lookup, version recovery from libdnf, every severity bucket |
| `test_pkgmgr` | apt / libdnf version parsing and CVE matching |
| `test_pkgcve` | version comparator: OpenSSL letter suffixes, RHEL z-streams, Ubuntu rebuilds, Debian `+deb` suffixes |
| `test_pkgcve_e2e` | 35 distro/package/version cases, including all built-in kernel CVEs |
| `test_fixes` | regressions: Debian `-security` suites, `%3a` epochs, RPM names containing `-<digit>`, apt backports, EOL persistence |
| `test_osv` | OSV table end to end: source aliases, kernel ABI names, collapsing, built-in fallback (needs the generated table) |

## Limits

- **Only plain-HTTP downloads are visible.** Hosts using HTTPS mirrors (Fedora by default) are missed; hosts behind a caching proxy appear as the proxy.
- **A host that never updates never appears.** `EOL_Persistent_Host` partly covers this, but only for hosts that still fetch metadata.
- **A download is not an install.** The alert says the host fetched a vulnerable version, usually as part of an upgrade to a newer one; it does not prove that version is running.
- **No language or container packages:** pip, npm, gem, cargo and container image layers don't use the system package manager.
- **Ubuntu kernels** other than the `-generic` and `-lowlatency` flavours, and Ubuntu kernel metapackages, are not matched.
- **Release coverage:** OSV data covers the distros listed above. Others (Debian 11, Amazon Linux) use only the built-in list, and some EOL dates and apt backport versions in the tables are marked "verify".

## LBL site config

- Loaded from `zeek-cpp/host/policies/local.zeek` (`@load zeek-os-package-tracking`); `host/policies/zeek-os-package-tracking` is a symlink to this repository.
- The `bro` crontab regenerates the OSV table at 04:17 and runs `zeekctl deploy`; output goes to `~/.cache/zeek-osv/last-run.log`.
- This replaced `/YURT/feeds/BRO-feeds/CVE/package_cves.zeek` on 2026-11-19. That feed had about 1.7 million rows, cost about 3.85 GB of memory per Zeek process and 20 s of startup, and keyed Debian and Ubuntu CVEs by source package name, so downloads of binary packages (`openssh-server`, `libc6`, `linux-image-*`) never matched it.
- Replaying `tmp/ALL.pcap` (port 80) gave 643 `os_info` rows, 188 package downloads, 44 `eol_summary` hosts, and no `pkgmgr_cve` rows: all package managers seen were patched builds. Before the backport fix the same capture gave 71 false `pkgmgr_cve` rows.

## Changes from upstream

- Debian/Ubuntu: `-security` and `-ports` mirrors, URL-escaped epochs (`%3a`), package rows carry the OS release.
- RPM: names containing `-<digit>` split correctly; version includes release and architecture.
- Windows: names no longer read "WindowsWindows-…"; `track_hosts` is honored.
- Cheaper `HTTP::log_http` handler: User-Agent test before any URI work.
- The three detectors and the OSV generator.

## Acknowledgements

This work was supported by the US National Science Foundation under grant [OAC-1642161](https://nsf.gov/awardsearch/showAward?AWD_ID=1642161&HistoricalAwards=false).
Any opinions, findings, and conclusions or recommendations
expressed in this material are those of the authors or origina-
tors, and do not necessarily reflect the views of the National
Science Foundation.
