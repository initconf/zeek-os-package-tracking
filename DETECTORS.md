# Security Detectors

This package ships three security detectors that build on top of `os-package-tracking.zeek`. Each detector consumes the existing `os_info.log` / `package_info.log` streams via Zeek policy hooks - they do not modify the parent script and can be loaded independently.

## At a glance

| Detector | Script | Output log(s) | Notice |
|---|---|---|---|
| End-of-life distro | `detect-eol-linux.zeek` | `eol_info.log`, `eol_summary.log` | `EOLLinux::EOL_Distro_Detected`, `EOLLinux::EOL_Persistent_Host` |
| Vulnerable package manager | `detect-vulnerable-pkgmgr.zeek` | `pkgmgr_cve.log` | `PkgMgrCVE::Vulnerable_Pkgmgr_Detected` |
| Vulnerable installed package | `detect-package-cve.zeek` | `package_cve.log` | `PkgCVE::Vulnerable_Package_Detected` |

All three are auto-loaded by `__load__.zeek`. To opt out of any one, copy the relevant `@load` line out of `__load__.zeek` into your `local.zeek` and toggle as needed.

## Detection heuristics

### H1: End-of-life distro

**Trigger**: A host downloads packages from a distro release whose vendor support window has ended.

**Mechanism**: `OSPTracking::os_log_policy` hook. Normalises the OS string into a canonical distro id, looks up `(distro, version)` in a built-in EOL date table, and emits `eol_info.log` if `today > eol_date`.

**Outputs**:
- `eol_info.log` - one row per `(host, distro, version)` first seen, deduped per `eol_dedup_interval` (default 1 day). Carries `severity` (Info / Low / Medium / High / Critical bucketed by days past EOL) and `support_status` (active / approaching / eol / rolling / unknown).
- `eol_summary.log` - one row per EOL `(host, distro, version)` seen within `summary_active_window` (default 2 days), written every `summary_interval` (default 1 day) and once more at shutdown. Per-host state is kept for `state_expire` (default 30 days, refreshed on every sighting) so persistence can build up across days. Adds `first_seen`, `last_seen`, `active_days`, `is_persistent` (host observed for ≥ `persistent_threshold`, default 7 days), `observations`, plus the `kernel_lpe_likely` cross-reference (see below).

**Notable behaviour**:
- Recovers OS version from libdnf User-Agents whose `version` field is an "edition" word like `generic` / `workstation` / `kde` (this works around a parsing quirk upstream in `os-package-tracking.zeek`).
- Truncates RHEL-family minor versions before lookup (`8.10` -> `8`), since the EOL table is keyed by major version.
- Covers Ubuntu, Debian, RHEL, CentOS / CentOS Stream, Rocky, AlmaLinux, Oracle Linux, Fedora, openSUSE Leap / Tumbleweed, SLES, FreeBSD, Alpine, Arch, Manjaro, Gentoo, NixOS, Windows.

**Cross-reference: `kernel_lpe_likely`**
A persistent EOL Linux host is flagged as likely vulnerable to the May 2026 page-cache LPE class (Copy Fail + Dirty Frag). Rationale: hosts that have been EOL for months almost certainly have not received the May 2026 patches, regardless of whether we observed them downloading a kernel. This catches the population that H3 misses.

**Tunables**:
```zeek
redef EOLLinux::raise_notice         = T;
redef EOLLinux::eol_dedup_interval   = 1day;
redef EOLLinux::summary_interval     = 1day;
redef EOLLinux::persistent_threshold = 7day;
redef EOLLinux::state_expire         = 30day;  # must exceed persistent_threshold
redef EOLLinux::summary_active_window = 2day;
redef EOLLinux::eol_table            += { ["mydistro|99"] = "2099-01-01" };
redef EOLLinux::edition_words        += { "minimal" };
redef EOLLinux::linux_distros        += { "yocto" };
```

---

### H3a: Vulnerable package manager

**Trigger**: The package manager itself (apt, libdnf, dnf5) speaks to a mirror with a User-Agent revealing a known-CVE version.

**Mechanism**: `OSPTracking::os_log_policy` hook. Parses the version out of the User-Agent string (`Debian APT-HTTP/1.3 (1.6.12ubuntu0.2) non-interactive` -> `1.6.12`), compares against a redef-able CVE table.

**Why this is its own detector**: The package manager runs as root, downloads code from the network, and historically has had RCE-class CVEs (CVE-2019-3462 enables mirror-MITM root). A vulnerable manager is a one-step path to root that no other layer compensates for.

**CVE coverage** (from Debian Security Tracker, Ubuntu USN, NVD, RHSA):

| Tool | CVE | CVSS | Severity | Description |
|---|---|---|---|---|
| apt | CVE-2019-3462 | 8.1 | High | HTTP-redirect MITM RCE as root (DSA-4371-1) |
| apt | CVE-2018-0501 | 5.9 | Medium | mirror:// fallback skips InRelease GPG check |
| apt | CVE-2016-1252 | 5.9 | Medium | InRelease GPG signature bypass (DSA-3733-1) |
| apt | CVE-2020-3810 | 5.5 | Medium | ar/tar parser DoS via crafted .deb (DSA-4685-1) |
| apt | CVE-2020-27350 | 5.7 | Medium | .deb integer overflow / memory corruption (DSA-4808-1) |
| libdnf | CVE-2021-3445 | 7.5 | High | RPM main-header signature bypass -> code execution (RHSA-2021:4464) |
| dnf5 | CVE-2024-1929 | 7.5 | High | dnf5daemon D-Bus Polkit bypass -> local root |
| dnf5 | CVE-2024-2746 | 8.8 | High | dnf5daemon TOCTOU on reposdir whitelist -> local root |

**Output**: `pkgmgr_cve.log` - one row per `(host, manager, cve)` per `dedup_interval` (default 1 day). Carries `cve`, `fixed_in`, `severity`, `description`, full UA.

**Tunables**:
```zeek
redef PkgMgrCVE::raise_notice    = T;
redef PkgMgrCVE::dedup_interval  = 1day;
redef PkgMgrCVE::apt_cves       += vector(
    PkgMgrCVE::CVERec($cve="CVE-yyyy-nnnn", $max_vulnerable="2.5.0",
                      $fixed_in="2.5.1", $severity="High",
                      $description="...")
);
```

---

### H3b: Vulnerable installed package

**Trigger**: A host downloads a `.deb` or `.rpm` whose `(distro, distro_major, package, version)` matches a known-CVE rule.

**Mechanism**: `OSPTracking::package_log_policy` hook. Combines OS context (recovered from libdnf where needed via the H1 helper functions) with the parsed package name + version, looks up `<distro>|<distro_major>|<package>` in `PkgCVE::package_cves`, and emits a row for any CVE whose `fixed_in` strictly exceeds the observed version.

**Distro-aware version comparison**: `package_cves` is keyed by `(distro, distro_major, package)` because Debian / Ubuntu / RHEL backport security fixes without bumping upstream versions. RHEL 8's `openssl-1.1.1k-9.el8_7` is a different fix point than upstream OpenSSL 1.1.1k. The comparator splits on `-`, compares upstream parts naturally (`1.1.1f` < `1.1.1n`, `3.0.7` < `3.0.13`), then compares distro suffixes with the rule that "shorter prefix sorts older" (`0.105-31` < `0.105-31+deb11u1`).

**CVE coverage** (~25 distro-package-CVE combinations):

| CVE | Class | Distro coverage |
|---|---|---|
| CVE-2024-6387 (regreSSHion) | OpenSSH RCE | Debian 11/12, Ubuntu jammy/noble, RHEL/Rocky/Alma 9 |
| CVE-2023-38408 | OpenSSH ssh-agent RCE | Debian 11/12 |
| CVE-2021-4034 (PwnKit) | polkit LPE | Debian 10/11, Ubuntu focal, RHEL/Rocky/Alma 8 |
| CVE-2021-3560 | polkit auth bypass | Debian 11 |
| CVE-2021-3156 (Baron Samedit) | sudo LPE | Debian 10, Ubuntu focal, RHEL/Rocky 8 |
| CVE-2023-4911 (Looney Tunables) | glibc LPE | Debian 11/12, Ubuntu jammy, RHEL/Rocky 8/9 |
| CVE-2024-5535 | OpenSSL buffer over-read | Debian 12, Ubuntu focal/jammy, RHEL 8/9 |
| CVE-2023-0286 | OpenSSL X.400 type confusion | Debian 12, Ubuntu jammy, RHEL 8/9 |
| CVE-2022-1292 | OpenSSL c_rehash RCE | Ubuntu focal |
| CVE-2023-38545 | curl SOCKS5 heap overflow | Debian 12, Ubuntu jammy, RHEL 9 |
| CVE-2023-25690 | Apache mod_proxy request smuggling | Debian 11/12 |
| CVE-2024-38475 | Apache mod_rewrite SSRF / auth bypass | Debian 11/12 |
| CVE-2021-44228 (Log4Shell) | Log4j JNDI RCE | Debian 11, Ubuntu jammy |
| CVE-2021-44832 | Log4j JDBC appender RCE | Debian 11, Ubuntu jammy |
| CVE-2024-3094 | xz-utils SSH backdoor | Debian sid, Fedora 41 |
| **CVE-2026-31431 (Copy Fail)** | Kernel algif_aead LPE, public PoC | Debian 11/12, RHEL 8/9/10, Alma 8/9/10, Rocky 8/9/10, Amazon Linux 2023 |
| **CVE-2026-43284 (Dirty Frag, xfrm-ESP)** | Kernel page-cache LPE | Debian 11/12, RHEL 8/9/10, Alma 8/9/10, Amazon Linux 2023 |
| **CVE-2026-43500 (Dirty Frag, RxRPC)** | Kernel page-cache LPE | Debian 11/12, RHEL 9/10, Alma 9/10 (RHEL 8 / Alma 8 do not ship `rxrpc.ko`) |

**Lookup order** for each downloaded package: the binary name, its exact source package from the OSV alias table (`openssh-server` -> `openssh`, `libc6` -> `glibc`), `linux` for ABI-named kernel packages (`linux-image-6.1.0-18-amd64`), then (RHEL family) heuristic SRPM names. If the generated OSV table covers the package, `package_cves` rows for it are ignored (`osv_overrides_builtin`). All tables are looked up in place, never copied.

**Output**: `package_cve.log` - by default (`collapse_matches=T`) ONE row per vulnerable download, listing every unpatched CVE (`cve`, capped at `max_cves_in_row`, with `cve_count` holding the true total), the version that fixes all of them (`fixed_in`) and the worst severity. Deduped per `(host, package, fixed_in)` per `dedup_interval` (default 1 day). With `collapse_matches=F` you get one row per CVE / fix group instead.

**Tunables**:
```zeek
redef PkgCVE::raise_notice           = T;
redef PkgCVE::dedup_interval         = 1day;
redef PkgCVE::collapse_matches       = T;
redef PkgCVE::max_cves_in_row        = 50;
redef PkgCVE::osv_overrides_builtin  = T;
redef PkgCVE::package_cves   += {
    ["debian|12|nginx"] = vector(
        PkgCVE::CVERec($cve="CVE-yyyy-nnnn",
                       $fixed_in="1.22.1-9+deb12u3",
                       $severity="High",
                       $description="...")
    )
};
```

---

## Severity scale (used by H1 and H3b)

| Bucket | Trigger |
|---|---|
| Info | No EOL date known (rolling release, unknown distro) |
| Low | EOL date known, host not yet past it; OR < 90 days past |
| Medium | 90 - 364 days past EOL |
| High | 365 - 1094 days past EOL |
| Critical | ≥ 1095 days past EOL (3+ years) |

H3a / H3b take severity directly from the per-CVE entry in their tables.

---

## Field reference

### `eol_info.log` (per-event)
| Field | Type | Description |
|---|---|---|
| ts | time | Time of the underlying os_info event |
| host | addr | Source IP |
| os | string | OS string as reported (e.g. `"Rocky Linux 8.10"`) |
| version | string | Version as recovered (e.g. `"8.10"`) |
| platform | string &optional | Architecture / kernel string |
| distro_key | string | Normalised distro id (`"rocky"`) |
| eol_date | string | YYYY-MM-DD; empty if rolling |
| is_eol | bool | True if `today > eol_date` |
| days_past_eol | count | Days since EOL |
| support_status | string | active / approaching / eol / rolling / unknown |
| severity | string | Info / Low / Medium / High / Critical |
| observations | count | How many `os_info.log` rows (roughly one per active day) seen for this `(host, distro, version)` |
| last_seen | time &optional | Most recent observation |
| user_agent | string &optional | UA from the triggering HTTP request |

### `eol_summary.log` (per-host periodic rollup)
All `eol_info.log` fields plus:
| Field | Type | Description |
|---|---|---|
| first_seen | time | First observation (state kept for `state_expire` after last sighting) |
| last_seen | time | Most recent observation |
| active_days | double | `(last_seen - first_seen)` in days |
| is_persistent | bool | True if `active_days >= persistent_threshold` |
| kernel_lpe_likely | bool | True if `is_persistent && distro in linux_distros` |
| kernel_lpe_cves | string &optional | Comma-separated CVE list when `kernel_lpe_likely` |

### `pkgmgr_cve.log`
| Field | Type | Description |
|---|---|---|
| ts | time | Event time |
| host | addr | Source IP |
| manager | string | `apt` or `libdnf` |
| version | string | Manager version parsed from UA |
| cve | string | Matched CVE |
| fixed_in | string | First version not vulnerable |
| severity | string | High / Medium / etc |
| description | string | One-line CVE description |
| user_agent | string | Full UA |

### `package_cve.log`
| Field | Type | Description |
|---|---|---|
| ts | time | Event time |
| host | addr | Source IP |
| package | string | Package name parsed from URL |
| version | string | Observed version (with distro suffix) |
| distro | string | Normalised distro (`rhel`, `ubuntu`, ...) |
| distro_major | string | Release (`8`, `22.04`, `12`, ...); codenames are mapped to numbers |
| cve | string | Matched CVE, or comma separated list (`,+N more` when truncated) |
| fixed_in | string | Version that fixes every listed CVE |
| severity | string | Worst severity among the listed CVEs |
| description | string | One-line description (of the worst CVE / fix group) |
| request_uri | string &optional | URL of the package fetch |
| cve_count | count | Total number of unpatched CVEs in this row |
| origin | string | `builtin` (package_cves), `osv` (generated table) or `builtin+osv` |

---

## What this does NOT detect

These limits are intrinsic to the data source (HTTP package-fetch traffic), not bugs:

- **Hosts that don't update**. A box that hasn't run `apt upgrade` in 3 years is the most-vulnerable host on the network and will never appear in `package_info.log`. H1 + `eol_summary.log` partly compensates by surfacing persistent hosts on EOL distros (the `kernel_lpe_likely` flag), but only if the host fetches metadata at all.
- **Hosts that fetch over HTTPS**. Fedora's `libdnf` uses HTTPS by default; we still see metadata fetches via SNI but lose package-level visibility. APT/freebsd-update use HTTP for content (signed packages, by design).
- **Static binaries, language packages (pip / npm / cargo / gem), container image layers**. None of these flow through the system package manager.
- **Local-only attack surface (D-Bus, kernel-modules-partner, kernel modules loaded at runtime)**. We can flag the kernel version but cannot tell whether a vulnerable module is loaded.

For these gaps, pair this package with an EDR / SCA tool (Tenable, Qualys, Trivy, OSV-Scanner). The Zeek detectors here are a passive, network-observed inventory layer that complements active scanning.

---

## Verification

Each detector ships unit tests under `tmp/`:

| Test | Coverage |
|---|---|
| `tmp/test_eol.zeek` | H1: `recover_version_from_os`, `looks_like_edition`, `eol_lookup_key`, `check_eol` (all severity buckets) |
| `tmp/test_pkgmgr.zeek` | H3a: `compare_versions`, `parse_apt_version`, `parse_libdnf_version` |
| `tmp/test_pkgcve.zeek` | H3b comparator: `compare_pkg_versions` including OpenSSL letter suffixes, RHEL z-stream, Ubuntu rebuilds, Debian `+deb` suffix |
| `tmp/test_pkgcve_e2e.zeek` | H3b end-to-end: 35 distro/package/version assertions including all kernel CVEs |
| `tmp/test_fixes.zeek` | Regressions: Debian `-security` suites, `%3a` epochs, RPM names with `-<digit>`, apt backports, EOL persistence (writes logs) |
| `tmp/test_osv.zeek` | OSV table end-to-end: binary->source aliases, kernel ABI names, collapse, builtin fallback (needs generated data; writes logs) |

Run with `zeek tmp/test_*.zeek` from the package root.

---

## Keeping CVE data current (OSV generator)

The hand-written `package_cves` table in `detect-package-cve.zeek` is a static watch-list of ~50 high-profile entries. `tools/osv-to-zeek.py` builds a current, distro-accurate table from [OSV.dev](https://osv.dev/) and writes it to `osv-package-cves.zeek`, which `__load__.zeek` loads automatically when present. The generated file is not tracked in git (see `.gitignore`); until the generator has run, only the builtin table is used.

```sh
tools/osv-to-zeek.py                 # default distros + allowlist, Medium and above
tools/osv-to-zeek.py --help          # all options
```

Cron (daily), then redeploy so workers pick it up:

```
17 4 * * *  /path/to/zeek-os-package-tracking/tools/osv-to-zeek.py --quiet --strict && zeekctl deploy
```

What it does:

| | |
|---|---|
| Sources | OSV full-ecosystem archives: `Debian`, `Ubuntu`, `Rocky Linux`, `AlmaLinux`, `Red Hat`. **Not** the per-release archives (`Debian:12/all.zip`, `Ubuntu:22.04:LTS/all.zip`): those stopped updating in Oct 2024. |
| Default distros | Debian 12/13, Ubuntu 20.04/22.04/24.04, Rocky/Alma/RHEL 8/9/10 (`--distros`) |
| Packages | ~50 high-impact source packages (`--packages FILE`, or `--all-packages`) |
| Binary names | Debian: from the release `Packages` index. Ubuntu: from the OSV records. RPM: advisory sibling prefix (`openssl-libs` -> `openssl`). Kernel ABI package names are handled by a regex in Zeek. |
| Severity | CVSS v3 base score, else distro rating (Ubuntu priority, Red Hat Important/Moderate, Debian urgency). `--min-severity` (default medium). CVEs with no rating are kept unless `--drop-unknown`. |
| Size | CVEs sharing a fixed version are grouped into one row; Debian fixes that predate the release are pruned. Default run: ~500 packages, ~4,800 rows, ~2,700 aliases, 1.6 MB; +~15 MB RSS per Zeek process. |
| Freshness | Logs the newest record date per feed and warns if any is older than `--max-data-age-days` (14). `--strict` makes that exit 2 (after writing). `PkgCVE::osv_generated_at` is logged to reporter.log at startup. |
| Downloads | Cached in `~/.cache/zeek-osv`, re-fetched only when changed (If-Modified-Since). Ubuntu's archive is ~800 MB. |

Limitations: Ubuntu kernels other than `-generic` / `-lowlatency` flavours, and Ubuntu kernel metapackages (`linux-image-generic` uses a different version scheme), are not matched. Rows for packages only in `package_cves` (e.g. Debian 11, Amazon Linux) still come from the hand table.

### Older external feed (`/YURT/feeds/BRO-feeds/CVE/package_cves.zeek`)

An earlier site feed redefs `package_cves` directly with ~1.7M rows. Measured on 2026-11-19 it costs **~3.7 GB RSS per Zeek process and ~20 s startup**, and it keys Debian/Ubuntu rows by *source* package name, so binary downloads (`openssh-server`, `libc6`, `linux-image-*`) never match it. The generator above replaces it; if both are loaded, OSV rows override it for every package OSV covers.

## Sources

CVE data sourced from authoritative trackers (preferred in this order):

- [Debian Security Tracker](https://security-tracker.debian.org/tracker/)
- [Ubuntu USN database](https://ubuntu.com/security/notices)
- [Red Hat errata](https://access.redhat.com/security/security-updates/)
- [AlmaLinux errata](https://errata.almalinux.org/)
- [Amazon Linux Security Center](https://alas.aws.amazon.com/)
- [NVD](https://nvd.nist.gov/)
- [OSV.dev](https://osv.dev/) (aggregates the above into one normalized schema; used by the auto-updated feed)

Each `CVERec` description in the source files cites the originating advisory. When extending tables, prefer these sources over secondary aggregators.
