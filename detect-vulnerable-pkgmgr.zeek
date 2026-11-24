##! detect-vulnerable-pkgmgr.zeek
##!
##! Companion to OSPTracking. Hooks into OS_Log via os_log_policy and emits
##! an entry to pkgmgr_cve.log when a host is observed using a known-
##! vulnerable version of its package manager (APT, libdnf).
##!
##! The package manager itself runs as root and downloads code from the
##! network. CVEs in the manager (e.g. CVE-2019-3462 for APT, which
##! allowed mirror-MITM RCE) are categorically more severe than CVEs in
##! the OS - any unpatched manager is a one-step path to root.

@load base/frameworks/logging
@load base/frameworks/notice
@load ./os-package-tracking
@load ./detect-package-cve

module PkgMgrCVE;

export {
    redef enum Log::ID += { LOG };

    redef enum Notice::Type += {
        Vulnerable_Pkgmgr_Detected,
    };

    type Info: record {
        ts:           time   &log;
        host:         addr   &log;
        manager:      string &log;
        version:      string &log;
        cve:          string &log;
        fixed_in:     string &log;
        severity:     string &log;
        description:  string &log;
        user_agent:   string &log;
    };

    option raise_notice: bool = T;

    const dedup_interval = 1day &redef;

    ## A vulnerability record. `max_vulnerable` is the LAST version that
    ## carries the bug; anything <= max_vulnerable is flagged.
    type CVERec: record {
        cve:            string;
        ## First affected version (inclusive). Unset = all versions up to
        ## max_vulnerable. Needed for bugs introduced on a later branch.
        min_vulnerable: string &optional;
        max_vulnerable: string;
        fixed_in:       string;
        severity:       string;
        description:    string;
    };

    ## Known vulnerable APT versions. Sources: Debian Security Tracker,
    ## Ubuntu USN, NVD. `max_vulnerable` is the LAST version carrying the
    ## bug (inclusive). Comparison uses upstream version semantics; for
    ## distro-patched versions like "1.6.12ubuntu0.2" we strip suffix.
    ## Redef in local.zeek to extend.
    const apt_cves: vector of CVERec = vector(
        CVERec($cve="CVE-2019-3462",
               $max_vulnerable="1.4.8",
               $fixed_in="1.4.9",
               $severity="High",
               $description="HTTP 302 redirect field unsanitized; MITM RCE as root via mirror poisoning (DSA-4371-1, CVSS 8.1)"),
        CVERec($cve="CVE-2018-0501",
               $min_vulnerable="1.6",
               $max_vulnerable="1.6.3",
               $fixed_in="1.6.4",
               $severity="Medium",
               $description="mirror:// fallback skips InRelease GPG check; MITM serves unsigned packages (CVSS 5.9)"),
        CVERec($cve="CVE-2016-1252",
               $max_vulnerable="1.3.99",
               $fixed_in="1.4~beta2",
               $severity="Medium",
               $description="Malformed error handling allows MITM to bypass InRelease GPG signature (DSA-3733-1, CVSS 5.9)"),
        CVERec($cve="CVE-2020-3810",
               $max_vulnerable="2.1.1",
               $fixed_in="2.1.2",
               $severity="Medium",
               $description="ar/tar parser missing input validation; crafted .deb causes DoS (DSA-4685-1, CVSS 5.5)"),
        CVERec($cve="CVE-2020-27350",
               $max_vulnerable="2.1.12",
               $fixed_in="2.1.13",
               $severity="Medium",
               $description="Integer overflow in .deb ar/tar parsing (GHSL-2020-168/169); crash or memory corruption (DSA-4808-1, CVSS 5.7)"),
    ) &redef;

    ## libdnf / dnf5 CVEs. Sources: NVD, RHSA, oss-sec.
    const libdnf_cves: vector of CVERec = vector(
        CVERec($cve="CVE-2021-3445",
               $max_vulnerable="0.60.0",
               $fixed_in="0.60.1",
               $severity="High",
               $description="RPM main-header signature tricks libdnf verify; altered package install -> code execution (RHSA-2021:4464, CVSS 7.5)"),
        CVERec($cve="CVE-2024-2746",
               $max_vulnerable="5.1.16",
               $fixed_in="5.1.17",
               $severity="High",
               $description="dnf5daemon D-Bus reposdir whitelist TOCTOU bypass; local root via crafted .repo (CVSS 8.8)"),
        CVERec($cve="CVE-2024-1929",
               $max_vulnerable="5.1.11",
               $fixed_in="5.1.12",
               $severity="High",
               $description="dnf5daemon D-Bus open_session accepts arbitrary config before Polkit; local root via attacker .so (CVSS 7.5)"),
    ) &redef;

    ## Distro backports. Debian/Ubuntu patch apt WITHOUT moving the
    ## upstream version past max_vulnerable (e.g. Ubuntu 20.04 stays on
    ## 2.0.x, Debian 10 on 1.8.2.x), so an upstream-only comparison flags
    ## every patched host. Key: "<CVE>|<major.minor apt branch>", value:
    ## first FULL distro apt version on that branch that carries the fix.
    ## If the observed apt branch has an entry here, the host is flagged
    ## only when its full version is older than this.
    ## Sources: USN-4359-1 (CVE-2020-3810), USN-4667-1 / DSA-4808-1 /
    ## DLA-2487-1 (CVE-2020-27350), DSA-4685-1, USN-3863-1 / DSA-4371-1
    ## (CVE-2019-3462), USN-3156-1 (CVE-2016-1252). Verify and extend in
    ## local.zeek.
    const apt_backport_fixes: table[string] of string = {
        ["CVE-2020-3810|1.2"]  = "1.2.32ubuntu0.1",
        ["CVE-2020-3810|1.4"]  = "1.4.10",
        ["CVE-2020-3810|1.6"]  = "1.6.12ubuntu0.1",
        ["CVE-2020-3810|1.8"]  = "1.8.2.1",
        ["CVE-2020-3810|2.0"]  = "2.0.2ubuntu0.1",
        ["CVE-2020-27350|1.2"] = "1.2.32ubuntu0.2",
        ["CVE-2020-27350|1.4"] = "1.4.11",
        ["CVE-2020-27350|1.6"] = "1.6.12ubuntu0.2",
        ["CVE-2020-27350|1.8"] = "1.8.2.2",
        ["CVE-2020-27350|2.0"] = "2.0.2ubuntu0.2",
        ["CVE-2020-27350|2.1"] = "2.1.10ubuntu0.1",
        ["CVE-2016-1252|1.2"]  = "1.2.15ubuntu0.2",
        ["CVE-2019-3462|1.2"]  = "1.2.29ubuntu0.1",
        ["CVE-2019-3462|1.4"]  = "1.4.9",
    } &redef;

    global compare_versions: function(a: string, b: string): int;
    global parse_apt_full_version: function(ua: string): string;
    global parse_apt_version:    function(ua: string): string;
    global parse_libdnf_version: function(ua: string): string;
}

global reported: set[addr, string, string]
    &create_expire=dedup_interval;

event zeek_init() &priority=5
    {
    Log::create_stream(PkgMgrCVE::LOG,
                       [$columns=Info, $path="pkgmgr_cve"]);
    }

## Compare two dotted version strings numerically. Returns -1/0/+1 like
## strcmp. Non-numeric segments compare as 0; trailing missing segments
## are treated as 0 (so "1.6" == "1.6.0").
function compare_versions(a: string, b: string): int
    {
    local pa = split_string(a, /\./);
    local pb = split_string(b, /\./);
    local n = (|pa| > |pb|) ? |pa| : |pb|;
    local i = 0;
    while ( i < n )
        {
        local sa = (i < |pa|) ? pa[i] : "0";
        local sb = (i < |pb|) ? pb[i] : "0";
        local ia = to_count(sa);
        local ib = to_count(sb);
        if ( ia < ib ) return -1;
        if ( ia > ib ) return  1;
        i += 1;
        }
    return 0;
    }

## Extract the apt version from a Debian APT-HTTP User-Agent.
##   "Debian APT-HTTP/1.3 (1.6.12ubuntu0.2) non-interactive"
## yields "1.6.12". Returns "" if not parseable.
function parse_apt_version(ua: string): string
    {
    if ( /Debian APT-HTTP/ !in ua )
        return "";
    local m = find_last(ua, /\([0-9][^)]*\)/);
    if ( m == "" )
        return "";
    local inner = sub_bytes(m, 2, |m| - 2);
    local toks = split_string(inner, /[^0-9.]/);
    if ( |toks| == 0 )
        return "";
    return toks[0];
    }

## Full distro apt version from the UA, e.g. "1.6.12ubuntu0.2", or "".
function parse_apt_full_version(ua: string): string
    {
    if ( /Debian APT-HTTP/ !in ua )
        return "";
    local m = find_last(ua, /\([0-9][^)]*\)/);
    if ( m == "" )
        return "";
    local toks = split_string(sub_bytes(m, 2, |m| - 2), /[[:space:]]+/);
    return |toks| > 0 ? toks[0] : "";
    }

## "1.6.12" -> "1.6"
function version_branch(v: string): string
    {
    local p = split_string(v, /\./);
    if ( |p| < 2 )
        return v;
    return p[0] + "." + p[1];
    }

## Extract the libdnf version when present. Most libdnf UAs in the wild
## do NOT include the manager version (only the OS), so this often
## returns "". Kept for forward compatibility.
function parse_libdnf_version(ua: string): string
    {
    if ( /^libdnf/ !in ua )
        return "";
    local m = find_last(ua, /libdnf\/[0-9][0-9.]*/);
    if ( m == "" )
        return "";
    local toks = split_string(m, /\//);
    if ( |toks| < 2 )
        return "";
    return toks[1];
    }

function check_against(manager: string, version: string, full_version: string,
                       cves: vector of CVERec, host: addr,
                       ts: time, ua: string)
    {
    if ( version == "" )
        return;
    local branch = version_branch(version);
    for ( _, c in cves )
        {
        if ( compare_versions(version, c$max_vulnerable) > 0 )
            next;
        if ( c?$min_vulnerable && compare_versions(version, c$min_vulnerable) < 0 )
            next;

        # Upstream says vulnerable; check whether the distro backported
        # the fix onto this branch.
        local bk = c$cve + "|" + branch;
        if ( full_version != "" && bk in apt_backport_fixes &&
             PkgCVE::compare_pkg_versions(full_version, apt_backport_fixes[bk]) >= 0 )
            next;

        if ( [host, manager, c$cve] in reported )
            next;

        local r = Info($ts=ts, $host=host, $manager=manager,
                       $version=version, $cve=c$cve,
                       $fixed_in=c$fixed_in, $severity=c$severity,
                       $description=c$description, $user_agent=ua);
        Log::write(PkgMgrCVE::LOG, r);
        add reported[host, manager, c$cve];

        if ( raise_notice )
            NOTICE([$note=Vulnerable_Pkgmgr_Detected,
                    $src=host,
                    $identifier=fmt("%s|%s|%s", host, manager, c$cve),
                    $suppress_for=dedup_interval,
                    $msg=fmt("%s %s on host has %s (%s, fixed in %s): %s",
                             manager, version, c$cve, c$severity,
                             c$fixed_in, c$description),
                    $sub=fmt("ua=%s", ua)]);
        }
    }

hook OSPTracking::os_log_policy(rec: OSPTracking::OSInfo,
                                id: Log::ID,
                                filter: Log::Filter)
    {
    if ( ! rec?$request || ! rec$request?$user_agent )
        return;
    local ua = rec$request$user_agent;

    local av = parse_apt_version(ua);
    if ( av != "" )
        check_against("apt", av, parse_apt_full_version(ua), apt_cves,
                      rec$host, rec$ts, ua);

    local lv = parse_libdnf_version(ua);
    if ( lv != "" )
        check_against("libdnf", lv, "", libdnf_cves, rec$host, rec$ts, ua);
    }
