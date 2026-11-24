##! detect-eol-linux.zeek
##!
##! Companion to OSPTracking. Hooks into OS_Log via os_log_policy and emits
##! an entry to eol_info.log (and optionally a Notice) whenever a host is
##! observed running an end-of-life Linux/FreeBSD/Windows distribution.
##!
##! Load order in local.zeek:
##!   @load ./ospt
##!   @load ./detect-eol-linux

@load base/frameworks/logging
@load base/frameworks/notice

module EOLLinux;

export {
    redef enum Log::ID += { LOG, SUMMARY_LOG };

    redef enum Notice::Type += {
        ## Host observed running an end-of-life Linux distribution.
        EOL_Distro_Detected,
        ## Host running an EOL distro AND observed continuously over a long
        ## period - very likely forgotten / unmanaged infrastructure.
        EOL_Persistent_Host,
    };

    type Info: record {
        ts:             time   &log;
        host:           addr   &log;
        os:             string &log;
        version:        string &log;
        platform:       string &log &optional;
        distro_key:     string &log;
        eol_date:       string &log;
        is_eol:         bool   &log;
        days_past_eol:  count  &log &default=0;
        ## Bucketed risk level derived from days_past_eol.
        ## one of: active, approaching, low, medium, high, critical
        support_status: string &log &default="active";
        severity:       string &log &default="Info";
        ## How many distinct (host, distro, version) observations we've
        ## accumulated since this worker started. Helps differentiate a
        ## one-off curiosity scan from a long-running production host.
        observations:   count  &log &default=1;
        last_seen:      time   &log &optional;
        user_agent:     string &log &optional;
    };

    option raise_notice: bool = T;

    const eol_dedup_interval = 1day &redef;

    ## Per-host EOL summary record (one row per (host, distro, version)
    ## per summary cycle, emitted to eol_summary.log). Captures the
    ## "forgotten infrastructure" signal: stale hosts running an EOL
    ## distro that have been continuously active for a long time.
    type SummaryInfo: record {
        ts:             time   &log;
        host:           addr   &log;
        distro_key:     string &log;
        version:        string &log;
        eol_date:       string &log;
        days_past_eol:  count  &log &default=0;
        observations:   count  &log;
        first_seen:     time   &log;
        last_seen:      time   &log;
        active_days:    double &log;
        is_persistent:  bool   &log &default=F;
        severity:       string &log &default="Info";
        ## True when the host is on a Linux distro known to ship a kernel
        ## affected by the recent page-cache LPE class (Copy Fail
        ## CVE-2026-31431, Dirty Frag CVE-2026-43284 / CVE-2026-43500),
        ## AND the host is persistent + EOL. EOL hosts almost certainly
        ## have not received the May 2026 patches, so this is a strong
        ## "exploitable in seconds with public PoC" signal.
        kernel_lpe_likely:    bool   &log &default=F;
        ## Comma-separated CVE list when kernel_lpe_likely is true.
        kernel_lpe_cves:      string &log &optional;
    };

    ## How often to flush the per-host EOL summary log. A final flush also
    ## happens at zeek_done so short pcap runs still produce a summary.
    const summary_interval = 1day &redef;

    ## A host is "persistent" once it's been observed across at least this
    ## span. Default: 7 days. Tune down for short captures, up for noisy
    ## environments.
    const persistent_threshold = 7day &redef;

    ## How long per-host EOL state (first_seen / last_seen / observations)
    ## is kept after the host was last seen. Must be comfortably larger
    ## than persistent_threshold, otherwise persistence can never be
    ## established. Refreshed on every observation.
    const state_expire = 30day &redef;

    ## Only hosts seen within this window are written to eol_summary.log
    ## on each flush (no point re-reporting a host that went away).
    const summary_active_window = 2day &redef;

    ## Distros that ship a Linux kernel and are therefore in scope for
    ## the kernel_lpe_likely flag. (FreeBSD excluded - different kernel.)
    const linux_distros: set[string] = {
        "ubuntu", "debian", "rhel", "centos", "centos-stream", "rocky",
        "almalinux", "oracle", "fedora", "opensuse-leap",
        "opensuse-tumbleweed", "sles", "alpine", "arch", "manjaro",
        "gentoo", "nixos",
    } &redef;

    const eol_table: table[string] of string = {
        ["fedora|28"] = "2019-05-28",
        ["fedora|29"] = "2019-11-26",
        ["fedora|30"] = "2020-05-26",
        ["fedora|31"] = "2020-11-24",
        ["fedora|32"] = "2021-05-25",
        ["fedora|33"] = "2021-11-30",
        ["fedora|34"] = "2022-06-07",
        ["fedora|35"] = "2022-12-13",
        ["fedora|36"] = "2023-05-16",
        ["fedora|37"] = "2023-12-05",
        ["fedora|38"] = "2024-05-21",
        ["fedora|39"] = "2024-11-26",
        ["fedora|40"] = "2025-05-13",
        ["fedora|41"] = "2025-12-15",
        ["fedora|42"] = "2026-06-15",
        ["fedora|43"] = "2026-12-15",
        ["fedora|44"] = "2027-06-15",

        ["rhel|6"]  = "2020-11-30",
        ["rhel|7"]  = "2024-06-30",
        ["rhel|8"]  = "2029-05-31",
        ["rhel|9"]  = "2032-05-31",
        ["rhel|10"] = "2035-05-31",

        ["centos|6"]         = "2020-11-30",
        ["centos|7"]         = "2024-06-30",
        ["centos|8"]         = "2021-12-31",
        ["centos-stream|8"]  = "2024-05-31",
        ["centos-stream|9"]  = "2027-05-31",
        ["centos-stream|10"] = "2030-05-31",

        ["rocky|8"]     = "2029-05-31",
        ["rocky|9"]     = "2032-05-31",
        ["rocky|10"]    = "2034-05-31",
        ["almalinux|8"]  = "2029-05-31",
        ["almalinux|9"]  = "2032-05-31",
        ["almalinux|10"] = "2034-05-31",

        ["oracle|6"]  = "2024-03-31",
        ["oracle|7"]  = "2024-12-31",
        ["oracle|8"]  = "2029-07-31",
        ["oracle|9"]  = "2032-06-30",
        ["oracle|10"] = "2035-06-30",

        ["debian|8"]        = "2020-06-30",
        ["debian|9"]        = "2022-07-01",
        ["debian|10"]       = "2024-06-30",
        ["debian|11"]       = "2026-08-31",
        ["debian|12"]       = "2028-06-30",
        ["debian|13"]       = "2030-06-30",   # LTS end; verify
        ["debian|jessie"]   = "2020-06-30",
        ["debian|stretch"]  = "2022-07-01",
        ["debian|buster"]   = "2024-06-30",
        ["debian|bullseye"] = "2026-08-31",
        ["debian|bookworm"] = "2028-06-30",
        ["debian|trixie"]   = "2030-06-30",   # LTS end; verify

        ["ubuntu|14.04"]  = "2019-04-30",
        ["ubuntu|16.04"]  = "2021-04-30",
        ["ubuntu|18.04"]  = "2023-05-31",
        ["ubuntu|19.10"]  = "2020-07-17",
        ["ubuntu|20.04"]  = "2025-05-29",
        ["ubuntu|20.10"]  = "2021-07-22",
        ["ubuntu|21.04"]  = "2022-01-20",
        ["ubuntu|21.10"]  = "2022-07-14",
        ["ubuntu|22.04"]  = "2027-06-01",
        ["ubuntu|22.10"]  = "2023-07-20",
        ["ubuntu|23.04"]  = "2024-01-25",
        ["ubuntu|23.10"]  = "2024-07-11",
        ["ubuntu|24.04"]  = "2029-05-31",
        ["ubuntu|24.10"]  = "2025-07-10",
        # Interim releases get 9 months; 26.04 LTS gets 5 years standard.
        # Dates below are approximate - verify against ubuntu.com/about/release-cycle.
        ["ubuntu|25.04"]  = "2026-01-15",
        ["ubuntu|25.10"]  = "2026-07-09",
        ["ubuntu|26.04"]  = "2031-05-31",
        ["ubuntu|oracular"] = "2025-07-10",
        ["ubuntu|plucky"]   = "2026-01-15",
        ["ubuntu|questing"] = "2026-07-09",
        ["ubuntu|resolute"] = "2031-05-31",
        ["ubuntu|trusty"]  = "2019-04-30",
        ["ubuntu|xenial"]  = "2021-04-30",
        ["ubuntu|bionic"]  = "2023-05-31",
        ["ubuntu|focal"]   = "2025-05-29",
        ["ubuntu|jammy"]   = "2027-06-01",
        ["ubuntu|noble"]   = "2029-05-31",
        ["ubuntu|precise"] = "2017-04-28",

        ["opensuse-leap|15.0"] = "2019-12-03",
        ["opensuse-leap|15.1"] = "2021-02-02",
        ["opensuse-leap|15.2"] = "2021-12-31",
        ["opensuse-leap|15.3"] = "2022-12-31",
        ["opensuse-leap|15.4"] = "2023-12-07",
        ["opensuse-leap|15.5"] = "2024-12-31",
        ["opensuse-leap|15.6"] = "2025-12-31",

        ["sles|12"] = "2027-10-31",
        ["sles|15"] = "2031-07-31",

        ["freebsd|11"] = "2021-09-30",
        ["freebsd|12"] = "2023-12-31",
        ["freebsd|13"] = "2026-04-30",
        ["freebsd|14"] = "2028-11-30",

        ["windows|5.1"] = "2014-04-08",
        ["windows|6.0"] = "2017-04-11",
        ["windows|6.1"] = "2020-01-14",
        ["windows|6.2"] = "2018-01-09",
        ["windows|6.3"] = "2023-01-10",
        # Deliberately NO "windows|10.0": CryptoAPI/10.0 is sent by
        # Windows 10, Windows 11 and Server 2016+ alike, so an EOL date
        # (Win10: 2025-10-14) would flag every modern Windows host.

        ["opensuse-tumbleweed|"] = "",
        ["arch|"]                = "",
        ["manjaro|"]             = "",
        ["gentoo|"]              = "",
        ["nixos|"]               = "",
        ["alpine|"]              = "",
    } &default = "";

    ## Distros for which `eol_table` is keyed by MAJOR version only,
    ## so we truncate "8.10" -> "8" before lookup. (FreeBSD versions look
    ## like "13.2-RELEASE-p4" and are keyed by major too.)
    const major_only_distros: set[string] = {
        "rhel", "centos", "centos-stream", "rocky", "almalinux",
        "oracle", "fedora", "freebsd",
    } &redef;

    ## Edition / spin words that libdnf packs into the `version` field
    ## ("Rocky Linux 8.10; generic; ..."). When we see one of these we
    ## know the real version is hiding in the `os` field instead.
    const edition_words: set[string] = {
        "generic", "workstation", "server", "kde", "container", "cloud",
        "minimal", "desktop", "core", "atomic", "iot", "silverblue",
    } &redef;

    global normalize_distro:         function(os: string): string;
    global recover_version_from_os:  function(os: string): string;
    global looks_like_edition:       function(version: string): bool;
    global eol_lookup_key:           function(distro: string, version: string): string;
    global check_eol:                function(distro: string, version: string, now: time): Info;
}

## Per-day dedup for eol_info.log rows + EOL_Distro_Detected notices.
global reported: set[addr, string, string] &create_expire=eol_dedup_interval;

## All per-(host, distro, version) state in ONE record so the pieces can't
## expire independently. &read_expire is refreshed on every observation, so
## an active host keeps its first_seen and can actually become persistent.
## Only EOL hosts are tracked.
type HostState: record {
    first_seen:    time;
    last_seen:     time;
    observations:  count &default=0;
    eol_date:      string;
    days_past_eol: count;
    severity:      string;
};
global host_state: table[addr, string, string] of HostState
    &read_expire=state_expire;

## eol_table dates pre-parsed once at startup.
global eol_times: table[string] of time;

global flush_summaries: event();
global iso_to_time: function(s: string): time;

event zeek_init() &priority=5
    {
    Log::create_stream(EOLLinux::LOG,
                       [$columns=Info, $path="eol_info"]);
    Log::create_stream(EOLLinux::SUMMARY_LOG,
                       [$columns=SummaryInfo, $path="eol_summary"]);

    for ( k, d in eol_table )
        if ( d != "" )
            eol_times[k] = iso_to_time(d);

    schedule summary_interval { flush_summaries() };
    }

global last_flush: time = double_to_time(0.0);

function write_summaries()
    {
    local now = network_time();
    last_flush = now;
    for ( [h, d, v], st in host_state )
        {
        if ( now - st$last_seen > summary_active_window )
            next;

        local span_i     = st$last_seen - st$first_seen;
        local span       = interval_to_double(span_i) / 86400.0;
        local persistent = span_i >= persistent_threshold;

        local s = SummaryInfo($ts=now, $host=h, $distro_key=d, $version=v,
                              $eol_date=st$eol_date,
                              $days_past_eol=st$days_past_eol,
                              $observations=st$observations,
                              $first_seen=st$first_seen,
                              $last_seen=st$last_seen,
                              $active_days=span, $is_persistent=persistent,
                              $severity=st$severity);

        if ( persistent && d in linux_distros )
            {
            s$kernel_lpe_likely = T;
            s$kernel_lpe_cves   = "CVE-2026-31431,CVE-2026-43284,CVE-2026-43500";
            }

        Log::write(EOLLinux::SUMMARY_LOG, s);

        if ( persistent && raise_notice )
            {
            NOTICE([$note=EOL_Persistent_Host,
                    $src=h,
                    $identifier=fmt("%s|%s|%s", h, d, v),
                    $suppress_for=summary_interval,
                    $msg=fmt("%s %s is EOL (%s, %d days past) and host has been active for %.1f days - likely forgotten%s",
                             d, v, st$eol_date, st$days_past_eol, span,
                             s$kernel_lpe_likely ? " (likely vuln to Copy Fail / Dirty Frag)" : "")]);
            }
        }
    }

event flush_summaries()
    {
    write_summaries();
    schedule summary_interval { flush_summaries() };
    }

event zeek_done()
    {
    # Final flush for short runs, unless a periodic flush just happened.
    if ( network_time() - last_flush >= 1hr )
        write_summaries();
    }

function normalize_distro(os: string): string
    {
    local s = to_lower(os);

    if ( /centos[[:space:]]+stream/ in s ) return "centos-stream";
    if ( /centos/    in s ) return "centos";
    if ( /red[[:space:]]*hat|rhel/ in s ) return "rhel";
    if ( /rocky/     in s ) return "rocky";
    if ( /alma/      in s ) return "almalinux";
    if ( /oracle/    in s ) return "oracle";
    if ( /fedora/    in s ) return "fedora";
    if ( /ubuntu/    in s ) return "ubuntu";
    if ( /debian/    in s ) return "debian";
    if ( /tumbleweed/ in s ) return "opensuse-tumbleweed";
    if ( /leap|opensuse/ in s ) return "opensuse-leap";
    if ( /sles|suse[[:space:]]+linux[[:space:]]+enterprise/ in s ) return "sles";
    if ( /freebsd/   in s ) return "freebsd";
    if ( /alpine/    in s ) return "alpine";
    if ( /arch/      in s ) return "arch";
    if ( /manjaro/   in s ) return "manjaro";
    if ( /gentoo/    in s ) return "gentoo";
    if ( /nixos/     in s ) return "nixos";
    if ( /windows/   in s ) return "windows";

    return "unknown";
    }

## Pulls a trailing version-like token out of an OS string.
## Handles libdnf User-Agents like "Rocky Linux 8.10" / "AlmaLinux 9.7" /
## "Fedora Linux 41" / "CentOS Linux 8". Returns "" if no version-shaped
## token is present.
function recover_version_from_os(os: string): string
    {
    local toks = find_all_ordered(os, /[^[:space:]]+/);
    if ( |toks| == 0 )
        return "";
    local last = toks[|toks|-1];
    if ( /^[0-9]+(\.[0-9]+)*$/ in last )
        return last;
    return "";
    }

## True when the version field carries an "edition" word (libdnf quirk)
## rather than a real version like "8.10" or "noble".
function looks_like_edition(version: string): bool
    {
    return to_lower(version) in edition_words;
    }

## Given a distro id and a version string, return the lookup key we should
## use against eol_table. For RHEL-family distros that means truncating
## "8.10" -> "8".
function eol_lookup_key(distro: string, version: string): string
    {
    local v = version;
    if ( distro in major_only_distros )
        {
        local parts = split_string(v, /\./);
        if ( |parts| > 0 )
            v = parts[0];
        }
    return fmt("%s|%s", distro, v);
    }

## Map days_past_eol into a coarse severity bucket. Mirrors the kind of
## summary Nessus prints for each plugin.
function severity_for(days_past: count, has_eol_date: bool, is_eol_now: bool): string
    {
    if ( ! has_eol_date )
        return "Info";
    if ( ! is_eol_now )
        return "Low";
    if ( days_past >= 1095 ) return "Critical";
    if ( days_past >=  365 ) return "High";
    if ( days_past >=   90 ) return "Medium";
    return "Low";
    }

function support_status_for(days_until_eol: count, is_eol_now: bool, has_eol_date: bool): string
    {
    if ( ! has_eol_date )
        return "rolling";
    if ( is_eol_now )
        return "eol";
    if ( days_until_eol <= 90 )
        return "approaching";
    return "active";
    }

function iso_to_time(s: string): time
    {
    if ( |s| != 10 )
        return double_to_time(0.0);

    local y  = to_count(sub_bytes(s, 1, 4));
    local mo = to_count(sub_bytes(s, 6, 2));
    local d  = to_count(sub_bytes(s, 9, 2));

    local yy  = (mo <= 2) ? y - 1 : y;
    local era = yy / 400;
    local yoe = yy - era * 400;
    local mp  = (mo > 2) ? mo - 3 : mo + 9;
    local doy = (153 * mp + 2) / 5 + d - 1;
    local doe = yoe * 365 + yoe/4 - yoe/100 + doy;
    local days = era * 146097 + doe - 719468;

    return double_to_time(days * 86400.0);
    }

function check_eol(distro: string, version: string, now: time): Info
    {
    local out = Info($ts=now, $host=0.0.0.0, $os="", $version=version,
                     $distro_key=distro, $eol_date="", $is_eol=F);

    local key = eol_lookup_key(distro, version);
    if ( key !in eol_table )
        {
        out$support_status = "unknown";
        out$severity       = "Info";
        return out;
        }

    local eol = eol_table[key];
    out$eol_date = eol;

    if ( eol == "" )
        {
        out$support_status = "rolling";
        out$severity       = "Info";
        return out;
        }

    local eol_t = (key in eol_times) ? eol_times[key] : iso_to_time(eol);
    local days_until_eol: count = 0;
    if ( now > eol_t )
        {
        out$is_eol        = T;
        out$days_past_eol = double_to_count(interval_to_double(now - eol_t) / 86400.0);
        }
    else
        {
        days_until_eol = double_to_count(interval_to_double(eol_t - now) / 86400.0);
        }

    out$severity       = severity_for(out$days_past_eol, T, out$is_eol);
    out$support_status = support_status_for(days_until_eol, out$is_eol, T);
    return out;
    }

hook OSPTracking::os_log_policy(rec: OSPTracking::OSInfo,
                                id: Log::ID,
                                filter: Log::Filter)
    {
    local distro = normalize_distro(rec$os);
    if ( distro == "unknown" )
        return;

    local raw_version = rec?$version ? rec$version : "";

    # Libdnf quirk: when the version field is an edition word, the real
    # version is the trailing token of the os field. This was the cause
    # of ~870 hosts (Rocky/Alma/RHEL/Fedora/Oracle/CentOS) being silently
    # dropped from eol_info.log even though they are clearly visible in
    # os_info.log.
    local effective_version = raw_version;
    if ( raw_version == "" || looks_like_edition(raw_version) )
        {
        local recovered = recover_version_from_os(rec$os);
        if ( recovered != "" )
            effective_version = recovered;
        }

    if ( effective_version == "" )
        return;

    local res = check_eol(distro, effective_version, rec$ts);

    # Only EOL hosts are tracked / logged. Rolling and supported releases
    # cost nothing beyond the lookup above.
    if ( ! res$is_eol )
        return;

    # Update persistence state on EVERY observation (os_info.log emits one
    # row per host/os/version/platform per os_tracking_interval, i.e.
    # roughly daily for an active host), before the per-day dedup below.
    local st: HostState;
    if ( [rec$host, distro, effective_version] in host_state )
        {
        st = host_state[rec$host, distro, effective_version];
        if ( rec$ts > st$last_seen )
            st$last_seen = rec$ts;
        if ( rec$ts < st$first_seen )
            st$first_seen = rec$ts;
        st$days_past_eol = res$days_past_eol;
        st$severity      = res$severity;
        }
    else
        {
        st = HostState($first_seen=rec$ts, $last_seen=rec$ts,
                       $eol_date=res$eol_date,
                       $days_past_eol=res$days_past_eol,
                       $severity=res$severity);
        host_state[rec$host, distro, effective_version] = st;
        }
    st$observations += 1;

    if ( [rec$host, distro, effective_version] in reported )
        return;

    res$observations = st$observations;
    res$last_seen    = st$last_seen;
    res$host = rec$host;
    res$os   = rec$os;
    if ( rec?$platform )
        res$platform = rec$platform;
    if ( rec?$request && rec$request?$user_agent )
        res$user_agent = rec$request$user_agent;

    Log::write(EOLLinux::LOG, res);
    add reported[rec$host, distro, effective_version];

    if ( raise_notice )
        {
        local ua = res?$user_agent ? res$user_agent : "";
        NOTICE([$note=EOL_Distro_Detected,
                $src=rec$host,
                $identifier=fmt("%s|%s|%s", rec$host, distro, effective_version),
                $suppress_for=eol_dedup_interval,
                $msg=fmt("%s %s is end-of-life (EOL %s, %d days past, severity=%s)",
                         distro, effective_version, res$eol_date,
                         res$days_past_eol, res$severity),
                $sub=fmt("ua=%s", ua)]);
        }
    }
