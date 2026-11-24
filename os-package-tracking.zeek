# The goal of this script is to detect operating systems and packages installed on said operating systems.
# This script specifically focusses on unix-like systems that use package managers. At the moment this mostly
# encompasses a range of linux distributions, as well as FreeBSD systems.

module OSPTracking;

export {
	redef enum Log::ID += { OS_Log, Package_Log };

	global os_log_policy: Log::PolicyHook;
	global package_log_policy: Log::PolicyHook;

	## The categoty of hosts of which you would like to track the likely operating systems and packages that they
	## download.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS
	##
	## NOTE: if your site serves a public Debian/Ubuntu/Rocky/FreeBSD mirror,
	## ALL_HOSTS will track every external client of that mirror. In that
	## case set this to LOCAL_HOSTS (and make sure Site::local_nets is set).
	option track_hosts = ALL_HOSTS;

	## Duration for which per-host operating system information is stored and used for de-duplication on worker nodes.
	const os_tracking_interval = 1day;

	type RequestInfo: record {
		ts: time &default=network_time();
		user_agent: string &optional &log;
		host: string &optional &log;
		uri: string &optional &log;
	};

	type OSInfo: record {
		ts: time &log &default=network_time();
		host: addr &log;
		os: string &log;
		version: string &log &optional;
		platform: string &log &optional;
		request: RequestInfo &log &default=RequestInfo();
	};

	type PackageInfo: record {
		ts: time &log &default=network_time();
		host: addr &log;
		os: string &log &optional;
		os_version: string &log &optional;
		platform: string &log &optional;
		package: string &log;
		version: string &log;
		prev_version: string &log &optional;
		request: RequestInfo &log;
	};
}


global known_os: set[addr, string, string, string] &create_expire=os_tracking_interval;

## Last OS (name + version) seen for a host via a package-manager request.
## Used to attach an os_version to package rows whose URI doesn't carry
## one (Debian/Ubuntu pool/ downloads). One small entry per tracked host,
## expired once the host stops talking to package mirrors.
type HostOS: record {
	os: string;
	version: string;
};
global host_os: table[addr] of HostOS &read_expire=os_tracking_interval;

event zeek_init() &priority=5
	{
	Log::create_stream(OSPTracking::OS_Log, [$columns=OSInfo, $path="os_info", $policy=os_log_policy]);
	Log::create_stream(OSPTracking::Package_Log, [$columns=PackageInfo, $path="package_info", $policy=package_log_policy]);
	}

function found_os(orig: addr, name: string, version: string, platform: string, r: RequestInfo)
	{
	if ( [orig, name, version, platform] in known_os )
		return;

	# TODO: cluster-aware deduping...
	local osi = OSInfo($ts=r$ts, $host=orig, $os=name, $request=r);
	if ( version != "" )
		osi$version = version;
	if ( platform != "" )
		osi$platform = platform;
	Log::write(OSPTracking::OS_Log, osi);

	add known_os[orig, name, version, platform];
	}

## found_os() plus remembering the host's OS version for later package rows.
## Only used for unix package managers (not Windows CryptoAPI) so the
## host_os table stays limited to hosts that actually download packages.
function found_unix_os(orig: addr, name: string, version: string, platform: string, r: RequestInfo)
	{
	if ( version != "" )
		{
		# Only allocate when something changed; reading also refreshes
		# the &read_expire timer.
		if ( orig !in host_os || host_os[orig]$os != name || host_os[orig]$version != version )
			host_os[orig] = HostOS($os=name, $version=version);
		}

	found_os(orig, name, version, platform, r);
	}

type PackageVersion: record {
	name: string;
	version: string;
	platform: string &optional;
	invalid: bool &default=T;
};

function parse_freebsd_package_version(p: string): PackageVersion
	{
	local version = sub_bytes(find_last(p, /-.*/), 2, -1);
	local package = sub_bytes(p, 1, |p|-|version|-1);
	local v = PackageVersion($name=package, $version=version);
	if ( version != "" && package != "" )
		v$invalid = F;
	return v;
	}

## Debian packages have the form: name_version_arch(.deb already stripped).
## The caller must pass a URI-decoded name: epochs show up on the wire as
## "%3a" (e.g. openssh-server_1%3a9.2p1-2+deb12u3_amd64.deb).
function parse_debian_package_version(n: string): PackageVersion
	{
	local p = PackageVersion($name="", $version="");
	local parts = split_string(n, /_/);
	if ( |parts| >= 3 )
		{
		local platform = parts[|parts|-1];
		p$version = parts[|parts|-2];
		p$name = join_string_vec(parts[0:|parts|-2], "_");
		if ( platform != "all" )
			p$platform = platform;
		if ( p$name != "" && p$version != "" )
			p$invalid = F;
		}
	return p;
	}

## RPM packages have the form: name-version-release.arch (.rpm already
## stripped). The name itself may contain "-<digit>" (java-1.8.0-openjdk,
## compat-openssl10, ...) so we split from the RIGHT: the last two
## dash-separated fields are version and release.arch.
## version is reported as "version-release.arch" (unchanged log format).
function parse_rpm_package_version(n: string): PackageVersion
	{
	local p = PackageVersion($name="", $version="");
	local parts = split_string(n, /-/);
	if ( |parts| < 3 )
		return p;

	p$name = join_string_vec(parts[0:|parts|-2], "-");
	p$version = parts[|parts|-2] + "-" + parts[|parts|-1];
	if ( p$name != "" && parts[|parts|-2] != "" && parts[|parts|-1] != "" )
		p$invalid = F;
	return p;
	}

function found_package(orig: addr, o: OSInfo, p: PackageVersion, r: RequestInfo)
	{
	if ( p$invalid )
		return;

	local pi = PackageInfo($ts=r$ts, $host=orig, $package=p$name, $version=p$version, $request=r);
	if ( o?$os )
		pi$os = o$os;
	if ( o?$version )
		pi$os_version = o$version;
	else if ( orig in host_os && host_os[orig]$os == o$os )
		# The pool/ URI doesn't name the release; borrow it from the
		# dists/ request apt made moments earlier.
		pi$os_version = host_os[orig]$version;
	if ( o?$platform )
		pi$platform = o$platform;
	if ( p?$platform )
		pi$platform = p$platform;
	Log::write(OSPTracking::Package_Log, pi);
	}

## First "binary-<arch>" path component, or "".
function apt_platform(parts: string_vec): string
	{
	for ( _, part in parts )
		if ( /^binary-/ in part )
			return sub_bytes(part, 8, -1);
	return "";
	}

## "noble-updates" -> "noble", "bookworm-security" -> "bookworm",
## "buster" -> "buster".
function suite_to_release(suite: string): string
	{
	local idx = strstr(suite, "-");
	if ( idx == 0 )
		return suite;
	return sub_bytes(suite, 1, idx - 1);
	}

## Debian and Ubuntu (apt). Handles:
##   /debian/dists/<suite>/...                 /debian/pool/.../x.deb
##   /debian-security/dists/<rel>-security/... (bookworm and newer)
##   /debian-security/dists/<rel>/updates/...  (buster and older)
##   /debian-security/pool/updates/.../x.deb
##   /ubuntu/dists/<suite>/...                 /ubuntu/pool/.../x.deb
##   /ubuntu-ports/...                          (arm64, ppc64el, ...)
function handle_apt(orig: addr, uri: string, req: RequestInfo)
	{
	local os = "";
	if ( /^\/debian(-security)?\// in uri )
		os = "Debian";
	else if ( /^\/ubuntu(-ports)?\// in uri )
		os = "Ubuntu";
	else
		return;

	local parts = find_all_ordered(uri, /[^\/]+/);
	if ( |parts| < 3 )
		return;

	if ( parts[1] == "dists" )
		{
		local release = suite_to_release(parts[2]);
		if ( release != "" )
			found_unix_os(orig, os, release, apt_platform(parts), req);
		return;
		}

	if ( parts[1] == "pool" && /\.deb$/ in parts[|parts|-1] )
		{
		local fname = unescape_URI(parts[|parts|-1]);
		local pi = parse_debian_package_version(sub_bytes(fname, 1, |fname|-4));
		if ( ! pi$invalid )
			found_package(orig, OSInfo($host=orig, $os=os, $request=req), pi, req);
		}
	}

function handle_freebsd(orig: addr, ua: string, uri: string, req: RequestInfo)
	{
	# FreeBSD. We should be able to get the version from this. First - let's see if the user-agent is formatted the way we assume
	if ( /freebsd-update \(.*, .*\)/ in ua )
		{
		# ok, let's try to extract the OS-version.
		local freebsd_version = find_last(ua, /,.*\)/);
		freebsd_version = sub_bytes(freebsd_version, 3, |freebsd_version|-3);
		# sadly, we can't really get any more from this - at least not on a casual glance. The files downloaded using freebsd-updates
		# just use random hashes as filenames.
		# TODO: We might be able to extract the platform here.
		found_unix_os(orig, "FreeBSD", freebsd_version, "", req);
		}

	# let's be rather simple here - and just check if the file-name ends in .txz
	if ( /\.txz$/ !in uri )
		return;

	local filename = sub_bytes(find_last(uri, /\/.*/), 2, -1);
	# this means we have the package
	local package = sub_bytes(filename, 0, |filename|-4);
	if ( package == "" || package == "packagesite" )
		# packagesite is the repo catalogue, not a package
		return;

	local osi = OSInfo($host=orig, $os="FreeBSD", $request=req);
	local pv = parse_freebsd_package_version(package);

	if ( /^\/FreeBSD:/ in uri )
		{
		# /FreeBSD:13:amd64/... - it is just the slightest bit brittle
		local out = find_all_ordered(uri, /[^\/:]+/);
		if ( |out| > 3 )
			{
			osi$version=out[1];
			osi$platform=out[2];
			}
		}

	if ( ! pv$invalid )
		found_package(orig, osi, pv, req);

	# TODO: pkg also contains a bit of information about the OS-version. We should extract that
	}

function handle_libdnf(orig: addr, ua: string, uri: string, req: RequestInfo)
	{
	# UA shape: "libdnf (Rocky Linux 8.10; generic; Linux.x86_64)"
	# After sub_bytes(.., 9, -1) we are inside the parens; splitting on
	# /[^;)]+/ yields three tokens:
	#   parts[0] = "Rocky Linux 8.10"   (OS name + OS version)
	#   parts[1] = " generic"           (edition / spin)
	#   parts[2] = " Linux.x86_64"      (kernel.arch)
	#
	# The OS version is the LAST whitespace-separated token of parts[0]
	# when it looks like a version (digits, optionally dotted). If we
	# don't peel it off, downstream consumers (e.g. detect-eol-linux)
	# get version="generic" and silently drop the host.
	local parts = find_all_ordered(sub_bytes(ua, 9, -1), /[^;)]+/);
	if ( |parts| != 3 || /Linux/ !in parts[0] )
		return;

	local os_name    = parts[0];
	local os_version = "";
	local edition    = sub_bytes(parts[1], 2, -1);
	local arch       = sub_bytes(parts[2], 2, -1);

	local name_toks = split_string(parts[0], /[[:space:]]+/);
	if ( |name_toks| >= 2 )
		{
		local last_tok = name_toks[|name_toks|-1];
		if ( /^[0-9]+(\.[0-9]+)*$/ in last_tok )
			{
			os_version = last_tok;
			# Rebuild os_name without the trailing version token.
			os_name = sub_bytes(parts[0], 1, |parts[0]| - |last_tok| - 1);
			}
		}

	# Fall back to the old behaviour if we couldn't recover a
	# version (preserves backwards compatibility for unfamiliar
	# libdnf variants).
	if ( os_version == "" )
		os_version = edition;

	found_unix_os(orig, os_name, os_version, arch, req);

	if ( /\.rpm$/ in uri )
		{
		local fname = unescape_URI(sub_bytes(find_last(uri, /\/.*/), 2, -1));
		local pi = parse_rpm_package_version(sub_bytes(fname, 1, |fname|-4));
		if ( pi$invalid )
			return;
		local osi = OSInfo($host=orig, $os=os_name, $platform=arch, $request=req);
		if ( os_version != "" )
			osi$version = os_version;
		found_package(orig, osi, pi, req);
		}
	}

# For now - let's be a bit lazy and get the information we want out of the http logging event.
#
# This handler runs for EVERY HTTP transaction on the sensor, so it does the
# cheapest possible User-Agent test first and bails out before doing any
# regex work on the URI or allocating records. Fedora, by default, uses
# HTTPS, so it is mostly invisible here.
event HTTP::log_http(i: HTTP::Info)
	{
	if ( ! ( i?$user_agent && i?$host && i?$uri ) )
		return;

	local ua = i$user_agent;
	local kind = 0;
	if ( "Debian APT-HTTP" in ua )
		kind = 1;
	else if ( /^(freebsd-update|pkg\/)/ in ua )
		kind = 2;
	else if ( /^libdnf / in ua )
		kind = 3;
	else
		return;

	local orig = i$id$orig_h;
	if ( ! addr_matches_host(orig, track_hosts) )
		return;

	local req = RequestInfo($ts=i$ts, $user_agent=ua, $host=i$host, $uri=i$uri);

	switch ( kind ) {
	case 1:
		handle_apt(orig, i$uri, req);
		break;
	case 2:
		handle_freebsd(orig, ua, i$uri, req);
		break;
	case 3:
		handle_libdnf(orig, ua, i$uri, req);
		break;
	}
	}
