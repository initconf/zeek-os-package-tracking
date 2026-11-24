@load policy/frameworks/software/windows-version-detection.zeek
@load ./os-package-tracking

module OSPTracking;

# NOTE: as far as we know, Windows 11 (and Server 2016/2019/2022/2025) still
# send "Microsoft-CryptoAPI/10.0" - the NT kernel version never moved past
# 10.0. This "11.0" entry is kept in case a build ever sends it, but
# CryptoAPI/10.0 should be read as "Windows 10, 11 or Server 2016+", not
# "Windows 10". For the same reason detect-eol-linux has no EOL date for
# windows|10.0.
redef OS::crypto_api_mapping += {
	["Microsoft-CryptoAPI/11.0"]            = [$name="Windows", $version=[$major=11, $minor=0, $addl="11"]],
};

event HTTP::log_http(rec: HTTP::Info) &priority=5
	{
	# Cheapest test first: this runs for every HTTP transaction.
	if ( ! ( rec?$user_agent && rec?$host ) )
		return;
	if ( /^Microsoft-CryptoAPI\// !in rec$user_agent )
		return;
	if ( /crl\.microsoft\.com/ !in rec$host )
		return;

	local orig = rec$id$orig_h;
	if ( ! addr_matches_host(orig, track_hosts) )
		return;

	local req = RequestInfo($ts=rec$ts, $user_agent=rec$user_agent, $host=rec$host);
	if ( rec?$uri )
		req$uri = rec$uri;

	if ( rec$user_agent !in OS::crypto_api_mapping )
		{
		found_os(orig, "WINDOWS", "Unknown CryptoAPI Version", "WINDOWS", req);
		return;
		}

	local result = OS::crypto_api_mapping[rec$user_agent];

	# "Windows" or e.g. "Windows-7 or Server 2008 R2"
	local name = result$name;
	if ( result$version?$addl )
		name = fmt("%s-%s", result$name, result$version$addl);

	found_os(orig, name, fmt("%s.%s", result$version$major, result$version$minor), "WINDOWS", req);
	}
