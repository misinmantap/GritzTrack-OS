#  Author : Muhammad Faldih

module Conn;

export {
	option analyzer_inactivity_timeouts: table[Analyzer::Tag] of interval = {
		[[Analyzer::ANALYZER_SSH, Analyzer::ANALYZER_FTP]] = 1 hrs,
	};
	option port_inactivity_timeouts: table[port] of interval = {
		[[21/tcp, 22/tcp, 23/tcp, 513/tcp]] = 1 hrs,
	};

}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count)
	{
	if ( atype in analyzer_inactivity_timeouts )
		set_inactivity_timeout(c$id, analyzer_inactivity_timeouts[atype]);
	}

event connection_established(c: connection)
	{
	local service_port = c$id$resp_p;
	if ( c$orig$state == TCP_INACTIVE )
		{
		if ( service_port !in likely_server_ports && c$id$orig_p in likely_server_ports )
			service_port = c$id$orig_p;
		}

	if ( service_port in port_inactivity_timeouts )
		set_inactivity_timeout(c$id, port_inactivity_timeouts[service_port]);
	}
