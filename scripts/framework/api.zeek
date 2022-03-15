##! Internal API between Zeek and Zeek Agent.
##!
##! Note that some of the public types inside the ZeekAgent namespace are part
##! of the API as well.

@load ./types

module ZeekAgentAPI;

export {
	## Agent-side ``hello`` record broadcasted regularly by all agents.
	##
	## The record's field correspond directly to the agents' `zeek_agent`
	## table.
	type AgentHelloV1: record {
		agent_id: string;
		instance_id: string;
		hostname: string &optional;
		addresses: set[addr] &optional;
		platform: string &optional;
		os_name: string &optional;
		kernel_name: string &optional;
		kernel_version: string &optional;
		kernel_arch: string &optional;
		agent_version: count &optional;
		broker: string &optional;
		uptime: interval &optional;
		tables: set[string] &optional;
	};

	## Zeek-side ``hello`` record broadcasted regularly by Zeek to all clients.
	type ZeekHelloV1: record {
		version_string: string; ##< Zeek version string
		version_number: count; ##< Numerical Zeek version
		package_version: string; ##< ZeekAgent package version string if known, or empty otherwise
	};

	## Regularly broadcasted by all connected agents.
	global agent_hello_v1: event(ctx: ZeekAgent::Context, columns: AgentHelloV1);

	## Broadcasted by agents on regular shutdown.
	global agent_shutdown_v1: event(ctx: ZeekAgent::Context);

	## Send to Zeek by an agent if it encountered an error with a query.
	global agent_error_v1: event(ctx: ZeekAgent::Context, msg: string);

	## Regularly broadcasted by Zeek.
	global zeek_hello_v1: event(zeek_instance: string, info: ZeekHelloV1);

	## Broadcasted by Zeek on regular shutdown.
	global zeek_shutdown_v1: event(zeek_instance: string);

	## Sends query to agents.
	global install_query_v1: event(zeek_instance: string, query_id: string,
	    query: ZeekAgent::Query);

	## Cancels a previously sent query with agents.
	global cancel_query_v1: event(zeek_instance: string, query_id: string);
}
