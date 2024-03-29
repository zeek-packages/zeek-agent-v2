##! Framekwork for interfacing with external Zeek Agent instances.
##!
##! This framework provides the API for installing queries with a set of
##! agents, and receiving their results.

@load ./types
@load ./api

module ZeekAgent;

export {
	## Send a query to connected agents.
	##
	## Note that this operation will always succeed at first, but errors
	## may come back from the agents and will be logged through the
	## reporter if there's an issue with the query (such as the SQL
	## statement being ill-formed).
	##
	## q: query to send
	##
	## scope: scope of query determining whether to send to a group of agents, or an individual one
	##
	## target: if ``scope`` is group, the name of the group, with ``all``
	## meaning all connected agent; if ``scope`` is host, the ID (UUID) of
	## the target agent
	##
	## Returns: a unique ID for the query that can be used to later cancel it
	global query: function(q: Query, scope: Scope &default=Group, target: string
	    &default="all"): string;

	## Cancels a previously sent query with all relevant agents. If the query isn't active anymore (or otherwise not know),
	## the operation is ignored without error message.
	##
	## query_id: the query's ID as returned by ``query()``
	global cancel: function(query_id: string);

	## Given the query context from an incoming agent result, returns the
	## unique ID of the originating host system.
	global host_id: function(ctx: Context): string;

	## Given the query context from an incoming agent result, returns the
	## they hostname of the originating host system.
	global hostname: function(ctx: Context): string;

	## Given the query context from an incoming agent result, return
	## a human-readable representation of the type of change suitable for
	## logging.
	global change_type: function(ctx: Context): string;

	## Returns a set of tables that an agent provides.
	##
	## hid: unique of host to return tables for (which must be connected)
	##
	## Returns: set of tables names; empty if host isn't known/connected
	global supported_tables: function(hid: string): set[string];

	## Helper function that computes a mapping for the logging framework
	## that strips a common prefix from all column names.
	##
	## rec: record type representing the columns to be logged
	## strip_prefix: a common prefix to strip from logged column names
	##
	## Returns: table with one entry per record field, mapping
	## `<prefix>.<field-name>` to `<field-name>`.
	global log_column_map: function(rec: any, strip_prefix: string): table[string] of
	    string;

	## The logging stream identifier for ``zeek-agent.log``.
	redef enum Log::ID += { LOG };

	## Type defining the columns of ``zeek-agent.log``.
	type Info: record {
		ts: time &log; ##< Zeek's time when log entry was recorded
		type_: string &log; ##< type of update
		hid: string &log; ##< unique ID of host
		hostname: string &log &optional; ##< agent's hostname
		addresses: set[addr] &log &optional; ##< agent's primary addresses
		version: int &log &optional; ##< version of Zeek Agent running on host
		uptime: interval &log &optional; ##< uptime of host
		platform: string &log &optional; ##< platform of host
		os_name: string &log &optional; ##< name of OS on host
	};

	## A default logging policy hook for the ``zeek-agent.log`` stream.
	global log_policy: Log::PolicyHook;

	## Expiration interval for an agent's state after not hearing from it
	## anymore. (Note that this should be longer than the agent's hello interval.)
	option agent_timeout = 10mins;

	## Interval to broadcast ``hello`` events to all connected agents.
	option hello_interval = 60secs;

@if ( Version::number < 50000 )
	## If non-zero and we are on Zeek < 5.0, listen on this port for
	## incoming Broker connections.
	##
	## We use our own port for incoming connections here because
	## ZeekControl changes the default Broker port based on node type, but
	## we need a well-known port for the agents to connect to.
	##
	## If we are on Zeek >= 5.0, we instead activate its WebSocket support
	## on the default port.
	option listen_port = 9998/tcp;

	## Default address on which to listen; empty for any interface, which
	## is the default.
	option listen_address = Broker::default_listen_address;

	## Default interval to retry listening on a port if it's currently in
	## use already.
	option listen_retry = Broker::default_listen_retry;
@endif
}

# Unique ID for the current Zeek process.
global zeek_instance: string;

# This is generated by zkg.
const package_version_file = @DIR + "/../version.dat";

# Package version. Read from `version.dat` if available.
global package_version: string = "";

# Internal state per agent.
type Agent: record {
	last_seen: time;
	hello: ZeekAgentAPI::AgentHelloV1;
	hello_id: string;
};

# Callback for an agent's state expiring.
global agent_expired: function(t: table[string] of Agent, agent_id: string)
    : interval;

# Table of all currnetly know agents.
global agents: table[string] of Agent &read_expire=agent_timeout
    &expire_func=agent_expired;

# Internal state per active query.
type QueryState: record {
	query_id: string;
	scope: Scope;
	target: string;
	query: Query;
};

# Table of all currently active queries.
global queries: table[string] of QueryState;

### Internal helper functions

function log_update(agent_id: string, type_: string)
	{
	# Callers guarantee that the ID is in the table.
	local agent = agents[agent_id];

	local log: Info = [ $ts=network_time(), $type_=type_, $hid=agent_id ];

	local hello = agent$hello;

	if ( hello?$hostname )
		log$hostname = hello$hostname;

	if ( hello?$addresses )
		log$addresses = hello$addresses;

	if ( hello?$agent_version )
		log$version = hello$agent_version;

	if ( hello?$uptime )
		log$uptime = hello$uptime;

	if ( hello?$platform )
		log$platform = hello$platform;

	if ( hello?$os_name )
		log$os_name = hello$os_name;

	Log::write(LOG, log);
	}

function agent_expired(t: table[string] of Agent, agent_id: string): interval
	{
	log_update(agent_id, "offline");
	return 0secs;
	}

function make_topic(qstate: QueryState, agent_id: string): string
	{
	if ( qstate$scope == Host )
		return fmt("/zeek-agent/query/host/%s", agent_id);

	if ( qstate$scope == Group )
		{
		if ( agent_id == "" )
			# Group-wide broadcast
			return fmt("/zeek-agent/query/group/%s", to_lower(qstate$target));
		else
			# Group message to individual host only, if subscribed.
			return fmt("/zeek-agent/query/group/%s/%s", agent_id, to_lower(
			    qstate$target));
		}

	# can't get here
	Reporter::fatal("ZeekAgent::make_topic unreachable");
	}

function send_query_to_agent(query_id: string, agent_id: string)
	{
	local agent = agents[agent_id];
	local qstate = queries[query_id];
	local ev = Broker::make_event(ZeekAgentAPI::install_query_v1, zeek_instance,
	    qstate$query_id, qstate$query);
	Broker::publish(make_topic(qstate, agent_id), ev);
	}

function send_query_to_all_agents(query_id: string)
	{
	local qstate = queries[query_id];
	local ev = Broker::make_event(ZeekAgentAPI::install_query_v1, zeek_instance,
	    qstate$query_id, qstate$query);
	Broker::publish(make_topic(qstate, ""), ev);
	}

function send_hello_to_agent(agent_id: string)
	{
	local hello: ZeekAgentAPI::ZeekHelloV1 = [ $version_string=zeek_version(),
	    $version_number=Version::number, $package_version=package_version ];
	local ev = Broker::make_event(ZeekAgentAPI::zeek_hello_v1, zeek_instance,
	    hello);
	Broker::publish(fmt("/zeek-agent/query/host/%s", agent_id), ev);
	}

function send_hello_to_all_agents()
	{
	local hello: ZeekAgentAPI::ZeekHelloV1 = [ $version_string=zeek_version(),
	    $version_number=Version::number, $package_version=package_version ];
	local ev = Broker::make_event(ZeekAgentAPI::zeek_hello_v1, zeek_instance,
	    hello);
	Broker::publish("/zeek-agent/query/group/all", ev);
	}

function send_all_queries_to_agent(agent_id: string)
	{
	for ( query_id in queries )
		send_query_to_agent(query_id, agent_id);
	}

function send_cancel_to_all_agents(query_id: string)
	{
	local qstate = queries[query_id];
	local ev = Broker::make_event(ZeekAgentAPI::cancel_query_v1, zeek_instance,
	    query_id);
	Broker::publish(make_topic(qstate, ""), ev);
	}

### Public functions

function cancel(query_id: string)
	{
	send_cancel_to_all_agents(query_id);
	}

function query(query: Query, scope: Scope, target: string): string
	{
	local query_id = unique_id("za_");
	queries[query_id] = [ $query_id=query_id, $scope=scope, $target=target,
	    $query=query ];

	send_query_to_all_agents(query_id);
	return query_id;
	}

function hostname(ctx: Context): string
	{
	if ( ctx$agent_id !in agents )
		return "<unknown>";

	local agent = agents[ctx$agent_id];

	if ( agent$hello?$hostname && agent$hello$hostname != "" )
		return agent$hello$hostname;

	if ( agent$hello?$addresses && |agent$hello$addresses| > 0 )
		{
		for ( a in agent$hello$addresses )
			return fmt("%s", a);
		}

	return "<unknown>";
	}

function change_type(ctx: Context): string
	{
	if ( ! ctx?$change )
		return "";

	switch ( ctx$change )
		{
		case ZeekAgent::Add:
			return "new";
		case ZeekAgent::Delete:
			return "gone";
		}

	return "should-not-happen";
	}

function log_column_map(rec: any, strip_prefix: string): table[string] of string
	{
	local map: table[string] of string;

	for ( fname in record_fields(rec) )
		map[strip_prefix + fname] = fname;

	return map;
	}

function supported_tables(agent_id: string): set[string]
	{
	if ( agent_id in agents )
		return agents[agent_id]$hello$tables;
	else
		return set();
	}

### Event handlers

type PackageVersionLine: record {
	version: string;
};

event package_version_line(description: Input::EventDescription,
    ev: Input::Event, line: string)
	{
	if ( line != "" )
		package_version = line;
	}

event send_zeek_hello()
	{
	send_hello_to_all_agents();
	schedule hello_interval { send_zeek_hello() };
	}

event zeek_init() &priority=100
	{
	zeek_instance = unique_id("zeek_");
	Log::create_stream(LOG, [ $columns=Info, $path="zeek-agent", $policy=log_policy ]);

	if ( file_size(package_version_file) > 0 )
		Input::add_event([ $source=package_version_file, $reader=Input::READER_RAW,
		    $mode=Input::MANUAL, $name="package_version",
		    $fields=PackageVersionLine, $ev=package_version_line,
		    $want_record=F ]);
	}

event zeek_init() &priority=-10
	{
@if ( Version::number >= 50000 )
	if ( Broker::default_listen_address_websocket != "" )
		Broker::listen_websocket();
	else
		# Default is 127.0.0.1, which isn't very helpful for us.
		Broker::listen_websocket("0.0.0.0");
@else
	if ( listen_port != 0/tcp )
		Broker::listen(listen_address, listen_port, listen_retry);
@endif

	Broker::subscribe("/zeek-agent/response/all");
	Broker::subscribe(fmt("/zeek-agent/response/%s/", zeek_instance));

	schedule hello_interval { send_zeek_hello() };
	}

event zeek_done()
	{
	# This is best-effort, the message may not make it out anymore.
	# But the agents will eventually timeout their state once they don't
	# hear from us anymore.
	for ( query_id in queries )
		send_cancel_to_all_agents(query_id);

	local ev = Broker::make_event(ZeekAgentAPI::zeek_shutdown_v1, zeek_instance);
	Broker::publish("/zeek-agent/query/group/all", ev);
	}

event ZeekAgentAPI::agent_hello_v1(ctx: ZeekAgent::Context,
    columns: ZeekAgentAPI::AgentHelloV1)
	{
	local agent_id = ctx$agent_id;

	if ( agent_id in agents )
		{
		local agent = agents[agent_id];
		local old_hello_id = agent$hello_id;
		agent$last_seen = network_time();
		agent$hello = columns;
		agent$hello_id = ctx$query_id;

		if ( agent$hello_id == old_hello_id )
			# No change, nothing to do (but table expiration will have been bumped).
			log_update(agent_id, "update");
		else
			{
			# When the query ID changes, the agent reconnected and
			# needs a new copy of its query state.
			log_update(agent_id, "reconnect");
			send_hello_to_agent(agent_id);
			send_all_queries_to_agent(agent_id);
			}
		}
	else
		{
		agents[agent_id] = [ $last_seen=network_time(), $hello_id=ctx$query_id,
		    $hello=columns ];
		log_update(agent_id, "join");
		send_hello_to_agent(agent_id);
		send_all_queries_to_agent(agent_id);
		return;
		}
	}

event ZeekAgentAPI::agent_shutdown_v1(ctx: ZeekAgent::Context)
	{
	local agent_id = ctx$agent_id;

	if ( agent_id in agents )
		log_update(agent_id, "shutdown");
	}

event ZeekAgentAPI::agent_error_v1(ctx: ZeekAgent::Context, msg: string)
	{
	Reporter::error(fmt("error from Zeek Agent: %s [%s]", msg, ctx$agent_id));
	}
