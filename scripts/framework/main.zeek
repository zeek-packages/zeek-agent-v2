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
	global query: function(q: Query, scope: Scope &default=Group, target: string &default="all") : string;

	## Cancels a previously sent query with all relevant agents. If the query isn't active anymore (or otherwise not know),
	## the operation is ignored without error message.
	##
	## query_id: the query's ID as returned by ``query()``
	global cancel: function(query_id: string);

	## TODO: Add docs.
	global host_id: function(ctx: Context) : string;

	## TODO: Add docs.
	global hostname: function(ctx: Context) :string;

	## TODO: Add docs.
	global change_type: function(ctx: Context): string;

	## TODO: Add docs.
	global log_column_map: function(rec: any, strip_prefix: string) : table[string] of string;

	## TODO: Add docs.
	global supported_tables: function(hid: string) : set[string];

	## The logging stream identifier for ``zeek-agent.log``.
	redef enum Log::ID += { LOG };

	## Type defining the columns of ``zeek-agent.log``.
	type Info: record {
		ts: time		&log;	##< Zeek's time when log entry was recorded
		type_: string  		&log;	##< type of update
		hid: string		&log;	##< unique ID of host
		hostname: string	&log &optional;	##< agent's hostname
		address: string		&log &optional;	##< agent's address
		version: int            &log &optional;	##< version of Zeek Agent running on host
		uptime: interval	&log &optional;	##< uptime of host
		platform: string	&log &optional;	##< platform of host
		os_name: string 	&log &optional;	##< name of OS on host
	};

	## A default logging policy hook for the ``zeek-agent.log`` stream.
	global log_policy: Log::PolicyHook;

	## Expiration interval for an agent's state after not hearing from it
	## anymore. (Note that this should be longer than the agent's hello interval.)
	option agent_timeout = 10mins;

	## Interval to broadcast ``hello`` events to all connected agents.
	option hello_interval = 60secs;
}

# Unique ID for the current Zeek process.
global zeek_instance: string;

# Internal state per agent.
type Agent: record {
	last_seen: time;
	hello: ZeekAgentAPI::HelloV1;
	hello_id: string;
	};

# Callback for an agent's state expiring.
global agent_expired: function(t: table[string] of Agent, agent_id: string) : interval;

# Table of all currnetly know agents.
global agents: table[string] of Agent &read_expire=agent_timeout &expire_func=agent_expired;

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

	local log : Info = [
		$ts = network_time(),
		$type_ = type_,
		$hid = agent_id
	];

	local hello = agent$hello;

	if ( hello?$hostname )
		log$hostname = hello$hostname;

	if ( hello?$address )
		log$address = hello$address;

	if ( hello?$agent_version )
		log$version = hello$agent_version;

	if ( hello?$uptime)
		log$uptime = double_to_interval(hello$uptime);

	if ( hello?$platform )
		log$platform = hello$platform;

	if ( hello?$os_name )
		log$os_name = hello$os_name;

	Log::write(LOG, log);
	}

function agent_expired(t: table[string] of Agent, agent_id: string) : interval
	{
	log_update(agent_id, "offline");
	return 0secs;
	}

function make_topic(qstate: QueryState, agent_id: string) : string
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
			return fmt("/zeek-agent/query/group/%s/%s", agent_id, to_lower(qstate$target));
		}

	# can't get here
	Reporter::fatal("ZeekAgent::make_topic unreachable");
	}

function send_query_to_agent(query_id: string, agent_id: string)
	{
	local agent = agents[agent_id];
	local qstate = queries[query_id];
	local ev = Broker::make_event(ZeekAgentAPI::install_query_v1, zeek_instance, qstate$query_id, qstate$query);
	Broker::publish(make_topic(qstate, agent_id), ev);
	}

function send_query_to_all_agents(query_id: string)
	{
	local qstate = queries[query_id];
	local ev = Broker::make_event(ZeekAgentAPI::install_query_v1, zeek_instance, qstate$query_id, qstate$query);
	Broker::publish(make_topic(qstate, ""), ev);
	}

function send_all_queries_to_agent(agent_id: string)
	{
	for ( query_id in queries )
		send_query_to_agent(query_id, agent_id);
	}

function send_cancel_to_all_agents(query_id: string)
	{
	local qstate = queries[query_id];
	local ev = Broker::make_event(ZeekAgentAPI::cancel_query_v1, zeek_instance, query_id);
	Broker::publish(make_topic(qstate, ""), ev);
	}

### Public functions

function cancel(query_id: string)
	{
	send_cancel_to_all_agents(query_id);
	}

function query(query: Query, scope: Scope, target: string) : string
	{
	local query_id =  unique_id("za_");
	queries[query_id] = [
		$query_id = query_id,
		$scope = scope,
		$target = target,
		$query = query
		];

	send_query_to_all_agents(query_id);
	return query_id;
	}

function hostname(ctx: Context) : string
	{
	if ( ctx$agent_id !in agents )
		return "<unknown>";

	local agent = agents[ctx$agent_id];

	if ( agent$hello$hostname != "" )
		return agent$hello$hostname;

	if ( agent$hello$address != "" )
		return agent$hello$address;

	return "<unknown>";
	}

function change_type(ctx: Context) : string
	{
	if ( ! ctx?$change )
		return "";

	switch ( ctx$change ) {
		case ZeekAgent::Add: return "new";
		case ZeekAgent::Delete: return "gone";
		}

	return "should-not-happen";
	}

function log_column_map(rec: any, strip_prefix: string) : table[string] of string
	{
	local map: table[string] of string;

	for ( fname in record_fields(rec) )
		map[strip_prefix + fname] = fname;

	return map;
	}

function supported_tables(agent_id: string) : set[string]
	{
	if ( agent_id !in agents )
		return set();

	local tables = split_string(agents[agent_id]$hello$tables, /,/);
	local result: set[string];
	for ( i in tables )
		add result[tables[i]];

	return result;
	}

### Event handlers

event send_zeek_hello()
	{
	local ev = Broker::make_event(ZeekAgentAPI::zeek_hello_v1, zeek_instance);
	Broker::publish("/zeek-agent/query/group/all", ev);

	schedule hello_interval { send_zeek_hello() };
	}

event zeek_init() &priority=100
	{
	zeek_instance = unique_id("zeek_");
 	Log::create_stream(LOG, [$columns=Info, $path="zeek-agent", $policy=log_policy]);
	}

event zeek_init() &priority=-10
	{
	Broker::listen();
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

event ZeekAgentAPI::agent_hello_v1(ctx: ZeekAgent::Context, columns: ZeekAgentAPI::HelloV1)
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
		else {
			# When the query ID changes, the agent reconnected and
			# needs a new copy of its query state.
			log_update(agent_id, "reconnect");
			send_all_queries_to_agent(agent_id);
			}
		}
	else {
		agents[agent_id] = [$last_seen=network_time(), $hello_id=ctx$query_id, $hello=columns];
		log_update(agent_id, "join");
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
