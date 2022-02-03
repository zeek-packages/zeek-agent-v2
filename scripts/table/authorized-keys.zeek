module ZeekAgent_AuthorizedKeys;

export {
	## Paths to find `authorized_keys` files in.
	const paths_to_watch = set("/home/*/.ssh/authorized_keys", "/Users/*/.ssh/authorized_keys") &redef;

	## Query frequency.
	option query_interval = 30 secs;

	## Logging stream identifier for the tables.log.
	redef enum Log::ID += {
		LOG
	};

	## Lines of matching key files.
	type Columns: record {
		path: string &optional &log; ##< absolute path
		number: int &optional &log; ##< line number
		content: string &optional &log; ##< content of line
	};

	type Info: record {
		t: time &log; ##< time received
		hid: string &log; ##< unique ID of originater host
		host: string &log; ##< name of originator
		change: string &optional &log; ##< type of change
		columns: Columns &log;
	};

	## A default logging policy hook for the table's log stream.
	global log_policy: Log::PolicyHook;
}

event ZeekAgent_AuthorizedKeys::query_result(ctx: ZeekAgent::Context, columns: Columns) {
	local info = Info($t = network_time(), $hid = ctx$agent_id, $host = ZeekAgent::hostname(ctx), $columns = columns);

	if ( ctx?$change )
		info$change = ZeekAgent::change_type(ctx);

	Log::write(LOG, info);
}

event zeek_init() {
	if ( |paths_to_watch| == 0 )
		return;

	local field_name_map = ZeekAgent::log_column_map(Columns, "columns.");
	Log::create_stream(LOG, [$columns = Info, $policy = log_policy]);
	Log::remove_default_filter(LOG);
	Log::add_filter(LOG, [$name = "default", $path = "zeek-agent-authorized-keys", $field_name_map = field_name_map]);

	for ( p in paths_to_watch ) {
		local stmt = fmt("SELECT * FROM files_lines(\"%s\")", p);
		ZeekAgent::query([$sql_stmt = stmt, $event_ = query_result, $schedule_ = query_interval, $subscription = ZeekAgent::Differences]);
	}
}
