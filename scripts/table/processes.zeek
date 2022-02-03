module ZeekAgent_Processes;

export {
	option query_interval = 30 secs;

	## Logging stream identifier for the tables.log.
	redef enum Log::ID += {
		LOG
	};

	type Columns: record {
		name: string &optional &log;
		pid: int &optional &log;
		uid: int &optional &log;
		gid: int &optional &log;
		ppid: int &optional &log;
		priority: int &optional &log;
		startup: int &optional &log;
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

event ZeekAgent_Processes::query_result(ctx: ZeekAgent::Context, columns: Columns) {
	local info = Info($t = network_time(), $hid = ctx$agent_id, $host = ZeekAgent::hostname(ctx), $columns = columns);

	if ( ctx?$change )
		info$change = ZeekAgent::change_type(ctx);

	Log::write(LOG, info);
}

event zeek_init() {
	local field_name_map = ZeekAgent::log_column_map(Columns, "columns.");
	Log::create_stream(LOG, [$columns = Info, $policy = log_policy]);
	Log::remove_default_filter(LOG);
	Log::add_filter(LOG, [$name = "default", $path = "zeek-agent-processes", $field_name_map = field_name_map]);

	ZeekAgent::query([$sql_stmt = "SELECT name,pid,uid,gid,ppid,priority,startup FROM processes", $event_ = query_result, $schedule_ = query_interval, $subscription = ZeekAgent::Differences]);
}
