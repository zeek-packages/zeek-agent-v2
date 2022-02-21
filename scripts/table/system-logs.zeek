module ZeekAgent_SystemLogs;

export {
	option query_interval = 30 secs;

	## Logging stream identifier for the tables.log.
	redef enum Log::ID += {
		LOG
	};

	## Log messages recorded by the operating systems.
	type Columns: record {
		time_: int &optional &log; ##< timestamp as seconds since epoch
		process: string &optional &log; ##< process name
		level: string &optional &log; ##< severity level
		message: string &optional &log; ##< log message
	};

	type Info: record {
		t: time &log; ##< time received
		hid: string &log; ##< unique ID of originater host
		host: string &log; ##< name of originator
		columns: Columns &log;
	};

	## A default logging policy hook for the table's log stream.
	global log_policy: Log::PolicyHook;
}

event ZeekAgent_SystemLogs::query_result(ctx: ZeekAgent::Context, columns: Columns) {
	local info = Info($t = network_time(), $hid = ctx$agent_id, $host = ZeekAgent::hostname(ctx), $columns = columns);
	Log::write(LOG, info);
}

event zeek_init() {
	local field_name_map = ZeekAgent::log_column_map(Columns, "columns.");
	Log::create_stream(LOG, [$columns = Info, $policy = log_policy]);
	Log::remove_default_filter(LOG);
	Log::add_filter(LOG, [$name = "default", $path = "zeek-agent-system-logs", $field_name_map = field_name_map]);

	ZeekAgent::query([$sql_stmt = "SELECT * FROM system_logs_events", $event_ = query_result, $schedule_ = query_interval, $subscription = ZeekAgent::Events, $requires_tables = set("system_logs_events")]);
}
