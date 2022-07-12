module ZeekAgent_Users;

export {
	## Query frequency.
	option query_interval = 30 secs;

	## Subscription type
	option subscription = ZeekAgent::Differences;

	## Logging stream identifier for the tables.log.
	redef enum Log::ID += { LOG };

	## List of users on system
	type Columns: record {
		name: string &optional &log; ##< short name
		full_name: string &optional &log; ##< full name
		is_admin: bool &optional &log; ##< 1 if user has adminstrative privileges
		is_system: bool &optional &log; ##< 1 if user correponds to OS service
		uid: string &optional &log; ##< user ID
		gid: count &optional &log; ##< group ID
		home: string &optional &log; ##< path to home directory
		shell: string &optional &log; ##< path to default shell
		email: string &optional &log; ##< email address
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

event ZeekAgent_Users::query_result(ctx: ZeekAgent::Context, columns: Columns)
	{
	local info = Info($t=network_time(), $hid=ctx$agent_id,
	    $host=ZeekAgent::hostname(ctx), $columns=columns);

	if ( ctx?$change )
		info$change = ZeekAgent::change_type(ctx);

	Log::write(LOG, info);
	}

event zeek_init()
	{
	local field_name_map = ZeekAgent::log_column_map(Columns, "columns.");
	Log::create_stream(LOG, [$columns=Info, $policy=log_policy]);
	Log::remove_default_filter(LOG);
	Log::add_filter(LOG, [$name="default", $path="zeek-agent-users",
	    $field_name_map=field_name_map]);

	ZeekAgent::query([$sql_stmt="SELECT * FROM users", $event_=query_result,
	    $schedule_=query_interval, $subscription=subscription]);
	}
