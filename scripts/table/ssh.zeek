module ZeekAgent_SSH;

export {
	## Paths to find `authorized_keys` files in.
	option key_paths_to_watch = set("/home/*/.ssh/authorized_keys",
	    "/Users/*/.ssh/authorized_keys");

	## Query frequency.
	option query_interval = 30 secs;

	## Subscription type
	option subscription = ZeekAgent::Differences;

	## Logging stream identifier for the tables.log.
	redef enum Log::ID += {
		LOG_KEYS
	};

	## Lines from matching key files.
	type ColumnsKeys: record {
		path: string &optional &log; ##< absolute path
		number: count &optional &log; ##< line number
		content: string &optional &log; ##< content of line
	};

	## Information logged for key files.
	type InfoKeys: record {
		t: time &log; ##< time received
		hid: string &log; ##< unique ID of originater host
		host: string &log; ##< name of originator
		change: string &optional &log; ##< type of change
		columns: ColumnsKeys &log;
	};

	## A default logging policy hook for the table's keys log stream.
	global log_policy_keys: Log::PolicyHook;
}

event ZeekAgent_SSH::query_result_keys(ctx: ZeekAgent::Context,
    columns: ColumnsKeys)
{
	local info = InfoKeys(
	    $t=network_time(),
	    $hid=ctx$agent_id,
	    $host=ZeekAgent::hostname(ctx),
	    $columns=columns);

	if ( ctx?$change )
		info$change = ZeekAgent::change_type(ctx);

	Log::write(LOG_KEYS, info);
}

event zeek_init()
{
	if ( |key_paths_to_watch| == 0 )
		return;

	local field_name_map = ZeekAgent::log_column_map(ColumnsKeys, "columns.");
	Log::create_stream(LOG_KEYS, [$columns=InfoKeys, $policy=log_policy_keys]);
	Log::remove_default_filter(LOG_KEYS);
	Log::add_filter(LOG_KEYS, [
	    $name="default",
	    $path="zeek-agent-ssh-authorized-keys",
	    $field_name_map=field_name_map]);

	for ( p in key_paths_to_watch ) {
		local stmt = fmt("SELECT * FROM files_lines(\"%s\")", p);
		ZeekAgent::query([
		    $sql_stmt=stmt,
		    $event_=query_result_keys,
		    $schedule_=query_interval,
		    $subscription=subscription]);
	}
}
