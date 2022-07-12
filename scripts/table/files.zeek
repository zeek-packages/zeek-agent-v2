module ZeekAgent_Files;

export {
	## Paths to collect file listings for on all endpoints.
	const paths_to_watch = set("/etc/*", "/etc/*/*") &redef;

	## Query frequency.
	option query_interval = 30 secs;

	## Subscription type
	option subscription = ZeekAgent::Differences;

	## Logging stream identifier for the tables.log.
	redef enum Log::ID += { LOG };

	## File system paths matching one of our patterns.
	type Columns: record {
		path: string &optional &log; ##<  full path
		type_: string &optional &log; ##<  textual description of the path's type (e.g., `file`, `dir`, `socket`)
		uid: count &optional &log; ##<  ID of user owning file
		gid: count &optional &log; ##<  ID if group owning file
		mode: string &optional &log; ##<  octal permission mode
		mtime: time &optional &log; ##<  time of last modification as seconds since epoch
		size: count &optional &log; ##<  file size in bytes
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

event ZeekAgent_Files::query_result(ctx: ZeekAgent::Context, columns: Columns)
	{
	local info = Info($t=network_time(), $hid=ctx$agent_id,
	    $host=ZeekAgent::hostname(ctx), $columns=columns);

	if ( ctx?$change )
		info$change = ZeekAgent::change_type(ctx);

	Log::write(LOG, info);
	}

event zeek_init()
	{
	if ( |paths_to_watch| == 0 )
		return;

	local field_name_map = ZeekAgent::log_column_map(Columns, "columns.");
	Log::create_stream(LOG, [$columns=Info, $policy=log_policy]);
	Log::remove_default_filter(LOG);
	Log::add_filter(LOG, [$name="default", $path="zeek-agent-files",
	    $field_name_map=field_name_map]);

	for ( p in paths_to_watch )
		{
		local stmt = fmt("SELECT * FROM files_list(\"%s\")", p);
		ZeekAgent::query([$sql_stmt=stmt, $event_=query_result,
		    $schedule_=query_interval, $subscription=subscription]);
		}
	}
