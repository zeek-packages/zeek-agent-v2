module ZeekAgent_Sockets;

export {
	## Query frequency.
	option query_interval = 30 secs;

	## Subscription type
	option subscription = ZeekAgent::Differences;

	## Logging stream identifier for the tables.log.
	redef enum Log::ID += {
		LOG
	};

	## Open network sockets.
	type Columns: record {
		pid: count &optional &log; ##< ID of process holding socket
		process: string &optional &log; ##< name of process holding socket
		family: string &optional &log; ##< `IPv4` or `IPv6`
		protocol: count &optional &log; ##< transport protocol
		local_addr: addr &optional &log; ##< local IP address
		local_port: count &optional &log; ##< local port number
		remote_addr: addr &optional &log; ##< remote IP address
		remote_port: count &optional &log; ##< remote port number
		state: string &optional &log; ##< state of socket
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

event ZeekAgent_Sockets::query_result(ctx: ZeekAgent::Context, columns: Columns)
{
	local info = Info(
	    $t=network_time(),
	    $hid=ctx$agent_id,
	    $host=ZeekAgent::hostname(ctx),
	    $columns=columns);

	if ( ctx?$change )
		info$change = ZeekAgent::change_type(ctx);

	Log::write(LOG, info);
}

event zeek_init()
{
	local field_name_map = ZeekAgent::log_column_map(Columns, "columns.");
	Log::create_stream(LOG, [$columns=Info, $policy=log_policy]);
	Log::remove_default_filter(LOG);
	Log::add_filter(LOG, [
	    $name="default",
	    $path="zeek-agent-sockets",
	    $field_name_map=field_name_map]);

	ZeekAgent::query([
	    $sql_stmt="SELECT * FROM sockets",
	    $event_=query_result,
	    $schedule_=query_interval,
	    $subscription=subscription]);
}
