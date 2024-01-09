module ZeekAgent_SSH;

export {
	## Paths to find sshd configuration files in.
	option config_paths_to_watch = set("/etc/ssh/sshd_config",
	    "/etc/ssh/sshd_config.d/*");

	## Paths to find `authorized_keys` files in.
	option key_paths_to_watch: table[string] of set[string] = {
		["linux"] = set("/home/*/.ssh/authorized_keys"),
		["darwin"] = set("/Users/*/.ssh/authorized_keys")
	};

	## Query frequency.
	option query_interval = 30 secs;

	## Subscription type
	option subscription = ZeekAgent::Differences;

	## Logging stream identifier for the tables.log.
	redef enum Log::ID += { LOG_CONFIGS, LOG_KEYS };

	## Configuration option extracgt from a configuratin file.
	type ConfigOption: record {
		key: string &log; ##< config option key
		value: string &log; ##< config option value
	};

	## Options from matching config files.
	type ColumnsConfigs: record {
		path: string &optional &log; ##< absolute path
		number: count &optional &log; ##< line number
		option_: ConfigOption &optional &log; ##< option extracted from configuration line
	};

	## Lines from matching key files.
	type ColumnsKeys: record {
		path: string &optional &log; ##< absolute path
		number: count &optional &log; ##< line number
		content: string &optional &log; ##< content of line
	};

	## Information logged for configuration files.
	type InfoConfigs: record {
		t: time &log; ##< time received
		hid: string &log; ##< unique ID of originater host
		host: string &log; ##< name of originator
		change: string &optional &log; ##< type of change
		columns: ColumnsConfigs &log;
	};

	## Information logged for key files.
	type InfoKeys: record {
		t: time &log; ##< time received
		hid: string &log; ##< unique ID of originater host
		host: string &log; ##< name of originator
		change: string &optional &log; ##< type of change
		columns: ColumnsKeys &log;
	};

	## A default logging policy hook for the table's configs log stream.
	global log_policy_configs: Log::PolicyHook;

	## A default logging policy hook for the table's keys log stream.
	global log_policy_keys: Log::PolicyHook;
}

event ZeekAgent_SSH::query_result_configs(ctx: ZeekAgent::Context,
    columns: ColumnsConfigs)
	{
	local info = InfoConfigs($t=network_time(), $hid=ctx$agent_id,
	    $host=ZeekAgent::hostname(ctx), $columns=columns);

	if ( ctx?$change )
		info$change = ZeekAgent::change_type(ctx);

	Log::write(LOG_CONFIGS, info);
	}

event ZeekAgent_SSH::query_result_keys(ctx: ZeekAgent::Context,
    columns: ColumnsKeys)
	{
	local info = InfoKeys($t=network_time(), $hid=ctx$agent_id,
	    $host=ZeekAgent::hostname(ctx), $columns=columns);

	if ( ctx?$change )
		info$change = ZeekAgent::change_type(ctx);

	Log::write(LOG_KEYS, info);
	}

event zeek_init()
	{
	if ( |config_paths_to_watch| != 0 )
		{
		local field_name_map_configs = ZeekAgent::log_column_map(ColumnsConfigs,
		    "columns.");
		Log::create_stream(LOG_CONFIGS, [$columns=InfoConfigs,
		    $policy=log_policy_configs]);
		Log::remove_default_filter(LOG_CONFIGS);
		Log::add_filter(LOG_CONFIGS, [$name="default", $path="zeek-agent-ssh-configs",
		    $field_name_map=field_name_map_configs]);

		for ( p in config_paths_to_watch )
			{
			local stmt_configs = fmt("SELECT * FROM files_columns(\"%s\", \"$1:text,$2:text\")",
			    p);
			ZeekAgent::query([$sql_stmt=stmt_configs, $event_=query_result_configs,
			    $schedule_=query_interval,
			    $subscription=subscription]);
			}
		}

	if ( |key_paths_to_watch| != 0 )
		{
		local field_name_map_keys = ZeekAgent::log_column_map(ColumnsKeys,
		    "columns.");
		Log::create_stream(LOG_KEYS, [$columns=InfoKeys, $policy=log_policy_keys]);
		Log::remove_default_filter(LOG_KEYS);
		Log::add_filter(LOG_KEYS, [$name="default",
		    $path="zeek-agent-ssh-authorized-keys",
		    $field_name_map=field_name_map_keys]);


		for ( platform in key_paths_to_watch )
			{
			for ( path in key_paths_to_watch[platform] )
				{
				local stmt_keys = fmt("SELECT * FROM files_lines(\"%s\")", path);
				ZeekAgent::query([$sql_stmt=stmt_keys, $event_=query_result_keys,
				    $schedule_=query_interval,
				    $subscription=subscription], ZeekAgent::Group, platform);
				}
			}
		}
	}
