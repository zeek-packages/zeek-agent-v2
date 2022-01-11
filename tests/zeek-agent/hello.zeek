# @TEST-DOC: Basic, standalone functionality test with faked events.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: zeek ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff zeek-agent.log

@if ( getenv("ZEEK_PORT") != "" )
redef Broker::default_port = to_port(getenv("ZEEK_PORT"));
@endif

global n = 0;

event send_hello()
	{
	# We simulate an agent here by faking a corresponding "hello" event.
	local ctx: ZeekAgent::Context = [$agent_id="fake_agent", $host_time=network_time()];

	if ( ++n < 3 )
		{
		local hello: ZeekAgentAPI::HelloV1 = [$agent_id="fake_agent", $instance_id="fake_instance"];
		event ZeekAgentAPI::agent_hello_v1(ctx, hello);
		schedule 0.1secs { send_hello() };
		}
	else {
		event ZeekAgentAPI::agent_shutdown_v1(ctx);
		terminate();
		}
	}

event zeek_init()
	{
	schedule 0secs { send_hello() };
	}
