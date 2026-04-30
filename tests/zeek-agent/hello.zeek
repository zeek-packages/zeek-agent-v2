# @TEST-DOC: Basic, standalone functionality test with faked events.
#
# @TEST-PORT: ZEEK_PORT
#
# @TEST-EXEC: zeek ${PACKAGE} %INPUT
# @TEST-EXEC: btest-diff zeek-agent.log

# This follows testing/btest/cluster/websocket/server/default.zeek.

# Redef snippet for running XPUB/XSUB on ephemeral ports.
@load base/utils/numbers
module Cluster::Backend::ZeroMQ;

global xpub_port = extract_count(getenv("XPUB_PORT"));
global xsub_port = extract_count(getenv("XSUB_PORT"));
redef listen_xsub_endpoint = fmt("tcp://127.0.0.1:%s", xsub_port);
redef connect_xpub_endpoint = listen_xsub_endpoint;
redef listen_xpub_endpoint = fmt("tcp://127.0.0.1:%s", xpub_port);
redef connect_xsub_endpoint = listen_xpub_endpoint;
# Redef snippet ===

module Test;

global n = 0;

event send_hello()
	{
	# We simulate an agent here by faking a corresponding "hello" event.
	local ctx: ZeekAgent::Context = [ $agent_id="fake_agent",
	    $query_id="fake_query", $host_time=network_time() ];

	if ( ++n < 3 )
		{
		local hello: ZeekAgentAPI::AgentHelloV1 = [ $agent_id="fake_agent",
		    $instance_id="fake_instance" ];
		event ZeekAgentAPI::agent_hello_v1(ctx, hello);
		schedule 0.1secs { send_hello() };
		}
	else
		{
		event ZeekAgentAPI::agent_shutdown_v1(ctx);
		terminate();
		}
	}

event zeek_init()
	{
	schedule 0secs { send_hello() };
	}
