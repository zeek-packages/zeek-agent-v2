##! Types for the Zeek Agent framework.

module ZeekAgent;

export {
	## For queries that repeat their execution regularly, the type of
	## updates we are interested in.
	type SubscriptionType: enum {
		## Keep returning complete, fresh snapshots of the full
		## table.
		Snapshots,

		## Return rows that got added or deleted compared to the
		## previous result.
		Differences,

		## Return an initial snapshot, then rows that got added or
		## deleted compared to the previous result.
		SnapshotPlusDifferences,

		## Return only rows added since the previous result. (This is
		## most useful for evented tables, hence the name).
		Events,
	};

	## For queries using ``Subscription::Differences``, indicates the type of change to a row.
	type ChangeType: enum {
		## Rows has been added.
		Add,

		## Row has been deleted.
		Delete
	};

	## Context provided along with query results.
	type Context: record {
		## UUID of agent sending the result.
		agent_id: string;

		## Local time on the agent system when result was sent.
		host_time: time;

		## ID of query triggering this response, if any.
		query_id: string &optional;

		## Type of change that the result is reflecting.
		change: ChangeType &optional;

		## Cookie string provided with the query that produced this result, if any.
		cookie: string &optional;
	};

	## Query to send to connected agents.
	type Query: record {
		## SQL statement to execute.
		sql_stmt: string;

		## If set and non-zero, reschedules in such intervals until
		## canceled.
		schedule_: interval &optional;

		## For regularly rescheduled queries, the type of updates to
		## return.
		subscription: ZeekAgent::SubscriptionType &default=Snapshots;

		## Event to raise for results.
		event_: any;

		## Custom cookie string that will be included with results.
		cookie: string &optional;

		## Specify a set of tables that must be available for this
		## query to execute. If an agent doesn't have them all, it will
		## (silently) ignore the query.
		requires_tables: set[string] &default=set();

		## Specify a set of tables that must *not* be available for this
		## query to execute. If an agent does have any of them, it will
		## (silently) ignore the query.
		if_missing_tables: set[string] &default=set();
	};

	## Scope that queries apply to.
	type Scope: enum {
		## Send query to a group of agents.
		Group,

		## Send query to an individual agent only.
		Host
	};
}
