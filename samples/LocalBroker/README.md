# Local Broker sample

See the [standalone guide](../../docs/user/local-broker.md) for publishing, installing
and running this Windows .NET sample without a Gateway. It uses synthetic data only,
never prints plaintext/keys, and refuses to overwrite an existing envelope.

Real Windows Service qualification remains pending; in-process SDK/transport tests
are not a substitute for the guide's elevated service verification entrypoint.
