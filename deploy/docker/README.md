# Container packaging boundary

The repository contains separate Gateway and migration images plus synthetic Compose profiles. They are engineering, test and evaluation deployments, not a qualified cloud or production distribution. The Gateway image runs non-root; read-only filesystem and writable `tmpfs` are properties of the Compose/CI profiles that impose them, not of the image alone.

The default image contains the Core runtime and Synthetic Provider, with no vertical Connector pack. Optional deployment and vertical images depend on Core contracts and are qualified separately. See [deployment architecture](../../docs/deployment/deployment-architecture.md).
