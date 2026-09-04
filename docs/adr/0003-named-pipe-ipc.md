# ADR-0003: Named Pipe and IPC protocol

**Status:** Accepted

## Context

The Local Broker must serve .NET, VB6, Delphi, COBOL and native applications, authenticating the Windows caller without opening a local port.

## Decision

Windows Named Pipe is the primary transport. Versioned binary framing with a UTF-8 JSON body and binary chunks. Pipe ACLs, client PID, impersonation, challenge, sequence number, nonce and limits are mandatory.

The .NET SDK must also authenticate the server before sending any handshake or
request data. For the standalone service it resolves the configured own-process
Windows service through SCM, retains a limited-query/synchronize process handle,
and checks the connected pipe's kernel server PID and virtual-service owner SID.
The owner check prevents a stale/reused PID or transferred fake pipe from becoming
authority. Only administrator-installed service configuration is trusted; wire PIDs
and pipe names alone are insufficient. A new connection repeats authentication;
absence, mismatch or access denial fails closed without automatic retries.

Relevant Windows contracts: [QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex),
[GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid)
and [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).
SCM/pipe authority passed once in the elevated real-service gate on exact software
candidate `3955fd0c3a5eccf816d44b0faba9a704227baa3d`; ordinary-user access remains
unqualified. In-process IPC tests remain supporting evidence, not that operational claim.

## Consequences

The transport is local, language-neutral and x86/x64-compatible. The protocol must be implemented twice: in .NET and C++. A localhost API remains outside the MVP.

## Rejected alternatives

Localhost HTTP increases CSRF/DNS-rebinding exposure and token management; gRPC named pipes add complexity to legacy adapters; COM-only does not cover every language.
