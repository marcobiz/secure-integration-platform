# ADR-0003: Named Pipe and IPC protocol

**Status:** Accepted

## Context

The Local Broker must serve .NET, VB6, Delphi, COBOL and native applications, authenticating the Windows caller without opening a local port.

## Decision

Windows Named Pipe is the primary transport. Versioned binary framing with a UTF-8 JSON body and binary chunks. Pipe ACLs, client PID, impersonation, challenge, sequence number, nonce and limits are mandatory.

## Consequences

The transport is local, language-neutral and x86/x64-compatible. The protocol must be implemented twice: in .NET and C++. A localhost API remains outside the MVP.

## Rejected alternatives

Localhost HTTP increases CSRF/DNS-rebinding exposure and token management; gRPC named pipes add complexity to legacy adapters; COM-only does not cover every language.
