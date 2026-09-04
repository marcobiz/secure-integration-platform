# ADR-0001: Runtime and languages

**Status:** Accepted

## Context

The product includes a Windows service, API/container, web administration and x86/x64 adapters for heterogeneous legacy stacks.

## Decision

- C# and .NET 10 LTS for Local Broker, Gateway, Admin and the .NET SDK.
- C++20 for the C ABI and COM Automation x86/x64.
- Server-rendered ASP.NET Core Admin UI with focused TypeScript components.
- .NET SDK targets `netstandard2.0` and `net10.0`.

## Consequences

One ecosystem covers Core and cloud; C++ remains confined to adapters. The pipeline must build for Windows x86/x64 and Linux x64. Adapters do not duplicate policy or cryptography.

## Rejected alternatives

Java/Rust for Core would add stack and packaging complexity; NativeAOT does not adequately cover the required Windows x86 ABI.
