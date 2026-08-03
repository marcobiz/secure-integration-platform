# ADR-0001: Runtime e linguaggi

**Stato:** Accepted

## Contesto

Il prodotto comprende servizio Windows, API/container, web admin e adapter x86/x64 per stack legacy eterogenei.

## Decisione

- C# e .NET 10 LTS per Local Broker, Gateway, Admin e SDK .NET.
- C++20 per C ABI e COM Automation x86/x64.
- Admin UI server-rendered ASP.NET Core con componenti TypeScript mirati.
- SDK .NET target `netstandard2.0` e `net10.0`.

## Conseguenze

Un unico ecosistema copre core e cloud; C++ resta confinato agli adapter. La pipeline deve compilare Windows x86/x64 e Linux x64. Gli adapter non duplicano policy o crittografia.

## Alternative escluse

Java/Rust per il core aumenterebbero stack e packaging; NativeAOT non copre adeguatamente l'ABI Windows x86 richiesta.

