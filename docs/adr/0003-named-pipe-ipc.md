# ADR-0003: Named Pipe e protocollo IPC

**Stato:** Accepted

## Contesto

Il Local Broker deve servire .NET, VB6, Delphi, COBOL e applicazioni native, autenticando il chiamante Windows senza aprire una porta locale.

## Decisione

Windows Named Pipe come trasporto primario. Framing binario versionato con body JSON UTF-8 e chunk binari. Pipe ACL, client PID, impersonation, challenge, sequence number, nonce e limiti obbligatori.

## Conseguenze

Il trasporto è locale, language-neutral e compatibile x86/x64. Il protocollo deve essere implementato due volte: .NET e C++. L'API localhost resta fuori dall'MVP.

## Alternative escluse

HTTP localhost aumenta CSRF/DNS-rebinding e gestione token; gRPC named pipes aggiunge complessità agli adapter legacy; COM-only non copre tutti i linguaggi.

