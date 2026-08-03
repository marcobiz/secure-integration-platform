# Protocollo IPC del Local Broker

## Trasporto

Named Pipe Windows `\\.\pipe\<Vendor>.<Product>.Broker.v1`, byte mode, full duplex. L'API localhost è fuori dall'MVP.

## Framing

Ogni frame usa network byte order:

| Campo | Byte | Descrizione |
|---|---:|---|
| Magic | 4 | ASCII `BGR1`. |
| Major | 1 | Protocol major. |
| Minor | 1 | Protocol minor. |
| Type | 1 | Control, Data, End, Cancel o Error. |
| Flags | 1 | Riservati; devono essere zero in v1. |
| Length | 4 | Lunghezza body, massimo in base al frame type. |
| Correlation ID | 16 | UUID bytes. |
| Sequence | 8 | Contatore monotono per connessione. |
| Body | N | JSON UTF-8 o bytes. |

Control frame massimo 1 MiB. Data chunk massimo 64 KiB. Payload aggregato standard 16 MiB; stream massimo 64 MiB. Frame incompleti, magic/version errati, sequence duplicate o reserved flag non zero chiudono la connessione.

## Handshake

Client:

```json
{
  "message": "HandshakeRequest",
  "supported": {"major": 1, "minMinor": 0, "maxMinor": 0},
  "applicationRegistrationId": "sample.legacy",
  "clientNonce": "synthetic-base64url"
}
```

Server:

```json
{
  "message": "HandshakeResponse",
  "selected": {"major": 1, "minor": 0},
  "connectionId": "00000000-0000-7000-8000-000000000001",
  "serverChallenge": "synthetic-base64url",
  "limits": {"controlBytes": 1048576, "payloadBytes": 16777216, "streamBytes": 67108864}
}
```

Prima della risposta il Broker acquisisce client PID, process handle, creation time e Windows identity. Il manifest Application determina path, publisher/hash e operation grants.

## Envelope di richiesta

```json
{
  "message": "Request",
  "operation": "ComputeHmac",
  "protocolVersion": "1.0",
  "correlationId": "00000000-0000-7000-8000-000000000001",
  "connectionChallenge": "synthetic-base64url",
  "requestNonce": "synthetic-base64url",
  "deadlineUtc": "2026-08-02T12:00:00Z",
  "body": {}
}
```

Unknown property rifiutate, salvo `extensions`. Deadline massima 60 secondi. Nonce duplicate rifiutate.

## Operazioni v1

| Operazione | Input essenziale | Output | Note |
|---|---|---|---|
| `PutLocalSecret` | logical name, class, bytes, allowed uses | opaque ref | Tenant/Session only; mai Vendor Secret. |
| `DeleteLocalSecret` | opaque ref | status | Idempotente. |
| `ProtectData` | purpose, content type, bytes | AEAD envelope | Key/AAD scoped all'Application. |
| `UnprotectData` | purpose, envelope | bytes | Fallisce integralmente su auth error. |
| `PutSession` | connector, operation, value, expiry | sessionRef | Memory default, DPAPI only if requested/allowed. |
| `DeleteSession` | sessionRef | status | Idempotente. |
| `ComputeHmac` | connector, operation, secretRef, message | digest | Algoritmo fissato dalla policy. |
| `SignData` | connector, operation, key policy, digest/data | signature | Claims/payload constraints applicati. |
| `UseLocalCertificate` | connector, operation, certificate policy, request | result | Private key mai esportata. |
| `InvokeGateway` | connector, operation, payload/context | result/sessionRef | Nessun URL o secret name arbitrario. |
| `GetBrokerStatus` | detail level | health/version | Nessun metadata sensibile. |
| `Cancel` | target correlation ID | status | Best effort. |

`GetSecret` non esiste. Un futuro `RevealCompatibilitySecret` richiede feature flag, Application/secret allowlist, scadenza, audit e ADR; non potrà mai esporre Vendor Secret.

## Response ed errori

```json
{
  "message": "Response",
  "correlationId": "00000000-0000-7000-8000-000000000001",
  "success": false,
  "error": {
    "code": "BGR-AUTHZ-003",
    "category": "authorization",
    "retryable": false
  }
}
```

Categorie: protocol, identity, authorization, validation, storage, cryptography, gateway, timeout, cancelled e internal. Errori e exception non contengono path riservati, valori, payload o stack trace.

## Concorrenza e cancellation

- Più connessioni per processo sono ammesse entro policy.
- Ogni connessione supporta richieste concorrenti distinte per correlation ID.
- Default: 16 richieste concorrenti per Application; configurabile solo dall'amministratore.
- Backpressure prima di leggere grandi payload.
- Cancel non interrompe una primitive crittografica già iniziata, ma impedisce le fasi successive.

## Compatibilità

- Major diversa: handshake rifiutato.
- Minor selezionata come massimo valore comune.
- Nuove operazioni richiedono minor increment.
- Nuovi campi opzionali sono ammessi solo dentro `extensions` finché la minor non viene negoziata.
- SDK e Broker mantengono una matrice di compatibilità testata.

