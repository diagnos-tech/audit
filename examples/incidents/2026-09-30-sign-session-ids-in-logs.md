---
id: 2026-09-30-sign-session-ids-in-logs
title:
  en: Signing session identifiers written to an internal log
  pt-BR: Identificadores de sessão de assinatura gravados num log interno
services: [sign]
categories: [C]
severity: medium
status: resolved
declared_at: 2026-09-30T18:10:00Z
started_at: 2026-09-30T16:40:00Z
resolved_at: 2026-10-01T09:30:00Z
publish: true
summary:
  en: For 17 hours an internal error log kept signing session identifiers. No document or personal data was exposed.
  pt-BR: Por 17 horas um log interno de erros guardou identificadores de sessão de assinatura. Nenhum documento ou dado pessoal foi exposto.
---

## English

**Example data.** This incident is invented to show how a published incident looks.

### What happened

A change deployed at 16:40 UTC made the signing service write the identifier of failed signing
sessions to its internal error log. The log is readable only by two engineers.

### Impact

- 41 session identifiers were written. Each expires after 30 minutes and cannot be used without
  the signer's passkey.
- No document, document hash or personal data was written.

### What we did

1. Removed the field from the log at 09:30 UTC the next day.
2. Deleted the affected log lines.
3. Added a test that fails when a session identifier reaches any log.

## Português

**Dado de exemplo.** Este incidente é inventado para mostrar como fica um incidente publicado.

### O que aconteceu

Uma mudança publicada às 16:40 UTC fez o serviço de assinatura gravar o identificador das sessões
de assinatura que falharam no seu log interno de erros. O log só pode ser lido por dois
engenheiros.

### Impacto

- 41 identificadores de sessão foram gravados. Cada um expira em 30 minutos e não pode ser usado
  sem a passkey de quem assina.
- Nenhum documento, hash de documento ou dado pessoal foi gravado.

### O que fizemos

1. Tiramos o campo do log às 09:30 UTC do dia seguinte.
2. Apagamos as linhas afetadas.
3. Acrescentamos um teste que falha quando um identificador de sessão chega a qualquer log.
