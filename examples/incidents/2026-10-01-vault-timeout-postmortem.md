---
id: 2026-10-01-vault-timeout-postmortem
title:
  en: "Postmortem: vault did not answer for 20 minutes"
  pt-BR: "Análise: o vault ficou 20 minutos sem responder"
services: [vault]
categories: [A]
severity: high
status: resolved
declared_at: 2026-10-01T11:50:00Z
started_at: 2026-10-01T03:10:00Z
resolved_at: 2026-10-01T03:30:00Z
relates: 2026-10-01-auto-vault-a-0310
publish: true
summary:
  en: A database failover left the vault without a primary for 20 minutes. No exam was lost or exposed.
  pt-BR: Uma troca de primário do banco deixou o vault sem resposta por 20 minutos. Nenhum exame foi perdido nem exposto.
---

## English

**Example data.** This postmortem is invented to show how a declared incident adds to an incident the
auditor opened by itself (`relates`).

### What happened

At 03:10 UTC the vault stopped answering. The auditor opened an incident at 03:20, after three failed
five-minute checks, and resolved it at 03:35, after two good ones.

### Cause

A scheduled failover of the database left the vault without a primary for 20 minutes.

### What we changed

1. Failovers now run in the quietest hour of the week, with the vault in read-only mode.
2. The vault answers its health check from memory when the database is unavailable, so a failover is
   visible as a degraded answer and not as a timeout.

## Português

**Dado de exemplo.** Esta análise é inventada para mostrar como um incidente declarado complementa um
incidente que o auditor abriu sozinho (`relates`).

### O que aconteceu

Às 03:10 UTC o vault parou de responder. O auditor abriu um incidente às 03:20, depois de três
verificações de cinco minutos falharem, e o resolveu às 03:35, depois de duas boas.

### Causa

Uma troca programada de primário do banco de dados deixou o vault sem resposta por 20 minutos.

### O que mudamos

1. As trocas agora acontecem na hora mais calma da semana, com o vault em modo somente leitura.
2. O vault responde ao teste de saúde pela memória quando o banco está indisponível, de modo que uma
   troca aparece como resposta degradada e não como timeout.
