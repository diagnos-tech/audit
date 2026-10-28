package cia

import (
	"fmt"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// The summaries of change events are fixed templates in both languages, so the
// verifier can derive them again (INCIDENTS-CONTRACT §8).

var levelWords = map[string]map[string][2]string{ // dimension → level → {en, pt-BR}
	"availability": {"ok": {"up", "no ar"}, "warn": {"degraded", "degradado"}, "fail": {"down", "fora do ar"}},
	"integrity":    {"ok": {"verified", "verificada"}, "warn": {"unverified", "não verificada"}, "fail": {"failed", "com falha"}},
}

var dimensionWords = map[string][2]string{"availability": {"availability", "disponibilidade"}, "integrity": {"integrity", "integridade"}}

func levelSummary(service, dimension, from, to string) record.Localized {
	d, f, t := dimensionWords[dimension], levelWords[dimension][from], levelWords[dimension][to]
	return record.Localized{
		EN:   fmt.Sprintf("%s %s: %s → %s", service, d[0], f[0], t[0]),
		PTBR: fmt.Sprintf("%s %s: %s → %s", service, d[1], f[1], t[1]),
	}
}

func releaseSummary(service, version string) record.Localized {
	return record.Localized{EN: fmt.Sprintf("%s: release %s verified", service, version),
		PTBR: fmt.Sprintf("%s: versão %s verificada", service, version)}
}

func findingSummary(log string) record.Localized {
	return record.Localized{EN: "Witness finding in log " + log, PTBR: "Achado da testemunha no log " + log}
}

func delayedSummary(minutes int) record.Localized {
	return record.Localized{
		EN:   fmt.Sprintf("The record was delayed for %d minutes; this is not an outage of the services", minutes),
		PTBR: fmt.Sprintf("O registro atrasou %d minutos; isso não é uma queda dos serviços", minutes),
	}
}

func resumedSummary(minutes int) record.Localized {
	return record.Localized{EN: fmt.Sprintf("The record resumed after %d minutes", minutes),
		PTBR: fmt.Sprintf("O registro voltou depois de %d minutos", minutes)}
}

func vantageSummary() record.Localized {
	return record.Localized{
		EN:   "The auditor's network failed; nothing was measured in this run (not an outage of the services)",
		PTBR: "A rede do auditor falhou; nada foi medido nesta rodada (não é uma queda dos serviços)",
	}
}

// incidentVerbs are the words of the four things that happen to an incident.
var incidentVerbs = map[string][2]string{
	"opened":   {"Incident opened: ", "Incidente aberto: "},
	"declared": {"Incident declared: ", "Incidente declarado: "},
	"updated":  {"Incident updated: ", "Incidente atualizado: "},
	"resolved": {"Incident resolved: ", "Incidente resolvido: "},
	"removed":  {"Incident removed: ", "Incidente removido: "},
}

// autoIncidentSummary words an incident of the auditor: its service, its
// dimension and the reasons.
func autoIncidentSummary(verb string, e record.CIAIncidentEvent) record.Localized {
	d := dimensionWords[map[string]string{"A": "availability", "I": "integrity"}[e.Categories[0]]]
	reasons := strings.Join(e.Reasons, ", ")
	v := incidentVerbs[verb]
	return record.Localized{EN: fmt.Sprintf("%s%s %s (%s)", v[0], e.Services[0], d[0], reasons),
		PTBR: fmt.Sprintf("%s%s %s (%s)", v[1], e.Services[0], d[1], reasons)}
}

// declaredIncidentSummary words a declared incident by its title.
func declaredIncidentSummary(verb string, title record.Localized) record.Localized {
	v := incidentVerbs[verb]
	return record.Localized{EN: v[0] + title.EN, PTBR: v[1] + title.PTBR}
}
