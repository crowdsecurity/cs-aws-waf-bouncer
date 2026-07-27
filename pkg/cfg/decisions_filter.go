package cfg

import (
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// DecisionsFilter selects which of the decisions returned by LAPI apply to a given web ACL.
//
// The scenario options are named after, and behave like, the LAPI query parameters of the same
// name: a case-insensitive substring match. Origins use include/exclude instead of the LAPI
// "origins" parameter, because LAPI has no way to express "everything but this origin".
type DecisionsFilter struct {
	IncludeOrigins         []string `yaml:"include_origins"`
	ExcludeOrigins         []string `yaml:"exclude_origins"`
	ScenariosContaining    []string `yaml:"scenarios_containing"`
	ScenariosNotContaining []string `yaml:"scenarios_not_containing"`
}

func (f DecisionsFilter) IsEmpty() bool {
	return len(f.IncludeOrigins) == 0 &&
		len(f.ExcludeOrigins) == 0 &&
		len(f.ScenariosContaining) == 0 &&
		len(f.ScenariosNotContaining) == 0
}

func equalsAnyFold(value string, list []string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}

	return false
}

func containsAnyFold(value string, substrings []string) bool {
	value = strings.ToLower(value)

	for _, sub := range substrings {
		if strings.Contains(value, strings.ToLower(sub)) {
			return true
		}
	}

	return false
}

// allow reports whether a decision passes the filter. An empty list never rejects, and
// exclusion always wins over inclusion.
func (f DecisionsFilter) allow(decision *models.Decision) bool {
	if decision == nil {
		return false
	}

	origin := ""
	if decision.Origin != nil {
		origin = *decision.Origin
	}

	scenario := ""
	if decision.Scenario != nil {
		scenario = *decision.Scenario
	}

	if equalsAnyFold(origin, f.ExcludeOrigins) {
		return false
	}

	if len(f.IncludeOrigins) > 0 && !equalsAnyFold(origin, f.IncludeOrigins) {
		return false
	}

	if containsAnyFold(scenario, f.ScenariosNotContaining) {
		return false
	}

	if len(f.ScenariosContaining) > 0 && !containsAnyFold(scenario, f.ScenariosContaining) {
		return false
	}

	return true
}

// Apply returns the subset of a decision stream that passes the filter. Deleted decisions carry
// the same origin and scenario as the decision they expire, so a decision that was filtered out
// when added is also filtered out when removed.
func (f DecisionsFilter) Apply(stream *models.DecisionsStreamResponse) *models.DecisionsStreamResponse {
	if stream == nil || f.IsEmpty() {
		return stream
	}

	filtered := &models.DecisionsStreamResponse{
		New:     make(models.GetDecisionsResponse, 0, len(stream.New)),
		Deleted: make(models.GetDecisionsResponse, 0, len(stream.Deleted)),
	}

	for _, decision := range stream.New {
		if f.allow(decision) {
			filtered.New = append(filtered.New, decision)
		}
	}

	for _, decision := range stream.Deleted {
		if f.allow(decision) {
			filtered.Deleted = append(filtered.Deleted, decision)
		}
	}

	return filtered
}
