package cfg

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func decision(origin string, scenario string) *models.Decision {
	return &models.Decision{
		Origin:   &origin,
		Scenario: &scenario,
	}
}

func TestDecisionsFilterIsEmpty(t *testing.T) {
	t.Parallel()

	if !(DecisionsFilter{}).IsEmpty() {
		t.Error("zero value filter should be empty")
	}

	filters := []DecisionsFilter{
		{IncludeOrigins: []string{"cscli"}},
		{ExcludeOrigins: []string{"CAPI"}},
		{ScenariosContaining: []string{"http"}},
		{ScenariosNotContaining: []string{"http"}},
	}

	for _, filter := range filters {
		if filter.IsEmpty() {
			t.Errorf("filter %+v should not be empty", filter)
		}
	}
}

func TestDecisionsFilterAllow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filter   DecisionsFilter
		decision *models.Decision
		want     bool
	}{
		{
			name:     "empty filter allows everything",
			decision: decision("CAPI", "crowdsecurity/http-probing"),
			want:     true,
		},
		{
			name:     "nil decision is rejected",
			filter:   DecisionsFilter{IncludeOrigins: []string{"cscli"}},
			decision: nil,
			want:     false,
		},
		{
			name:     "include_origins keeps a listed origin",
			filter:   DecisionsFilter{IncludeOrigins: []string{"cscli", "crowdsec"}},
			decision: decision("cscli", "manual"),
			want:     true,
		},
		{
			name:     "include_origins drops an unlisted origin",
			filter:   DecisionsFilter{IncludeOrigins: []string{"cscli"}},
			decision: decision("CAPI", "crowdsecurity/http-probing"),
			want:     false,
		},
		{
			name:     "include_origins is case insensitive",
			filter:   DecisionsFilter{IncludeOrigins: []string{"capi"}},
			decision: decision("CAPI", "crowdsecurity/http-probing"),
			want:     true,
		},
		{
			name:     "include_origins matches exactly, not as a substring",
			filter:   DecisionsFilter{IncludeOrigins: []string{"cs"}},
			decision: decision("cscli", "manual"),
			want:     false,
		},
		{
			name:     "exclude_origins drops a listed origin",
			filter:   DecisionsFilter{ExcludeOrigins: []string{"CAPI"}},
			decision: decision("CAPI", "crowdsecurity/http-probing"),
			want:     false,
		},
		{
			name:     "exclude_origins keeps an unlisted origin",
			filter:   DecisionsFilter{ExcludeOrigins: []string{"CAPI"}},
			decision: decision("cscli", "manual"),
			want:     true,
		},
		{
			name: "exclude_origins wins over include_origins",
			filter: DecisionsFilter{
				IncludeOrigins: []string{"cscli", "CAPI"},
				ExcludeOrigins: []string{"CAPI"},
			},
			decision: decision("CAPI", "crowdsecurity/http-probing"),
			want:     false,
		},
		{
			name:     "scenarios_containing matches a substring",
			filter:   DecisionsFilter{ScenariosContaining: []string{"http"}},
			decision: decision("crowdsec", "crowdsecurity/http-probing"),
			want:     true,
		},
		{
			name:     "scenarios_containing is case insensitive",
			filter:   DecisionsFilter{ScenariosContaining: []string{"HTTP-Probing"}},
			decision: decision("crowdsec", "crowdsecurity/http-probing"),
			want:     true,
		},
		{
			name:     "scenarios_containing drops a non matching scenario",
			filter:   DecisionsFilter{ScenariosContaining: []string{"ssh"}},
			decision: decision("crowdsec", "crowdsecurity/http-probing"),
			want:     false,
		},
		{
			name:     "scenarios_containing matches any of the words",
			filter:   DecisionsFilter{ScenariosContaining: []string{"ssh", "http"}},
			decision: decision("crowdsec", "crowdsecurity/http-probing"),
			want:     true,
		},
		{
			name:     "scenarios_not_containing drops a matching scenario",
			filter:   DecisionsFilter{ScenariosNotContaining: []string{"crawl"}},
			decision: decision("crowdsec", "crowdsecurity/http-crawl-non_statics"),
			want:     false,
		},
		{
			name: "scenarios_not_containing wins over scenarios_containing",
			filter: DecisionsFilter{
				ScenariosContaining:    []string{"http"},
				ScenariosNotContaining: []string{"crawl"},
			},
			decision: decision("crowdsec", "crowdsecurity/http-crawl-non_statics"),
			want:     false,
		},
		{
			name: "origin and scenario must both pass",
			filter: DecisionsFilter{
				IncludeOrigins:      []string{"cscli"},
				ScenariosContaining: []string{"http"},
			},
			decision: decision("crowdsec", "crowdsecurity/http-probing"),
			want:     false,
		},
		{
			name:     "nil origin and scenario are treated as empty",
			filter:   DecisionsFilter{IncludeOrigins: []string{"cscli"}},
			decision: &models.Decision{},
			want:     false,
		},
		{
			name:     "a decision with no origin passes an exclude only filter",
			filter:   DecisionsFilter{ExcludeOrigins: []string{"CAPI"}},
			decision: &models.Decision{},
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.filter.allow(tc.decision); got != tc.want {
				t.Errorf("allow() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDecisionsFilterApply(t *testing.T) {
	t.Parallel()

	stream := &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			decision("cscli", "manual"),
			decision("CAPI", "crowdsecurity/http-probing"),
		},
		Deleted: models.GetDecisionsResponse{
			decision("CAPI", "crowdsecurity/http-probing"),
			decision("cscli", "manual"),
		},
	}

	t.Run("empty filter returns the stream untouched", func(t *testing.T) {
		t.Parallel()

		if got := (DecisionsFilter{}).Apply(stream); got != stream {
			t.Error("empty filter should return the same stream pointer")
		}
	})

	t.Run("nil stream is passed through", func(t *testing.T) {
		t.Parallel()

		filter := DecisionsFilter{IncludeOrigins: []string{"cscli"}}
		if got := filter.Apply(nil); got != nil {
			t.Errorf("Apply(nil) = %v, want nil", got)
		}
	})

	// A decision filtered out when added must also be filtered out when removed, otherwise the
	// IP would stay in the set forever.
	t.Run("new and deleted are filtered symmetrically", func(t *testing.T) {
		t.Parallel()

		filter := DecisionsFilter{IncludeOrigins: []string{"cscli"}}

		got := filter.Apply(stream)
		if len(got.New) != 1 || *got.New[0].Origin != "cscli" {
			t.Errorf("New = %d decisions, want only the cscli one", len(got.New))
		}

		if len(got.Deleted) != 1 || *got.Deleted[0].Origin != "cscli" {
			t.Errorf("Deleted = %d decisions, want only the cscli one", len(got.Deleted))
		}

		if len(stream.New) != 2 || len(stream.Deleted) != 2 {
			t.Error("Apply() must not mutate the input stream")
		}
	})

	t.Run("everything can be filtered out", func(t *testing.T) {
		t.Parallel()

		filter := DecisionsFilter{ExcludeOrigins: []string{"cscli", "CAPI"}}

		got := filter.Apply(stream)
		if len(got.New) != 0 || len(got.Deleted) != 0 {
			t.Errorf("Apply() kept %d new and %d deleted decisions, want none", len(got.New), len(got.Deleted))
		}
	})

	t.Run("nil slices are handled", func(t *testing.T) {
		t.Parallel()

		filter := DecisionsFilter{IncludeOrigins: []string{"cscli"}}

		got := filter.Apply(&models.DecisionsStreamResponse{})
		if len(got.New) != 0 || len(got.Deleted) != 0 {
			t.Errorf("Apply() on an empty stream returned %d/%d decisions", len(got.New), len(got.Deleted))
		}
	})
}
