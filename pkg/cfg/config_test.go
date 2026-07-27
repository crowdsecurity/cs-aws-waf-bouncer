package cfg

import (
	"slices"
	"strings"
	"testing"
)

// baseConfig is the smallest configuration NewConfig accepts, used as a prefix by the tests
// below. log_media is set to stdout so that Logging.setup() does not create a log file.
const baseConfig = `
api_key: test
api_url: http://127.0.0.1:8080/
log_media: stdout
`

const aclConfig = `
waf_config:
  - web_acl_name: test-acl
    rule_group_name: test-rule-group
    ipset_prefix: test-prefix
    fallback_action: ban
    scope: REGIONAL
    region: eu-west-1
`

func newConfigFromString(t *testing.T, content string) bouncerConfig {
	t.Helper()

	config, err := NewConfig(strings.NewReader(content))
	if err != nil {
		t.Fatalf("NewConfig() error: %s", err)
	}

	return config
}

func assertList(t *testing.T, name string, got []string, want []string) {
	t.Helper()

	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

func TestNewConfigLapiFilters(t *testing.T) {
	t.Parallel()

	config := newConfigFromString(t, baseConfig+aclConfig+`
scenarios_containing: ["http", "ssh"]
scenarios_not_containing: ["crawl"]
origins: ["cscli", "crowdsec"]
`)

	assertList(t, "scenarios_containing", config.ScenariosContaining, []string{"http", "ssh"})
	assertList(t, "scenarios_not_containing", config.ScenariosNotContaining, []string{"crawl"})
	assertList(t, "origins", config.Origins, []string{"cscli", "crowdsec"})
}

func TestNewConfigLapiFiltersDefaultToUnset(t *testing.T) {
	t.Parallel()

	config := newConfigFromString(t, baseConfig+aclConfig)

	// Left nil so that go-cs-bouncer omits the query parameters entirely.
	if config.ScenariosContaining != nil || config.ScenariosNotContaining != nil || config.Origins != nil {
		t.Errorf("LAPI filters should default to nil, got %+v / %+v / %+v",
			config.ScenariosContaining, config.ScenariosNotContaining, config.Origins)
	}
}

func TestNewConfigDecisionsFilter(t *testing.T) {
	t.Parallel()

	config := newConfigFromString(t, baseConfig+`
waf_config:
  - web_acl_name: filtered-acl
    rule_group_name: filtered-rule-group
    ipset_prefix: filtered-prefix
    fallback_action: ban
    scope: REGIONAL
    region: eu-west-1
    decisions_filter:
      include_origins: ["cscli", "crowdsec"]
      exclude_origins: ["CAPI"]
      scenarios_containing: ["http"]
      scenarios_not_containing: ["crawl"]
  - web_acl_name: unfiltered-acl
    rule_group_name: unfiltered-rule-group
    ipset_prefix: unfiltered-prefix
    fallback_action: ban
    scope: CLOUDFRONT
`)

	if len(config.WebACLConfig) != 2 {
		t.Fatalf("got %d web ACLs, want 2", len(config.WebACLConfig))
	}

	filter := config.WebACLConfig[0].DecisionsFilter
	assertList(t, "include_origins", filter.IncludeOrigins, []string{"cscli", "crowdsec"})
	assertList(t, "exclude_origins", filter.ExcludeOrigins, []string{"CAPI"})
	assertList(t, "scenarios_containing", filter.ScenariosContaining, []string{"http"})
	assertList(t, "scenarios_not_containing", filter.ScenariosNotContaining, []string{"crawl"})

	if !config.WebACLConfig[1].DecisionsFilter.IsEmpty() {
		t.Error("an ACL without a decisions_filter should have an empty filter")
	}
}

func TestNewConfigRejectsUnknownDecisionsFilterKey(t *testing.T) {
	t.Parallel()

	_, err := NewConfig(strings.NewReader(baseConfig + `
waf_config:
  - web_acl_name: test-acl
    rule_group_name: test-rule-group
    ipset_prefix: test-prefix
    fallback_action: ban
    scope: CLOUDFRONT
    decisions_filter:
      origins: ["cscli"]
`))
	if err == nil {
		t.Fatal("expected an error for an unknown decisions_filter key")
	}

	if !strings.Contains(err.Error(), "failed to unmarshal") {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestSplitEnvList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{name: "empty value yields no item", value: "", want: nil},
		{name: "only separators yield no item", value: ",,", want: nil},
		{name: "single item", value: "cscli", want: []string{"cscli"}},
		{name: "multiple items", value: "cscli,crowdsec", want: []string{"cscli", "crowdsec"}},
		{name: "surrounding spaces are trimmed", value: " cscli , crowdsec ", want: []string{"cscli", "crowdsec"}},
		{name: "empty items are dropped", value: "cscli,,crowdsec", want: []string{"cscli", "crowdsec"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertList(t, "splitEnvList", splitEnvList(tc.value), tc.want)
		})
	}
}

func TestGetConfigFromEnvDecisionsFilter(t *testing.T) {
	// Not parallel: t.Setenv cannot be used in a parallel test.
	t.Setenv("BOUNCER_ORIGINS", "cscli,crowdsec")
	t.Setenv("BOUNCER_SCENARIOS_CONTAINING", "http")
	t.Setenv("BOUNCER_SCENARIOS_NOT_CONTAINING", "")
	t.Setenv("BOUNCER_WAF_CONFIG_0_WEB_ACL_NAME", "test-acl")
	t.Setenv("BOUNCER_WAF_CONFIG_0_RULE_GROUP_NAME", "test-rule-group")
	t.Setenv("BOUNCER_WAF_CONFIG_0_IPSET_PREFIX", "test-prefix")
	t.Setenv("BOUNCER_WAF_CONFIG_0_FALLBACK_ACTION", "ban")
	t.Setenv("BOUNCER_WAF_CONFIG_0_SCOPE", "CLOUDFRONT")
	t.Setenv("BOUNCER_WAF_CONFIG_0_DECISIONS_FILTER_INCLUDE_ORIGINS", "cscli")
	t.Setenv("BOUNCER_WAF_CONFIG_0_DECISIONS_FILTER_EXCLUDE_ORIGINS", "CAPI,lists")
	t.Setenv("BOUNCER_WAF_CONFIG_0_DECISIONS_FILTER_SCENARIOS_CONTAINING", "http,ssh")
	t.Setenv("BOUNCER_WAF_CONFIG_0_DECISIONS_FILTER_SCENARIOS_NOT_CONTAINING", "crawl")

	config := newConfigFromString(t, baseConfig)

	assertList(t, "origins", config.Origins, []string{"cscli", "crowdsec"})
	assertList(t, "scenarios_containing", config.ScenariosContaining, []string{"http"})
	assertList(t, "scenarios_not_containing", config.ScenariosNotContaining, nil)

	if len(config.WebACLConfig) != 1 {
		t.Fatalf("got %d web ACLs, want 1", len(config.WebACLConfig))
	}

	filter := config.WebACLConfig[0].DecisionsFilter
	assertList(t, "include_origins", filter.IncludeOrigins, []string{"cscli"})
	assertList(t, "exclude_origins", filter.ExcludeOrigins, []string{"CAPI", "lists"})
	assertList(t, "scenarios_containing", filter.ScenariosContaining, []string{"http", "ssh"})
	assertList(t, "scenarios_not_containing", filter.ScenariosNotContaining, []string{"crawl"})
}
