package waf

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-aws-waf-bouncer/pkg/cfg"
)

const testRuleGroup = "crowdsec-rule-group"

// requestBody holds the request fields the tests read.
type requestBody struct {
	Name      string     `json:"Name"`
	ID        string     `json:"Id"`
	Addresses []string   `json:"Addresses"`
	Rules     []ruleBody `json:"Rules"`
}

type ruleBody struct {
	Name             string        `json:"Name"`
	Statement        statementBody `json:"Statement"`
	VisibilityConfig visibility    `json:"VisibilityConfig"`
}

type statementBody struct {
	IPSetReferenceStatement *ipSetReference `json:"IPSetReferenceStatement"`
	OrStatement             *orStatement    `json:"OrStatement"`
}

type ipSetReference struct {
	ARN string `json:"ARN"`
}

type orStatement struct {
	Statements []statementBody `json:"Statements"`
}

type visibility struct {
	CloudWatchMetricsEnabled bool   `json:"CloudWatchMetricsEnabled"`
	SampledRequestsEnabled   bool   `json:"SampledRequestsEnabled"`
	MetricName               string `json:"MetricName"`
}

type wafCall struct {
	op   string
	body requestBody
}

// fakeWAF answers the WAFv2 JSON API calls the bouncer makes and records them.
type fakeWAF struct {
	mu       sync.Mutex
	recorded []wafCall
	failNext map[string]int
	created  int
}

func newFakeWAF(t *testing.T) (*fakeWAF, *wafv2.Client) {
	t.Helper()

	f := &fakeWAF{failNext: make(map[string]int)}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	client := wafv2.New(wafv2.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		Credentials:      aws.AnonymousCredentials{},
		RetryMaxAttempts: 1,
	})

	return f, client
}

func (f *fakeWAF) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AWSWAF_20190729.")

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	var body requestBody
	if err := json.Unmarshal(raw, &body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.recorded = append(f.recorded, wafCall{op: op, body: body})
	fail := f.failNext[op] > 0
	if fail {
		f.failNext[op]--
	}
	if op == "CreateIPSet" {
		f.created++
	}
	created := f.created
	f.mu.Unlock()

	rw.Header().Set("Content-Type", "application/x-amz-json-1.1")

	if fail {
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = rw.Write([]byte(`{"__type":"WAFInternalErrorException","Message":"injected failure"}`))

		return
	}

	var resp any

	switch op {
	case "GetIPSet":
		resp = map[string]any{
			"IPSet": map[string]any{
				"Name":             body.Name,
				"Id":               body.ID,
				"ARN":              "arn:" + body.ID,
				"Description":      "",
				"IPAddressVersion": "IPV4",
				"Addresses":        []string{},
			},
			"LockToken": "lock",
		}
	case "CreateIPSet":
		id := fmt.Sprintf("new-%d", created)
		resp = map[string]any{
			"Summary": map[string]any{
				"Name":        body.Name,
				"Id":          id,
				"ARN":         "arn:" + id,
				"Description": "",
				"LockToken":   "lock",
			},
		}
	case "GetRuleGroup":
		resp = map[string]any{
			"RuleGroup": map[string]any{
				"Name":     testRuleGroup,
				"Id":       "rg-id",
				"ARN":      "arn:rg",
				"Capacity": 50,
				"Rules":    []any{},
				"VisibilityConfig": map[string]any{
					"SampledRequestsEnabled":   false,
					"CloudWatchMetricsEnabled": false,
					"MetricName":               testRuleGroup,
				},
			},
			"LockToken": "lock",
		}
	case "UpdateIPSet", "UpdateRuleGroup", "UpdateWebACL":
		resp = map[string]any{"NextLockToken": "lock"}
	case "DeleteIPSet":
		resp = map[string]any{}
	default:
		http.Error(rw, "unexpected operation "+op, http.StatusBadRequest)
		return
	}

	out, err := json.Marshal(resp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = rw.Write(out)
}

func (f *fakeWAF) calls(op string) []requestBody {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []requestBody

	for _, c := range f.recorded {
		if c.op == op {
			out = append(out, c.body)
		}
	}

	return out
}

// committedSet returns a set as it is after a successful sync with WAF.
func committedSet(client *wafv2.Client, ipType string, id string, ips ...string) *WAFIpSet {
	s := NewIpSet("crowdsec-ipset", ipType, "ban", "CLOUDFRONT", client)
	s.id = id
	s.arn = "arn:" + id
	s.ips = ips

	return s
}

func fullSet(client *wafv2.Client, id string) *WAFIpSet {
	ips := make([]string, 0, 10000)
	for i := range 10000 {
		ips = append(ips, fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}

	return committedSet(client, "IPV4", id, ips...)
}

func newTestWAF(client *wafv2.Client, sets ...*WAFIpSet) *WAF {
	logger := log.WithField("acl", "test-acl")
	manager := NewIPSetManager("crowdsec-ipset", "CLOUDFRONT", client, logger)
	manager.IPSets = sets

	return &WAF{
		config: &cfg.AclConfig{
			WebACLName:    "test-acl",
			RuleGroupName: testRuleGroup,
			Scope:         "CLOUDFRONT",
			IpsetPrefix:   "crowdsec-ipset",
		},
		client:          client,
		Logger:          logger,
		ruleGroupsInfos: map[string]RuleGroup{testRuleGroup: {ARN: "arn:rg", Id: "rg-id"}},
		ipsetManager:    manager,
		visibilityConfig: &wafv2types.VisibilityConfig{
			MetricName: aws.String(testRuleGroup),
		},
	}
}

func findRule(t *testing.T, body requestBody, name string) ruleBody {
	t.Helper()

	for _, rule := range body.Rules {
		if rule.Name == name {
			return rule
		}
	}

	t.Fatalf("no rule %q in %+v", name, body.Rules)

	return ruleBody{}
}

// referencedARNs returns the IP set ARNs a rule's statement references.
func referencedARNs(rule ruleBody) []string {
	statements := []statementBody{rule.Statement}
	if rule.Statement.OrStatement != nil {
		statements = rule.Statement.OrStatement.Statements
	}

	var arns []string

	for _, s := range statements {
		if s.IPSetReferenceStatement != nil {
			arns = append(arns, s.IPSetReferenceStatement.ARN)
		}
	}

	return arns
}

func TestUnbanUpdatesOnlyTheSetHoldingTheIP(t *testing.T) {
	t.Parallel()

	f, client := newFakeWAF(t)
	w := newTestWAF(client,
		committedSet(client, "IPV4", "set-1", "192.0.2.1"),
		committedSet(client, "IPV4", "set-2", "192.0.2.2", "192.0.2.3"),
		committedSet(client, "IPV4", "set-3", "192.0.2.4"),
		committedSet(client, "IPV6", "set-4", "2001:db8::1"),
	)

	err := w.UpdateSetsContent(t.Context(), Decisions{
		V4Del: map[string][]*string{"ban": {aws.String("192.0.2.2")}},
	})
	if err != nil {
		t.Fatalf("UpdateSetsContent: %s", err)
	}

	updates := f.calls("UpdateIPSet")
	if len(updates) != 1 {
		t.Fatalf("UpdateIPSet calls = %d, want 1", len(updates))
	}

	if got := updates[0].ID; got != "set-2" {
		t.Errorf("UpdateIPSet Id = %s, want set-2", got)
	}

	if got, want := updates[0].Addresses, []string{"192.0.2.3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("UpdateIPSet Addresses = %v, want %v", got, want)
	}
}

func TestRuleGroupUpdatedOnlyWhenReferencedSetsChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		sets          func(client *wafv2.Client) []*WAFIpSet
		failFirstSync bool
		next          Decisions
		wantWrites    int
		wantARNs      []string
	}{
		{
			name: "membership change only",
			sets: func(client *wafv2.Client) []*WAFIpSet {
				return []*WAFIpSet{
					committedSet(client, "IPV4", "set-1", "192.0.2.1"),
					committedSet(client, "IPV4", "set-2", "192.0.2.2", "192.0.2.3"),
				}
			},
			next: Decisions{
				V4Add: map[string][]*string{"ban": {aws.String("192.0.2.9")}},
				V4Del: map[string][]*string{"ban": {aws.String("192.0.2.2")}},
			},
			wantWrites: 1,
			wantARNs:   []string{"arn:set-1", "arn:set-2"},
		},
		{
			name: "new set created",
			sets: func(client *wafv2.Client) []*WAFIpSet {
				return []*WAFIpSet{fullSet(client, "set-1")}
			},
			next: Decisions{
				V4Add: map[string][]*string{"ban": {aws.String("192.0.2.9")}},
			},
			wantWrites: 2,
			wantARNs:   []string{"arn:set-1", "arn:new-1"},
		},
		{
			name: "set emptied",
			sets: func(client *wafv2.Client) []*WAFIpSet {
				return []*WAFIpSet{
					committedSet(client, "IPV4", "set-1", "192.0.2.1"),
					committedSet(client, "IPV4", "set-2", "192.0.2.2"),
				}
			},
			next: Decisions{
				V4Del: map[string][]*string{"ban": {aws.String("192.0.2.2")}},
			},
			wantWrites: 2,
			wantARNs:   []string{"arn:set-1"},
		},
		{
			name: "previous write failed",
			sets: func(client *wafv2.Client) []*WAFIpSet {
				return []*WAFIpSet{committedSet(client, "IPV4", "set-1", "192.0.2.1")}
			},
			failFirstSync: true,
			wantWrites:    2,
			wantARNs:      []string{"arn:set-1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, client := newFakeWAF(t)
			w := newTestWAF(client, tc.sets(client)...)

			if tc.failFirstSync {
				f.failNext["UpdateRuleGroup"] = 1
			}

			if err := w.UpdateSetsContent(t.Context(), Decisions{}); err != nil && !tc.failFirstSync {
				t.Fatalf("first UpdateSetsContent: %s", err)
			}

			if err := w.UpdateSetsContent(t.Context(), tc.next); err != nil {
				t.Fatalf("second UpdateSetsContent: %s", err)
			}

			writes := f.calls("UpdateRuleGroup")
			if len(writes) != tc.wantWrites {
				t.Fatalf("UpdateRuleGroup calls = %d, want %d", len(writes), tc.wantWrites)
			}

			rule := findRule(t, writes[len(writes)-1], "crowdsec-rule-ban")
			if got := referencedARNs(rule); !reflect.DeepEqual(got, tc.wantARNs) {
				t.Errorf("last UpdateRuleGroup references %v, want %v", got, tc.wantARNs)
			}
		})
	}
}

func TestRulesUseConfiguredVisibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		enabled       bool
		wantRuleGroup visibility
		wantACL       visibility
	}{
		{
			name:          "metrics disabled",
			enabled:       false,
			wantRuleGroup: visibility{CloudWatchMetricsEnabled: false, SampledRequestsEnabled: false, MetricName: "crowdsec-metric-ban"},
			wantACL:       visibility{CloudWatchMetricsEnabled: false, SampledRequestsEnabled: false, MetricName: "crowdsec-metric"},
		},
		{
			name:          "metrics enabled",
			enabled:       true,
			wantRuleGroup: visibility{CloudWatchMetricsEnabled: true, SampledRequestsEnabled: true, MetricName: "crowdsec-metric-ban"},
			wantACL:       visibility{CloudWatchMetricsEnabled: true, SampledRequestsEnabled: true, MetricName: "crowdsec-metric"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, client := newFakeWAF(t)
			w := newTestWAF(client, committedSet(client, "IPV4", "set-1", "192.0.2.1"))
			w.visibilityConfig = &wafv2types.VisibilityConfig{
				CloudWatchMetricsEnabled: tc.enabled,
				SampledRequestsEnabled:   tc.enabled,
				MetricName:               aws.String("crowdsec-metric"),
			}

			if err := w.UpdateSetsContent(t.Context(), Decisions{}); err != nil {
				t.Fatalf("UpdateSetsContent: %s", err)
			}

			acl := &wafv2types.WebACL{
				Name:          aws.String("test-acl"),
				Id:            aws.String("acl-id"),
				ARN:           aws.String("arn:acl"),
				DefaultAction: &wafv2types.DefaultAction{Allow: &wafv2types.AllowAction{}},
				VisibilityConfig: &wafv2types.VisibilityConfig{
					CloudWatchMetricsEnabled: true,
					SampledRequestsEnabled:   true,
					MetricName:               aws.String("test-acl"),
				},
			}
			if err := w.AddRuleGroupToACL(t.Context(), acl, aws.String("lock")); err != nil {
				t.Fatalf("AddRuleGroupToACL: %s", err)
			}

			if got := findRule(t, f.calls("UpdateRuleGroup")[0], "crowdsec-rule-ban").VisibilityConfig; got != tc.wantRuleGroup {
				t.Errorf("rule group rule visibility = %+v, want %+v", got, tc.wantRuleGroup)
			}

			if got := findRule(t, f.calls("UpdateWebACL")[0], testRuleGroup).VisibilityConfig; got != tc.wantACL {
				t.Errorf("web ACL rule visibility = %+v, want %+v", got, tc.wantACL)
			}
		})
	}
}
