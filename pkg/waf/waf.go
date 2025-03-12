package waf

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/smithy-go/logging"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/cs-aws-waf-bouncer/pkg/cfg"
)

type WAF struct {
	config           *cfg.AclConfig
	client           *wafv2.Client
	setsInfos        map[string]IpSet
	ruleGroupsInfos  map[string]RuleGroup
	aclsInfo         map[string]Acl
	Logger           *log.Entry
	DecisionsChan    chan Decisions
	T                *tomb.Tomb
	ipsetManager     *IPSetManager
	visibilityConfig *wafv2types.VisibilityConfig
	lock             sync.Mutex
}

type IpSet struct {
	ARN string
	Id  string
}

type RuleGroup struct {
	ARN string
	Id  string
}

type Acl struct {
	ARN string
	Id  string
}

func (w *WAF) getIpSetReferenceStatement(ipsets []*WAFIpSet) *wafv2types.OrStatement {
	statements := make([]wafv2types.Statement, 0)

	for _, ipset := range ipsets {
		statements = append(statements, wafv2types.Statement{
			IPSetReferenceStatement: ipset.ToStatement(w.config.IPHeader, w.config.IPHeaderPosition),
		})
	}

	return &wafv2types.OrStatement{
		Statements: statements,
	}
}

func (w *WAF) getWafStatement(actionType string) *wafv2types.Statement {
	sets := make([]*WAFIpSet, 0)

	for _, ipset := range w.ipsetManager.IPSets {
		if ipset.GetDecisionType() == actionType && ipset.Size() > 0 {
			sets = append(sets, ipset)
		}
	}

	switch len(sets) {
	case 0:
		w.Logger.Debugf("No ipset for action %s", actionType)
		return nil
	case 1:
		w.Logger.Debugf("One ipset for action %s", actionType)

		return &wafv2types.Statement{
			IPSetReferenceStatement: sets[0].ToStatement(w.config.IPHeader, w.config.IPHeaderPosition),
		}
	default:
		w.Logger.Debugf("Multiple ipsets for action %s", actionType)

		return &wafv2types.Statement{
			OrStatement: w.getIpSetReferenceStatement(sets),
		}
	}
}

func (w *WAF) ListRuleGroups() (map[string]RuleGroup, error) {
	rg := make(map[string]RuleGroup)

	var marker *string

	for {
		output, err := w.client.ListRuleGroups(context.TODO(), &wafv2.ListRuleGroupsInput{
			Scope:      wafv2types.Scope(w.config.Scope),
			NextMarker: marker,
		})
		if err != nil {
			return nil, err
		}

		for _, ruleGroup := range output.RuleGroups {
			rg[*ruleGroup.Name] = RuleGroup{
				ARN: *ruleGroup.ARN,
				Id:  *ruleGroup.Id,
			}
		}

		if output.NextMarker == nil {
			break
		}

		marker = output.NextMarker
	}

	return rg, nil
}

func (w *WAF) CreateRuleGroup(ruleGroupName string) error {
	w.Logger.Trace("before create rule group")

	r, err := w.client.CreateRuleGroup(context.TODO(), &wafv2.CreateRuleGroupInput{
		Name:  aws.String(ruleGroupName),
		Rules: nil,
		Tags: []wafv2types.Tag{
			{
				Key:   aws.String("CrowdsecManaged"),
				Value: aws.String("true"),
			},
		},
		Scope:            wafv2types.Scope(w.config.Scope),
		Capacity:         aws.Int64(int64(w.config.Capacity)), //FIXME: Automatically set capacity if not provided by the user
		VisibilityConfig: w.visibilityConfig,
	})
	if err != nil {
		return err
	}

	w.ruleGroupsInfos[ruleGroupName] = RuleGroup{
		ARN: *r.Summary.ARN,
		Id:  *r.Summary.Id,
	}

	return nil
}

func (w *WAF) UpdateRuleGroup() error {
	rules := make([]wafv2types.Rule, 0)
	priority := 0

	if len(w.ipsetManager.IPSets) == 0 {
		w.Logger.Debugf("No IPSets to add to rule group %s", w.config.RuleGroupName)
		return nil
	}

	token, rg, err := w.GetRuleGroup(w.config.RuleGroupName)

	if err != nil {
		return fmt.Errorf("failed to get rule group: %w", err)
	}

	for _, rule := range rg.Rules {
		if *rule.Name != "crowdsec-rule-ban" && *rule.Name != "crowdsec-rule-captcha" && *rule.Name != "crowdsec-rule-count" {
			spew.Dump(rule)
			rules = append(rules, rule)
		}
	}

	for _, actionType := range cfg.ValidActions {
		statement := w.getWafStatement(actionType)
		if statement != nil {
			r := wafv2types.Rule{
				Name:      aws.String(fmt.Sprintf("crowdsec-rule-%s", actionType)),
				Action:    w.getRuleAction(actionType),
				Statement: statement,
				Priority:  int32(priority),
				VisibilityConfig: &wafv2types.VisibilityConfig{
					SampledRequestsEnabled:   false,
					CloudWatchMetricsEnabled: false,
					MetricName:               aws.String(w.config.RuleGroupName),
				},
			}
			priority++

			rules = append(rules, r)
		}
	}

	if len(rules) == 0 {
		w.Logger.Infof("Removing all rules from group %s", w.config.RuleGroupName)
	}

	_, err = w.client.UpdateRuleGroup(context.TODO(), &wafv2.UpdateRuleGroupInput{
		Name:             aws.String(w.config.RuleGroupName),
		Rules:            rules,
		Scope:            wafv2types.Scope(w.config.Scope),
		VisibilityConfig: rg.VisibilityConfig,
		Id:               aws.String(w.ruleGroupsInfos[w.config.RuleGroupName].Id),
		LockToken:        aws.String(token),
	})
	if err != nil {
		return err
	}

	return nil
}

func (w *WAF) DeleteRuleGroup(ruleGroupName string, token string, id string) error {
	_, err := w.client.DeleteRuleGroup(context.TODO(), &wafv2.DeleteRuleGroupInput{
		Name:      aws.String(ruleGroupName),
		Scope:     wafv2types.Scope(w.config.Scope),
		LockToken: aws.String(token),
		Id:        aws.String(id),
	})

	return err
}

func (w *WAF) ListWebACL() (map[string]Acl, error) {
	acls := make(map[string]Acl)

	r, err := w.client.ListWebACLs(context.TODO(), &wafv2.ListWebACLsInput{
		Scope: wafv2types.Scope(w.config.Scope),
	})
	if err != nil {
		return nil, err
	}

	for _, acl := range r.WebACLs {
		acls[*acl.Name] = Acl{
			ARN: *acl.ARN,
			Id:  *acl.Id,
		}
	}

	return acls, nil
}

func (w *WAF) GetWebACL(aclName string, id string) (*wafv2types.WebACL, *string, error) {
	r, err := w.client.GetWebACL(context.TODO(), &wafv2.GetWebACLInput{
		Name:  aws.String(aclName),
		Scope: wafv2types.Scope(w.config.Scope),
		Id:    aws.String(id),
	})
	if err != nil {
		return nil, nil, err
	}

	return r.WebACL, r.LockToken, nil
}

func (w *WAF) ListIpSet() (map[string]IpSet, error) {
	sets := make(map[string]IpSet)

	r, err := w.client.ListIPSets(context.TODO(), &wafv2.ListIPSetsInput{
		Scope: wafv2types.Scope(w.config.Scope),
	})
	if err != nil {
		return nil, err
	}

	for _, set := range r.IPSets {
		sets[*set.Name] = IpSet{
			ARN: *set.ARN,
			Id:  *set.Id,
		}
	}

	return sets, nil
}

func (w *WAF) getRuleAction(actionType string) *wafv2types.RuleAction {
	switch actionType {
	case "ban":
		return &wafv2types.RuleAction{
			Block: &wafv2types.BlockAction{},
		}
	case "captcha":
		return &wafv2types.RuleAction{
			Captcha: &wafv2types.CaptchaAction{},
		}
	case "count":
		return &wafv2types.RuleAction{
			Count: &wafv2types.CountAction{},
		}
	}

	return nil
}

func (w *WAF) getPriority(acl *wafv2types.WebACL) int32 {
	// Find the lowest available priority
	lowest := int32(0)

	for _, rule := range acl.Rules {
		w.Logger.Debugf("Rule %s has priority %d", *rule.Name, rule.Priority)

		if rule.Priority > lowest {
			lowest = rule.Priority
		}
	}

	return lowest + 1
}

func (w *WAF) AddRuleGroupToACL(acl *wafv2types.WebACL, token *string) error {
	var newRules []wafv2types.Rule
	newRules = append(newRules, acl.Rules...)

	w.Logger.Infof("Adding RuleGroup %s to ACL %s", w.config.RuleGroupName, *acl.Name)

	rule := wafv2types.Rule{
		Name:     aws.String(w.config.RuleGroupName),
		Priority: w.getPriority(acl),
		VisibilityConfig: &wafv2types.VisibilityConfig{
			CloudWatchMetricsEnabled: false,
			MetricName:               aws.String(w.config.RuleGroupName),
			SampledRequestsEnabled:   false,
		},
		Statement: &wafv2types.Statement{
			RuleGroupReferenceStatement: &wafv2types.RuleGroupReferenceStatement{
				ARN: aws.String(w.ruleGroupsInfos[w.config.RuleGroupName].ARN),
			},
		},
		OverrideAction: &wafv2types.OverrideAction{
			None: &wafv2types.NoneAction{},
		},
	}

	newRules = append(newRules, rule)

	var description *string = nil
	if acl.Description != nil && *acl.Description != "" {
		description = acl.Description
	}

	_, err := w.client.UpdateWebACL(context.TODO(), &wafv2.UpdateWebACLInput{
		AssociationConfig:    acl.AssociationConfig,
		ChallengeConfig:      acl.ChallengeConfig,
		TokenDomains:         acl.TokenDomains,
		CaptchaConfig:        acl.CaptchaConfig,
		CustomResponseBodies: acl.CustomResponseBodies,
		DefaultAction:        acl.DefaultAction,
		Description:          description,
		Id:                   acl.Id,
		LockToken:            token,
		Name:                 acl.Name,
		Rules:                newRules,
		Scope:                wafv2types.Scope(w.config.Scope),
		VisibilityConfig:     acl.VisibilityConfig,
	})
	if err != nil {
		return err
	}

	w.Logger.Debugf("RuleGroup %s added to ACL %s", w.config.RuleGroupName, *acl.Name)

	return nil
}

func (w *WAF) RemoveRuleGroupFromACL(acl *wafv2types.WebACL, token *string) error {
	var newRules []wafv2types.Rule

	w.Logger.Debugf("Removing rule group %s from ACL %s", w.config.RuleGroupName, *acl.Name)

	for _, rule := range acl.Rules {
		if *rule.Name != w.config.RuleGroupName {
			spew.Dump(rule)
			newRules = append(newRules, rule)
		}
	}

	spew.Dump(acl)

	var description *string = nil
	if acl.Description != nil && *acl.Description != "" {
		description = acl.Description
	}

	_, err := w.client.UpdateWebACL(context.TODO(), &wafv2.UpdateWebACLInput{
		AssociationConfig:    acl.AssociationConfig,
		ChallengeConfig:      acl.ChallengeConfig,
		TokenDomains:         acl.TokenDomains,
		CaptchaConfig:        acl.CaptchaConfig,
		CustomResponseBodies: acl.CustomResponseBodies,
		DefaultAction:        acl.DefaultAction,
		Description:          description,
		Id:                   acl.Id,
		LockToken:            token,
		Name:                 acl.Name,
		Rules:                newRules,
		Scope:                wafv2types.Scope(w.config.Scope),
		VisibilityConfig:     acl.VisibilityConfig,
	})
	if err != nil {
		return err
	}

	return nil
}

func (w *WAF) GetRuleGroup(ruleGroupname string) (string, wafv2types.RuleGroup, error) {
	r, err := w.client.GetRuleGroup(context.TODO(), &wafv2.GetRuleGroupInput{
		Name:  aws.String(ruleGroupname),
		Scope: wafv2types.Scope(w.config.Scope),
		ARN:   aws.String(w.ruleGroupsInfos[ruleGroupname].ARN),
	})
	if err != nil {
		return "", wafv2types.RuleGroup{}, err
	}

	return *r.LockToken, *r.RuleGroup, nil
}

func (w *WAF) CleanupAcl(acl *wafv2types.WebACL, token *string) error {
	err := w.RemoveRuleGroupFromACL(acl, token)
	if err != nil {
		return fmt.Errorf("error removing rule group from ACL: %w", err)
	}

	if _, ok := w.ruleGroupsInfos[w.config.RuleGroupName]; ok {
		token, _, err := w.GetRuleGroup(w.config.RuleGroupName)
		if err != nil {
			return fmt.Errorf("failed to get RuleGroup %s: %w", w.config.RuleGroupName, err)
		}

		w.Logger.Debugf("Deleting RuleGroup %s", w.config.RuleGroupName)

		err = w.DeleteRuleGroup(w.config.RuleGroupName, token, w.ruleGroupsInfos[w.config.RuleGroupName].Id)
		if err != nil {
			return fmt.Errorf("failed to delete RuleGroup %s: %w", w.config.RuleGroupName, err)
		}
	} else {
		log.Debugf("RuleGroup %s not found, nothing to do", w.config.RuleGroupName)
	}

	w.ipsetManager.DeleteSets()

	return nil
}

func (w *WAF) Cleanup() error {
	var err error

	w.lock.Lock()
	defer w.lock.Unlock()

	w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListResources()
	if err != nil {
		return fmt.Errorf("failed to list WAF resources: %w", err)
	}

	acl, token, err := w.GetWebACL(w.config.WebACLName, w.aclsInfo[w.config.WebACLName].Id)
	if err != nil {
		return fmt.Errorf("failed to get WebACL: %w", err)
	}

	return w.CleanupAcl(acl, token)
}

func (w *WAF) ListResources() (map[string]Acl, map[string]IpSet, map[string]RuleGroup, error) {
	var err error

	acls, err := w.ListWebACL()
	if err != nil {
		return nil, nil, nil, err
	}

	sets, err := w.ListIpSet()
	if err != nil {
		return nil, nil, nil, err
	}

	rgs, err := w.ListRuleGroups()
	if err != nil {
		return nil, nil, nil, err
	}

	return acls, sets, rgs, nil
}

func (w *WAF) Init() error {
	var err error
	w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListResources()

	if err != nil {
		return fmt.Errorf("failed to list resources: %w", err)
	}

	w.Logger.Tracef("Found %d WebACLs", len(w.aclsInfo))
	w.Logger.Tracef("ACLs: %+v", w.aclsInfo)

	w.Logger.Tracef("Found %d IPSets", len(w.setsInfos))
	w.Logger.Tracef("IPSets: %+v", w.setsInfos)

	w.Logger.Tracef("Found %d RuleGroups", len(w.ruleGroupsInfos))
	w.Logger.Tracef("RuleGroups: %+v", w.ruleGroupsInfos)

	if _, ok := w.aclsInfo[w.config.WebACLName]; !ok {
		return fmt.Errorf("WebACL %s does not exist in region %s", w.config.WebACLName, w.config.Region)
	}

	acl, token, err := w.GetWebACL(w.config.WebACLName, w.aclsInfo[w.config.WebACLName].Id)

	if err != nil {
		return fmt.Errorf("failed to get WebACL: %w", err)
	}

	w.ipsetManager = NewIPSetManager(w.config.IpsetPrefix, w.config.Scope, w.client, w.Logger)

	err = w.CleanupAcl(acl, token)

	if err != nil {
		return fmt.Errorf("failed to cleanup: %w", err)
	}

	w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListResources()

	if err != nil {
		return fmt.Errorf("failed to list resources: %w", err)
	}

	err = w.CreateRuleGroup(w.config.RuleGroupName)

	if err != nil {
		return fmt.Errorf("failed to create RuleGroup %s: %w", w.config.RuleGroupName, err)
	}

	w.Logger.Infof("RuleGroup %s created", w.config.RuleGroupName)

	acl, lockTocken, err := w.GetWebACL(w.config.WebACLName, w.aclsInfo[w.config.WebACLName].Id)

	if err != nil {
		return fmt.Errorf("failed to get WebACL %s: %w", w.config.WebACLName, err)
	}

	err = w.AddRuleGroupToACL(acl, lockTocken)

	if err != nil {
		return fmt.Errorf("failed to add RuleGroup %s to WebACL %s: %w", w.config.RuleGroupName, w.config.WebACLName, err)
	}

	return nil
}

func (w *WAF) UpdateSetsContent(d Decisions) error {
	var err error

	for action, ips := range d.V4Add {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}

		for _, ip := range ips {
			w.ipsetManager.AddIp(*ip, action)
		}
	}

	for action, ips := range d.V4Del {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}

		for _, ip := range ips {
			w.ipsetManager.DeleteIp(*ip, action)
		}
	}

	for action, ips := range d.V6Add {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}

		for _, ip := range ips {
			w.ipsetManager.AddIp(*ip, action)
		}
	}

	for action, ips := range d.V6Del {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}

		for _, ip := range ips {
			w.ipsetManager.DeleteIp(*ip, action)
		}
	}

	err = w.ipsetManager.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit ipset changes: %w", err)
	}

	err = w.UpdateRuleGroup()

	if err != nil {
		return fmt.Errorf("failed to update RuleGroup %s: %w", w.config.RuleGroupName, err)
	}

	w.ipsetManager.DeleteEmptySets()

	return nil
}

func (w *WAF) UpdateGeoSet(d Decisions) error {
	if len(d.CountriesAdd) == 0 && len(d.CountriesDel) == 0 {
		return nil
	}

	rules := make(map[string]wafv2types.Rule)
	decisions := make(map[string][]wafv2types.CountryCode)

	priority := 50

	token, rg, err := w.GetRuleGroup(w.config.RuleGroupName)
	if err != nil {
		return fmt.Errorf("failed to get RuleGroup  %s for geoset update: %w", w.config.WebACLName, err)
	}

	for _, rule := range rg.Rules {
		switch *rule.Name {
		case "crowdsec-rule-country-captcha":
			rules["captcha"] = rule
		case "crowdsec-rule-country-ban":
			rules["ban"] = rule
		case "crowdsec-rule-country-count":
			rules["count"] = rule
		}
	}

	for _, action := range cfg.ValidActions {
		decisions[action] = make([]wafv2types.CountryCode, 0)
		decisions[action] = append(decisions[action], d.CountriesAdd[action]...)

		if w.config.FallbackAction == action && len(d.CountriesAdd["fallback"]) > 0 {
			decisions[action] = append(decisions[action], d.CountriesAdd["fallback"]...)
		}

		// We don't currently have a rule for countries for this action
		if _, ok := rules[action]; !ok && len(decisions[action]) > 0 {
			w.Logger.Infof("Creating rule %s for action %s", "crowdsec-rule-country-"+action, action)
			rules[action] = wafv2types.Rule{
				Name: aws.String("crowdsec-rule-country-" + action),
				Statement: &wafv2types.Statement{
					GeoMatchStatement: &wafv2types.GeoMatchStatement{
						CountryCodes: uniqueSlice(decisions[action]),
					},
				},
				Priority:         int32(priority), //FIXME: get the priority dynamically, but it does not really matter as we managed the rulegroup ourselves
				VisibilityConfig: rg.VisibilityConfig,
				Action:           w.getRuleAction(action),
			}
			rg.Rules = append(rg.Rules, rules[action])
		} else if _, ok := rules[action]; ok { // We have a rule for this action
			w.Logger.Infof("Updating rule %s for action %s", *rules[action].Name, action)
			decisions[action] = append(decisions[action], rules[action].Statement.GeoMatchStatement.CountryCodes...)

			for _, c := range d.CountriesDel[action] {
				decisions[action] = slices.DeleteFunc(decisions[action], func(cn wafv2types.CountryCode) bool {
					return cn == c
				})
			}

			if len(d.CountriesDel["fallback"]) > 0 && w.config.FallbackAction == action {
				for _, c := range d.CountriesDel["fallback"] {
					decisions[action] = slices.DeleteFunc(decisions[action], func(cn wafv2types.CountryCode) bool {
						return cn == c
					})
				}
			}
		}

		priority++

		w.Logger.Debugf("Decisions for action %s: %+v", action, decisions[action])

		if _, ok := rules[action]; ok && len(decisions[action]) == 0 {
			w.Logger.Infof("Removing rule %s for action %s", *rules[action].Name, action)
			rg.Rules = removeRuleFromRuleGroup(rg.Rules, *rules[action].Name)
		} else if len(decisions[action]) > 0 {
			w.Logger.Debugf("Updating rule %s for action %s with countries %v", *rules[action].Name, action, decisions[action])
			rules[action].Statement.GeoMatchStatement.CountryCodes = uniqueSlice(decisions[action])
		}
	}

	_, err = w.client.UpdateRuleGroup(context.TODO(), &wafv2.UpdateRuleGroupInput{
		Name:             rg.Name,
		Rules:            rg.Rules,
		Scope:            wafv2types.Scope(w.config.Scope),
		VisibilityConfig: rg.VisibilityConfig,
		Id:               rg.Id,
		LockToken:        aws.String(token),
	})
	if err != nil {
		return fmt.Errorf("failed to update RuleGroup  %s for geoset update: %w", w.config.WebACLName, err)
	}

	w.Logger.Debug("Updated RuleGroup for geomatch")

	return nil
}

func (w *WAF) Process() error {
	for {
		select {
		case <-w.T.Dying():
			return nil
		case <-w.T.Dead():
			w.Logger.Info("WAF process is dead")
			return nil
		case decisions := <-w.DecisionsChan:
			var err error

			w.lock.Lock()

			w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListResources()
			if err != nil {
				w.Logger.Errorf("Failed to list resources: %s", err)
				w.lock.Unlock()

				continue
			}

			err = w.UpdateSetsContent(decisions)
			if err != nil {
				w.Logger.Errorf("Failed to update IPSets: %s", err)
			}

			err = w.UpdateGeoSet(decisions)
			if err != nil {
				w.Logger.Errorf("Failed to update GeoSet: %s", err)
			}
			w.lock.Unlock()
		}
	}
}

func (w *WAF) Dump() {
	w.Logger.Debugf("WAF config: %+v", w.config)
	w.Logger.Debugf("WAF sets: %+v", w.setsInfos)
}

func NewWaf(cfg cfg.AclConfig) (*WAF, error) {
	if cfg.Scope == "CLOUDFRONT" {
		cfg.Region = "us-east-1"
	}

	logger := log.WithFields(log.Fields{
		"region": cfg.Region,
		"scope":  cfg.Scope,
		"acl":    cfg.WebACLName,
	})

	sdkLogger := logging.LoggerFunc(func(classification logging.Classification, format string, v ...interface{}) {
		switch classification {
		case logging.Debug:
			logger.WithField("component", "aws-sdk").Debugf(format, v...)
		case logging.Warn:
			logger.WithField("component", "aws-sdk").Warnf(format, v...)
		default:
			logger.WithField("component", "aws-sdk").Infof(format, v...)
		}
	})

	w := &WAF{
		setsInfos:       make(map[string]IpSet),
		aclsInfo:        make(map[string]Acl),
		ruleGroupsInfos: make(map[string]RuleGroup),
		Logger:          logger,
		DecisionsChan:   make(chan Decisions),
	}

	logMode := aws.LogRetries

	if logger.Logger.IsLevelEnabled(log.TraceLevel) {
		logMode = aws.LogRequestWithBody
	}

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(cfg.Region),
		config.WithRetryer(func() aws.Retryer {
			return retry.AddWithErrorCodes(retry.NewStandard(), (*wafv2types.WAFUnavailableEntityException)(nil).ErrorCode())
		}),
		config.WithLogger(sdkLogger),
		config.WithClientLogMode(logMode),
	}

	if cfg.AWSProfile != "" {
		opts = append(opts, config.WithSharedConfigProfile(cfg.AWSProfile))
	}

	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		opts...,
	)

	if err != nil {
		return nil, err
	}

	client := wafv2.NewFromConfig(awsCfg)
	w.client = client
	w.config = &cfg
	w.T = &tomb.Tomb{}

	metricName := w.config.RuleGroupName
	if w.config.CloudWatchMetricName != "" {
		metricName = w.config.CloudWatchMetricName
	}

	w.visibilityConfig = &wafv2types.VisibilityConfig{
		SampledRequestsEnabled:   w.config.SampleRequests,
		CloudWatchMetricsEnabled: w.config.CloudWatchEnabled,
		MetricName:               aws.String(metricName),
	}

	w.T.Go(w.Process)

	return w, nil
}
