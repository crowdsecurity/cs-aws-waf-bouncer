package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type WAF struct {
	config           *AclConfig
	client           *wafv2.WAFV2
	setsInfos        map[string]IpSet
	ruleGroupsInfos  map[string]RuleGroup
	aclsInfo         map[string]Acl
	logger           *log.Entry
	decisionsChan    chan Decisions
	t                *tomb.Tomb
	ipsetManager     *IPSetManager
	visibilityConfig *wafv2.VisibilityConfig
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

func (w *WAF) getIpSetReferenceStatement(ipsets []*WAFIpSet) *wafv2.OrStatement {
	statements := make([]*wafv2.Statement, 0)

	for _, ipset := range ipsets {
		statements = append(statements, &wafv2.Statement{
			IPSetReferenceStatement: ipset.ToStatement(w.config.IPHeader, w.config.IPHeaderPosition),
		})
	}
	return &wafv2.OrStatement{
		Statements: statements,
	}
}

func (w *WAF) getWafStatement(actionType string) *wafv2.Statement {
	sets := make([]*WAFIpSet, 0)
	for _, ipset := range w.ipsetManager.IPSets {
		if ipset.GetDecisionType() == actionType && ipset.Size() > 0 {
			sets = append(sets, ipset)
		}
	}
	if len(sets) == 0 {
		w.logger.Debugf("No ipset for action %s", actionType)
		return nil
	} else if len(sets) == 1 {
		w.logger.Debugf("One ipset for action %s", actionType)
		return &wafv2.Statement{
			IPSetReferenceStatement: sets[0].ToStatement(w.config.IPHeader, w.config.IPHeaderPosition),
		}
	} else {
		w.logger.Debugf("Multiple ipsets for action %s", actionType)
		return &wafv2.Statement{
			OrStatement: w.getIpSetReferenceStatement(sets),
		}
	}
}

func (w *WAF) ListRuleGroups() (map[string]RuleGroup, error) {
	rg := make(map[string]RuleGroup)
	var marker *string
	for {
		output, err := w.client.ListRuleGroups(&wafv2.ListRuleGroupsInput{
			Scope:      aws.String(w.config.Scope),
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

	maxRetries := 5

	for {
		w.logger.Trace("before create rule group")
		r, err := w.client.CreateRuleGroup(&wafv2.CreateRuleGroupInput{
			Name:  aws.String(ruleGroupName),
			Rules: nil,
			Tags: []*wafv2.Tag{
				{
					Key:   aws.String("CrowdsecManaged"),
					Value: aws.String("true"),
				},
			},
			Scope:            aws.String(w.config.Scope),
			Capacity:         aws.Int64(int64(w.config.Capacity)), //FIXME: Automatically set capacity if not provided by the user
			VisibilityConfig: w.visibilityConfig,
		})
		if err != nil {
			switch err.(type) {
			case *wafv2.WAFUnavailableEntityException:
				if maxRetries > 0 {
					maxRetries -= 1
					log.Warnf("Dependencies of rule group %s not ready yet, retrying in 2 seconds", w.config.RuleGroupName)
					time.Sleep(2 * time.Second)
					continue
				} else {
					return fmt.Errorf("WAF is not ready yet, giving up")
				}
			default:
				return err
			}
		}
		w.ruleGroupsInfos[ruleGroupName] = RuleGroup{
			ARN: *r.Summary.ARN,
			Id:  *r.Summary.Id,
		}
		break
	}
	return nil
}

func (w *WAF) UpdateRuleGroup() error {
	rules := make([]*wafv2.Rule, 0)
	priority := 0
	maxRetries := 5

	if len(w.ipsetManager.IPSets) == 0 {
		w.logger.Debugf("No IPSets to add to rule group %s", w.config.RuleGroupName)
		return nil
	}

	token, rg, err := w.GetRuleGroup(w.config.RuleGroupName)

	if err != nil {
		return err
	}

	for _, rule := range rg.Rules {
		if *rule.Name != "crowdsec-rule-ban" && *rule.Name != "crowdsec-rule-captcha" && *rule.Name != "crowdsec-rule-count" {
			rules = append(rules, rule)
		}
	}

	for _, actionType := range validActions {
		statement := w.getWafStatement(actionType)
		if statement != nil {
			r := &wafv2.Rule{
				Name:      aws.String(fmt.Sprintf("crowdsec-rule-%s", actionType)),
				Action:    w.getRuleAction(actionType),
				Statement: statement,
				Priority:  aws.Int64(int64(priority)),
				VisibilityConfig: &wafv2.VisibilityConfig{
					SampledRequestsEnabled:   aws.Bool(false),
					CloudWatchMetricsEnabled: aws.Bool(false),
					MetricName:               aws.String(w.config.RuleGroupName),
				},
			}
			priority++
			rules = append(rules, r)
		}
	}

	if len(rules) == 0 {
		w.logger.Infof("Removing all rules from group %s", w.config.RuleGroupName)
	}

	for {
		if maxRetries <= 0 {
			return fmt.Errorf("WAF is not ready yet, giving up")
		}
		_, err = w.client.UpdateRuleGroup(&wafv2.UpdateRuleGroupInput{
			Name:             aws.String(w.config.RuleGroupName),
			Rules:            rules,
			Scope:            aws.String(w.config.Scope),
			VisibilityConfig: rg.VisibilityConfig,
			Id:               aws.String(w.ruleGroupsInfos[w.config.RuleGroupName].Id),
			LockToken:        aws.String(token),
		})
		if err != nil {
			switch err.(type) {
			case *wafv2.WAFUnavailableEntityException:
				log.Warnf("Dependencies of rule group %s not ready yet, retrying in 2 seconds", w.config.RuleGroupName)
				time.Sleep(2 * time.Second)
				maxRetries--
				continue
			default:
				return err
			}
		}
		return nil
	}
}

func (w *WAF) DeleteRuleGroup(ruleGroupName string, token string, id string) error {
	_, err := w.client.DeleteRuleGroup(&wafv2.DeleteRuleGroupInput{
		Name:      aws.String(ruleGroupName),
		Scope:     aws.String(w.config.Scope),
		LockToken: aws.String(token),
		Id:        aws.String(id),
	})
	return err
}

func (w *WAF) ListWebACL() (map[string]Acl, error) {
	acls := make(map[string]Acl)
	r, err := w.client.ListWebACLs(&wafv2.ListWebACLsInput{
		Scope: aws.String(w.config.Scope),
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

func (w *WAF) GetWebACL(aclName string, id string) (*wafv2.WebACL, *string, error) {
	r, err := w.client.GetWebACL(&wafv2.GetWebACLInput{
		Name:  aws.String(aclName),
		Scope: aws.String(w.config.Scope),
		Id:    aws.String(id),
	})
	if err != nil {
		return nil, nil, err
	}
	return r.WebACL, r.LockToken, nil
}

func (w *WAF) ListIpSet() (map[string]IpSet, error) {
	sets := make(map[string]IpSet)
	r, err := w.client.ListIPSets(&wafv2.ListIPSetsInput{
		Scope: aws.String(w.config.Scope),
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

func (w *WAF) getRuleAction(actionType string) *wafv2.RuleAction {
	switch actionType {
	case "ban":
		return &wafv2.RuleAction{
			Block: &wafv2.BlockAction{},
		}
	case "captcha":
		return &wafv2.RuleAction{
			Captcha: &wafv2.CaptchaAction{},
		}
	case "count":
		return &wafv2.RuleAction{
			Count: &wafv2.CountAction{},
		}
	}

	return nil
}

func (w *WAF) getPriority(acl *wafv2.WebACL) int64 {
	//Find the lowest available priority
	lowest := int64(0)
	for _, rule := range acl.Rules {
		w.logger.Debugf("Rule %s has priority %d", *rule.Name, *rule.Priority)
		if *rule.Priority > lowest {
			lowest = *rule.Priority
		}
	}
	return lowest + 1
}

func (w *WAF) AddRuleGroupToACL(acl *wafv2.WebACL, token *string) error {
	var newRules []*wafv2.Rule
	newRules = append(newRules, acl.Rules...)
	maxRetries := 5

	w.logger.Infof("Adding RuleGroup %s to ACL %s", w.config.RuleGroupName, *acl.Name)

	rule := wafv2.Rule{
		Name:     aws.String(w.config.RuleGroupName),
		Priority: aws.Int64(w.getPriority(acl)),
		VisibilityConfig: &wafv2.VisibilityConfig{
			CloudWatchMetricsEnabled: aws.Bool(false),
			MetricName:               aws.String(w.config.RuleGroupName),
			SampledRequestsEnabled:   aws.Bool(false),
		},
		Statement: &wafv2.Statement{
			RuleGroupReferenceStatement: &wafv2.RuleGroupReferenceStatement{
				ARN: aws.String(w.ruleGroupsInfos[w.config.RuleGroupName].ARN),
			},
		},
		OverrideAction: &wafv2.OverrideAction{
			None: &wafv2.NoneAction{},
		},
	}

	newRules = append(newRules, &rule)

	for {
		_, err := w.client.UpdateWebACL(&wafv2.UpdateWebACLInput{
			CaptchaConfig:        acl.CaptchaConfig,
			CustomResponseBodies: acl.CustomResponseBodies,
			DefaultAction:        acl.DefaultAction,
			Description:          nil,
			Id:                   acl.Id,
			LockToken:            token,
			Name:                 acl.Name,
			Rules:                newRules,
			Scope:                aws.String(w.config.Scope),
			VisibilityConfig:     acl.VisibilityConfig,
		})
		if err != nil {
			switch err.(type) {
			case *wafv2.WAFUnavailableEntityException:
				if maxRetries > 0 {
					maxRetries -= 1
					log.Warnf("rule group %s is not ready yet, retrying in 2 seconds", w.config.RuleGroupName)
					time.Sleep(2 * time.Second)
					continue
				} else {
					return fmt.Errorf("rule group %s is not ready, giving up", w.config.RuleGroupName)
				}
			default:
				return err
			}
		}
		break
	}
	w.logger.Debugf("RuleGroup %s added to ACL %s", w.config.RuleGroupName, *acl.Name)
	return nil
}

func (w *WAF) RemoveRuleGroupFromACL(acl *wafv2.WebACL, token *string) error {
	var newRules []*wafv2.Rule

	w.logger.Debugf("Removing rule group %s from ACL %s", w.config.RuleGroupName, *acl.Name)
	for _, rule := range acl.Rules {
		if *rule.Name != w.config.RuleGroupName {
			newRules = append(newRules, rule)
		}
	}
	_, err := w.client.UpdateWebACL(&wafv2.UpdateWebACLInput{
		CaptchaConfig:        acl.CaptchaConfig,
		CustomResponseBodies: acl.CustomResponseBodies,
		DefaultAction:        acl.DefaultAction,
		Description:          nil,
		Id:                   acl.Id,
		LockToken:            token,
		Name:                 acl.Name,
		Rules:                newRules,
		Scope:                aws.String(w.config.Scope),
		VisibilityConfig:     acl.VisibilityConfig,
	})
	if err != nil {
		return err
	}
	return nil
}

func (w *WAF) GetRuleGroup(ruleGroupname string) (string, wafv2.RuleGroup, error) {
	r, err := w.client.GetRuleGroup(&wafv2.GetRuleGroupInput{
		Name:  aws.String(ruleGroupname),
		Scope: aws.String(w.config.Scope),
		ARN:   aws.String(w.ruleGroupsInfos[ruleGroupname].ARN),
	})
	if err != nil {
		return "", wafv2.RuleGroup{}, err
	}
	return *r.LockToken, *r.RuleGroup, nil
}

func (w *WAF) CleanupAcl(acl *wafv2.WebACL, token *string) error {
	err := w.RemoveRuleGroupFromACL(acl, token)

	if err != nil {
		return errors.Wrapf(err, "Error removing rule group from ACL")
	}
	if _, ok := w.ruleGroupsInfos[w.config.RuleGroupName]; ok {
		token, _, err := w.GetRuleGroup(w.config.RuleGroupName)
		if err != nil {
			return errors.Wrapf(err, "Failed to get RuleGroup %s", w.config.RuleGroupName)
		}
		w.logger.Debugf("Deleting RuleGroup %s", w.config.RuleGroupName)
		err = w.DeleteRuleGroup(w.config.RuleGroupName, token, w.ruleGroupsInfos[w.config.RuleGroupName].Id)
		if err != nil {
			return errors.Wrapf(err, "Failed to delete RuleGroup %s", w.config.RuleGroupName)
		}
	} else {
		log.Debugf("RuleGroup %s not found, nothing to do", w.config.RuleGroupName)
	}

	if err != nil {
		return errors.Wrapf(err, "Failed to list IPSets")
	}

	w.ipsetManager.DeleteSets()

	return nil
}

func (w *WAF) Cleanup() error {
	var err error
	w.lock.Lock()
	defer w.lock.Unlock()
	w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListRessources()
	if err != nil {
		return errors.Wrapf(err, "Failed to list WAF resources")
	}
	acl, token, err := w.GetWebACL(w.config.WebACLName, w.aclsInfo[w.config.WebACLName].Id)
	if err != nil {
		return errors.Wrapf(err, "Failed to get WebACL")
	}
	return w.CleanupAcl(acl, token)
}

func (w *WAF) ListRessources() (map[string]Acl, map[string]IpSet, map[string]RuleGroup, error) {
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
	w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListRessources()

	if err != nil {
		return fmt.Errorf("failed to list ressources: %s", err)
	}

	w.logger.Tracef("Found %d WebACLs", len(w.aclsInfo))
	w.logger.Tracef("ACLs: %+v", w.aclsInfo)

	w.logger.Tracef("Found %d IPSets", len(w.setsInfos))
	w.logger.Tracef("IPSets: %+v", w.setsInfos)

	w.logger.Tracef("Found %d RuleGroups", len(w.ruleGroupsInfos))
	w.logger.Tracef("RuleGroups: %+v", w.ruleGroupsInfos)

	if _, ok := w.aclsInfo[w.config.WebACLName]; !ok {
		return fmt.Errorf("WebACL %s does not exist in region %s", w.config.WebACLName, w.config.Region)
	}

	acl, token, err := w.GetWebACL(w.config.WebACLName, w.aclsInfo[w.config.WebACLName].Id)

	if err != nil {
		return errors.Wrap(err, "Failed to get WebACL")
	}

	w.ipsetManager = NewIPSetManager(w.config.IpsetPrefix, w.config.Scope, w.client, w.logger)

	err = w.CleanupAcl(acl, token)

	if err != nil {
		return errors.Wrap(err, "Failed to cleanup")
	}

	w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListRessources()

	if err != nil {
		return fmt.Errorf("failed to list ressources: %s", err)
	}

	err = w.CreateRuleGroup(w.config.RuleGroupName)

	if err != nil {
		return errors.Wrapf(err, "Failed to create RuleGroup %s", w.config.RuleGroupName)
	}

	acl, lockTocken, err := w.GetWebACL(w.config.WebACLName, w.aclsInfo[w.config.WebACLName].Id)

	if err != nil {
		return errors.Wrapf(err, "Failed to get WebACL %s", w.config.WebACLName)
	}

	err = w.AddRuleGroupToACL(acl, lockTocken)

	if err != nil {
		return errors.Wrapf(err, "Failed to add RuleGroup %s to WebACL %s", w.config.RuleGroupName, w.config.WebACLName)
	}

	if err != nil {
		return fmt.Errorf("failed to list ressources: %s", err)
	}

	return nil
}

func (w *WAF) UpdateSetsContent(d Decisions) error {
	var err error

	if err != nil {
		return fmt.Errorf("failed to list ressources: %s", err)
	}

	for action, ips := range d.v4Add {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}
		for _, ip := range ips {
			w.ipsetManager.AddIp(*ip, action)
		}
	}

	for action, ips := range d.v4Del {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}
		for _, ip := range ips {
			w.ipsetManager.DeleteIp(*ip, action)
		}
	}

	for action, ips := range d.v6Add {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}
		for _, ip := range ips {
			w.ipsetManager.AddIp(*ip, action)
		}
	}

	for action, ips := range d.v6Del {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}
		for _, ip := range ips {
			w.ipsetManager.DeleteIp(*ip, action)
		}
	}
	err = w.ipsetManager.Commit()
	if err != nil {
		return errors.Wrap(err, "Failed to commit ipset changes")
	}

	err = w.UpdateRuleGroup()

	if err != nil {
		return errors.Wrapf(err, "Failed to update RuleGroup %s", w.config.RuleGroupName)
	}
	w.ipsetManager.DeleteEmptySets()
	return nil
}

func (w *WAF) UpdateGeoSet(d Decisions) error {

	if len(d.countriesAdd) == 0 && len(d.countriesDel) == 0 {
		return nil
	}

	rules := make(map[string]*wafv2.Rule)
	decisions := make(map[string][]*string)

	priority := 50

	token, rg, err := w.GetRuleGroup(w.config.RuleGroupName)
	if err != nil {
		return errors.Wrapf(err, "Failed to get RuleGroup  %s for geoset update", w.config.WebACLName)
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

	for _, action := range validActions {
		decisions[action] = make([]*string, 0)
		decisions[action] = append(decisions[action], d.countriesAdd[action]...)
		if w.config.FallbackAction == action && len(d.countriesAdd["fallback"]) > 0 {
			decisions[action] = append(decisions[action], d.countriesAdd["fallback"]...)
		}

		//We don't currently have a rule for countries for this action
		if rules[action] == nil && len(decisions[action]) > 0 {
			w.logger.Infof("Creating rule %s for action %s", "crowdsec-rule-country-"+action, action)
			rules[action] = &wafv2.Rule{
				Name: aws.String("crowdsec-rule-country-" + action),
				Statement: &wafv2.Statement{
					GeoMatchStatement: &wafv2.GeoMatchStatement{
						CountryCodes: uniqueStrPtr(decisions[action]),
					},
				},
				Priority:         aws.Int64(int64(priority)), //FIXME: get the priority dynamically, but it does not really matter as we managed the rulegroup ourselves
				VisibilityConfig: rg.VisibilityConfig,
				Action:           w.getRuleAction(action),
			}
			rg.Rules = append(rg.Rules, rules[action])

		} else if rules[action] != nil { //We have a rule for this action
			w.logger.Infof("Updating rule %s for action %s", *rules[action].Name, action)
			decisions[action] = append(decisions[action], rules[action].Statement.GeoMatchStatement.CountryCodes...)
			for _, c := range d.countriesDel[action] {
				decisions[action] = removesStringPtr(decisions[action], *c)
			}
			if len(d.countriesDel["fallback"]) > 0 && w.config.FallbackAction == action {
				for _, c := range d.countriesDel["fallback"] {
					decisions[action] = removesStringPtr(decisions[action], *c)
				}
			}
		}
		priority++
		w.logger.Debugf("Decisions for action %s: %+v", action, decisions[action])
		if len(decisions[action]) == 0 && rules[action] != nil {
			w.logger.Infof("Removing rule %s for action %s", *rules[action].Name, action)
			rg.Rules = removeRuleFromRuleGroup(rg.Rules, *rules[action].Name)
		} else if len(decisions[action]) > 0 {
			w.logger.Debugf("Updating rule %s for action %s with countries %v", *rules[action].Name, action, decisions[action])
			rules[action].Statement.GeoMatchStatement.CountryCodes = uniqueStrPtr(decisions[action])
		}
	}

	_, err = w.client.UpdateRuleGroup(&wafv2.UpdateRuleGroupInput{
		Name:             rg.Name,
		Rules:            rg.Rules,
		Scope:            aws.String(w.config.Scope),
		VisibilityConfig: rg.VisibilityConfig,
		Id:               rg.Id,
		LockToken:        aws.String(token),
	})
	if err != nil {
		return errors.Wrapf(err, "Failed to update RuleGroup  %s for geoset update", w.config.WebACLName)
	}
	w.logger.Debug("Updated RuleGroup for geomatch")

	return nil
}

func (w *WAF) Process() error {
	dontProcess := false
	for {
		select {
		case <-w.t.Dying():
			w.logger.Info("WAF process is dying")
			dontProcess = true
		case <-w.t.Dead():
			w.logger.Info("WAF process is dead")
			return nil
		case decisions := <-w.decisionsChan:
			var err error
			if dontProcess {
				continue
			}
			w.lock.Lock()
			w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListRessources()
			if err != nil {
				w.logger.Errorf("Failed to list ressources: %s", err)
				w.lock.Unlock()
				continue
			}
			err = w.UpdateSetsContent(decisions)
			if err != nil {
				w.logger.Errorf("Failed to update IPSets: %s", err)
			}

			err = w.UpdateGeoSet(decisions)
			if err != nil {
				w.logger.Errorf("Failed to update GeoSet: %s", err)
			}
			w.lock.Unlock()

		}
	}
}

func (w *WAF) Dump() {
	w.logger.Debugf("WAF config: %+v", w.config)
	w.logger.Debugf("WAF sets: %+v", w.setsInfos)
}

func NewWaf(config AclConfig) (*WAF, error) {
	var s *session.Session
	if config.Scope == "CLOUDFRONT" {
		config.Region = "us-east-1"
	}

	logger := log.WithFields(log.Fields{
		"region": config.Region,
		"scope":  config.Scope,
		"acl":    config.WebACLName,
	})

	w := &WAF{
		setsInfos:       make(map[string]IpSet),
		aclsInfo:        make(map[string]Acl),
		ruleGroupsInfos: make(map[string]RuleGroup),
		logger:          logger,
		decisionsChan:   make(chan Decisions),
	}

	if config.AWSProfile == "" {
		s = session.Must(session.NewSession(&aws.Config{
			Region:                        aws.String(config.Region),
			CredentialsChainVerboseErrors: aws.Bool(true),
		}))
	} else {
		s = session.Must(session.NewSessionWithOptions(session.Options{
			Profile: config.AWSProfile,
			Config: aws.Config{
				Region:                        aws.String(config.Region),
				CredentialsChainVerboseErrors: aws.Bool(true),
			},
		}))
	}
	client := wafv2.New(s)
	w.client = client
	w.config = &config
	w.t = &tomb.Tomb{}

	metricName := w.config.RuleGroupName
	if w.config.CloudWatchMetricName != "" {
		metricName = w.config.CloudWatchMetricName
	}
	w.visibilityConfig = &wafv2.VisibilityConfig{
		SampledRequestsEnabled:   &w.config.SampleRequests,
		CloudWatchMetricsEnabled: &w.config.CloudWatchEnabled,
		MetricName:               aws.String(metricName),
	}

	w.t.Go(w.Process)
	return w, nil
}
