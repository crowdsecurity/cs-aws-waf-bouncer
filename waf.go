package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type WAF struct {
	config          *AclConfig
	client          *wafv2.WAFV2
	setsInfos       map[string]IpSet
	ruleGroupsInfos map[string]RuleGroup
	aclsInfo        map[string]Acl
	logger          *log.Entry
	decisionsChan   chan Decisions
	t               *tomb.Tomb
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

func (w WAF) ListRuleGroups() (map[string]RuleGroup, error) {
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

func (w WAF) CreateRuleGroup(ruleGroupName string) error {

	rules := make([]*wafv2.Rule, 0)
	priority := int64(0)
	maxRetries := 5

	for _, actionType := range []string{"ban", "captcha"} {
		for _, ipType := range []string{"IPV4", "IPV6"} {
			name := aws.String(fmt.Sprintf("crowdsec-rule-%s-%s", actionType, ipType))
			setName := fmt.Sprintf("%s-%s-%s", w.config.IpsetPrefix, ipType, actionType)
			rule := &wafv2.Rule{
				Name:   name,
				Action: w.getRuleAction(actionType),
				Statement: &wafv2.Statement{
					IPSetReferenceStatement: &wafv2.IPSetReferenceStatement{
						ARN: aws.String(w.setsInfos[setName].ARN),
					},
				},
				Priority: aws.Int64(priority),
				VisibilityConfig: &wafv2.VisibilityConfig{
					SampledRequestsEnabled:   aws.Bool(false),
					CloudWatchMetricsEnabled: aws.Bool(false),
					MetricName:               name,
				},
			}
			rules = append(rules, rule)
			priority += 1
		}
	}

	for {
		w.logger.Trace("before create rule group")
		r, err := w.client.CreateRuleGroup(&wafv2.CreateRuleGroupInput{
			Name:  aws.String(ruleGroupName),
			Rules: rules,
			Tags: []*wafv2.Tag{
				{
					Key:   aws.String("CrowdsecManaged"),
					Value: aws.String("true"),
				},
			},
			Scope:    aws.String(w.config.Scope),
			Capacity: aws.Int64(25),
			VisibilityConfig: &wafv2.VisibilityConfig{
				SampledRequestsEnabled:   aws.Bool(false),
				CloudWatchMetricsEnabled: aws.Bool(false),
				MetricName:               aws.String(ruleGroupName),
			},
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

func (w WAF) DeleteRuleGroup(ruleGroupName string, token string, id string) error {
	_, err := w.client.DeleteRuleGroup(&wafv2.DeleteRuleGroupInput{
		Name:      aws.String(ruleGroupName),
		Scope:     aws.String(w.config.Scope),
		LockToken: aws.String(token),
		Id:        aws.String(id),
	})
	return err
}

func (w WAF) ListWebACL() (map[string]Acl, error) {
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

func (w WAF) GetWebACL(aclName string, id string) (*wafv2.WebACL, *string, error) {
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

func (w WAF) ListIpSet() (map[string]IpSet, error) {
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

func (w WAF) GetIPSet(setName string) (*wafv2.IPSet, *string, error) {
	w.logger.Debugf("Getting IPSet %s", setName)
	w.logger.Tracef("IPSet details: %+v", w.setsInfos[setName])
	r, err := w.client.GetIPSet(&wafv2.GetIPSetInput{
		Name:  aws.String(setName),
		Scope: aws.String(w.config.Scope),
		Id:    aws.String(w.setsInfos[setName].Id),
	})
	if err != nil {
		return nil, nil, err
	}
	return r.IPSet, r.LockToken, nil
}

func (w WAF) CreateIpSet(setName string, ipVersion string) (*wafv2.IPSetSummary, error) {
	r, err := w.client.CreateIPSet(&wafv2.CreateIPSetInput{
		Name:             aws.String(setName),
		Addresses:        []*string{},
		Scope:            aws.String(w.config.Scope),
		IPAddressVersion: aws.String(ipVersion),
	})
	if err != nil {
		return nil, err
	}
	return r.Summary, nil
}

func (w WAF) UpdateIpSet(setName string, add []*string, deleted []*string) error {
	setContent := make([]*string, 0)
	w.logger.Infof("Updating IPSet %s", setName)
	currSet, token, err := w.GetIPSet(setName)
	if err != nil {
		return err
	}
	setContent = append(setContent, currSet.Addresses...)
	for _, ip := range add {
		if !containsStringPtr(setContent, *ip) {
			setContent = append(setContent, ip)
		}
	}
	for _, ip := range deleted {
		if containsStringPtr(setContent, *ip) {
			setContent = removesStringPtr(setContent, *ip)
		}
	}
	_, err = w.client.UpdateIPSet(&wafv2.UpdateIPSetInput{
		Name:      currSet.Name,
		Addresses: add,
		Scope:     aws.String(w.config.Scope),
		Id:        currSet.Id,
		LockToken: token,
	})
	if err != nil {
		return err
	}
	return nil
}

func (w WAF) DeleteIpSet(setName string, id string) error {
	r, err := w.client.GetIPSet(&wafv2.GetIPSetInput{
		Name:  aws.String(setName),
		Scope: aws.String(w.config.Scope),
		Id:    aws.String(id),
	})
	if err != nil {
		return err
	}
	_, err = w.client.DeleteIPSet(&wafv2.DeleteIPSetInput{
		Name:      aws.String(setName),
		Scope:     aws.String(w.config.Scope),
		LockToken: r.LockToken,
		Id:        aws.String(id),
	})
	return err
}

func (w WAF) getRuleAction(actionType string) *wafv2.RuleAction {
	switch actionType {
	case "ban":
		return &wafv2.RuleAction{
			Block: &wafv2.BlockAction{},
		}
	case "captcha":
		return &wafv2.RuleAction{
			Captcha: &wafv2.CaptchaAction{},
		}
	}
	return nil
}

func (w WAF) getPriority(acl *wafv2.WebACL) int64 {
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

func (w WAF) AddRuleGroupToACL(acl *wafv2.WebACL, token *string) error {
	var newRules []*wafv2.Rule
	newRules = append(newRules, acl.Rules...)
	maxRetries := 5

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
	return nil
}

func (w WAF) RemoveRuleGroupFromACL(acl *wafv2.WebACL, token *string) error {
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

func (w WAF) AddIpSetToACL(acl *wafv2.WebACL, setARN string, token *string, ipType string) error {
	rules := make([]*wafv2.Rule, 0)

	for _, rule := range acl.Rules {
		if *rule.Name != "crowdsec-blocklist-"+ipType {
			rules = append(rules, rule)
		}
	}

	rule := &wafv2.Rule{
		Name: aws.String("crowdsec-blocklist-" + ipType),
		Statement: &wafv2.Statement{
			IPSetReferenceStatement: &wafv2.IPSetReferenceStatement{
				ARN: aws.String(setARN),
			},
		},
		Priority: aws.Int64(w.getPriority(acl)),
		VisibilityConfig: &wafv2.VisibilityConfig{
			SampledRequestsEnabled:   aws.Bool(false),
			CloudWatchMetricsEnabled: aws.Bool(false),
			MetricName:               aws.String("Crowdsec"),
		},
	}

	rules = append(rules, rule)

	_, err := w.client.UpdateWebACL(&wafv2.UpdateWebACLInput{
		CaptchaConfig:        acl.CaptchaConfig,
		CustomResponseBodies: acl.CustomResponseBodies,
		DefaultAction:        acl.DefaultAction,
		Description:          nil,
		Id:                   acl.Id,
		LockToken:            token,
		Name:                 acl.Name,
		Rules:                rules,
		Scope:                aws.String(w.config.Scope),
		VisibilityConfig:     acl.VisibilityConfig,
	})
	if err != nil {
		return err
	}
	return nil
}

func (w WAF) GetRuleGroup(ruleGroupname string) (string, wafv2.RuleGroup, error) {
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

func (w WAF) CleanupAcl(acl *wafv2.WebACL, token *string) error {
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

	sets, err := w.ListIpSet()

	if err != nil {
		return errors.Wrapf(err, "Failed to list IPSets")
	}

	for k, s := range sets {
		if strings.HasPrefix(k, w.config.IpsetPrefix) {
			w.logger.Debugf("Deleting IPSet %s", k)
			err = w.DeleteIpSet(k, s.Id)
			if err != nil {
				return errors.Wrapf(err, "Failed to delete IPSet %s", k)
			}
		}
	}

	return nil
}

func (w WAF) Cleanup() error {
	var err error
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

func (w WAF) ListRessources() (map[string]Acl, map[string]IpSet, map[string]RuleGroup, error) {
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

func (w WAF) WaitForIpSet(setName string) error {
	maxRetries := 5
	for {
		_, _, err := w.GetIPSet(setName)
		if err != nil {
			switch err.(type) {
			case *wafv2.WAFNonexistentItemException:
				if maxRetries == 0 {
					return fmt.Errorf("IPSet %s still not created, giving up", setName)
				}
				w.logger.Infof("IPSet %s still not created, waiting", setName)
				maxRetries--
				time.Sleep(time.Second * 2)
				continue
			default:
				w.logger.Errorf("Error getting IPSet %s: %s", setName, err)
				return err
			}
		}
		return nil
	}
}

func (w WAF) Init() error {
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

	err = w.CleanupAcl(acl, token)

	if err != nil {
		return errors.Wrap(err, "Failed to cleanup")
	}

	w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListRessources()

	if err != nil {
		return fmt.Errorf("failed to list ressources: %s", err)
	}

	for _, actionType := range []string{"ban", "captcha"} {
		for _, ipType := range []string{"IPV4", "IPV6"} {
			setName := fmt.Sprintf("%s-%s-%s", w.config.IpsetPrefix, ipType, actionType)
			if _, ok := w.setsInfos[setName]; !ok {
				w.logger.Infof("Creating IPSet %s", setName)
				r, err := w.CreateIpSet(setName, ipType)
				if err != nil {
					return errors.Wrapf(err, "Failed to create IPSet %s", setName)
				}
				w.logger.Debugf("IPSet %s created: %+v", setName, r)
				w.setsInfos[setName] = IpSet{ARN: *r.ARN, Id: *r.Id}
				err = w.WaitForIpSet(setName)
				if err != nil {
					return errors.Wrapf(err, "Failed to wait for IPSet %s", setName)
				}
			}
		}
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

func (w WAF) UpdateSetsContent(d Decisions) error {
	var err error

	if err != nil {
		return fmt.Errorf("failed to list ressources: %s", err)
	}

	for action, ips := range d.v4Add {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}
		setName := fmt.Sprintf("%s-IPV4-%s", w.config.IpsetPrefix, action)
		switch action {
		case "captcha":
			err = w.UpdateIpSet(setName, ips, []*string{})
			if err != nil {
				w.logger.Errorf("Failed to update IPv4 IPSet %s: %s", setName, err)
			}
		case "ban":
			err = w.UpdateIpSet(setName, ips, []*string{})
			if err != nil {
				w.logger.Errorf("Failed to update IPv4 IPSet %s: %s", setName, err)
			}
		}
	}

	for action, ips := range d.v4Del {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}
		setName := fmt.Sprintf("%s-IPV4-%s", w.config.IpsetPrefix, action)
		switch action {
		case "captcha":
			err = w.UpdateIpSet(setName, []*string{}, ips)
			if err != nil {
				w.logger.Errorf("Failed to update IPv4 IPSet %s: %s", setName, err)
			}
		case "ban":
			err = w.UpdateIpSet(setName, []*string{}, ips)
			if err != nil {
				w.logger.Errorf("Failed to update IPv4 IPSet %s: %s", setName, err)
			}
		}
	}

	for action, ips := range d.v6Add {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}
		setName := fmt.Sprintf("%s-IPV6-%s", w.config.IpsetPrefix, action)
		switch action {
		case "captcha":
			err = w.UpdateIpSet(setName, ips, []*string{})
			if err != nil {
				w.logger.Errorf("Failed to update IPv6 IPSet %s: %s", setName, err)
			}
		case "ban":
			err = w.UpdateIpSet(setName, ips, []*string{})
			if err != nil {
				w.logger.Errorf("Failed to update IPv6 IPSet %s: %s", setName, err)
			}
		}
	}

	for action, ips := range d.v6Del {
		if action == "fallback" {
			action = strings.ToLower(w.config.FallbackAction)
		}
		setName := fmt.Sprintf("%s-IPV6-%s", w.config.IpsetPrefix, action)
		switch action {
		case "captcha":
			err = w.UpdateIpSet(setName, []*string{}, ips)
			if err != nil {
				w.logger.Errorf("Failed to update IPv6 IPSet %s: %s", setName, err)
			}
		case "ban":
			err = w.UpdateIpSet(setName, []*string{}, ips)
			if err != nil {
				w.logger.Errorf("Failed to update IPv6 IPSet %s: %s", setName, err)
			}
		}
	}

	return nil
}

func (w WAF) UpdateGeoSet(d Decisions) error {
	var ruleCaptcha *wafv2.Rule
	var ruleBan *wafv2.Rule

	countriesban := make([]*string, 0)
	countriesCaptcha := make([]*string, 0)

	if len(d.countriesAdd) == 0 && len(d.countriesDel) == 0 {
		return nil
	}

	token, rg, err := w.GetRuleGroup(w.config.RuleGroupName)
	if err != nil {
		return errors.Wrapf(err, "Failed to get RuleGroup  %s for geoset update", w.config.WebACLName)
	}

	for _, rule := range rg.Rules {
		if *rule.Name == "crowdsec-rule-country-ban" {
			ruleBan = rule
		}
		if *rule.Name == "crowdsec-rule-country-captcha" {
			ruleCaptcha = rule
		}
	}

	countriesban = append(countriesban, d.countriesAdd["ban"]...)
	countriesCaptcha = append(countriesCaptcha, d.countriesAdd["captcha"]...)

	if len(d.countriesAdd["fallback"]) > 0 {
		if w.config.FallbackAction == "ban" {
			countriesban = append(countriesban, d.countriesAdd["fallback"]...)
		} else {
			countriesCaptcha = append(countriesCaptcha, d.countriesAdd["fallback"]...)
		}
	}

	if ruleBan == nil && len(countriesban) > 0 {
		w.logger.Infof("Creating new rule for countries ban")
		//we don't already have a geomatch rule in the rule group, create it
		ruleBan = &wafv2.Rule{
			Name: aws.String("crowdsec-rule-country-ban"),
			Statement: &wafv2.Statement{
				GeoMatchStatement: &wafv2.GeoMatchStatement{
					CountryCodes: countriesban,
				},
			},
			Priority:         aws.Int64(20), //FIXME: get the priority dynamically, but it does not really matter as we managed the rulegroup ourselves
			VisibilityConfig: rg.VisibilityConfig,
			Action:           w.getRuleAction("ban"),
		}
		rg.Rules = append(rg.Rules, ruleBan)
	} else if ruleBan != nil {
		w.logger.Infof("Updating existing rule %s for countries ban", *ruleBan.Name)
		countriesban = append(countriesban, ruleBan.Statement.GeoMatchStatement.CountryCodes...)
		for _, c := range d.countriesDel["ban"] {
			countriesban = removesStringPtr(countriesban, *c)
		}
		if len(d.countriesDel["fallback"]) > 0 && w.config.FallbackAction == "ban" {
			for _, c := range d.countriesDel["fallback"] {
				countriesban = removesStringPtr(countriesban, *c)
			}
		}
		w.logger.Debugf("Countries ban: %+v", countriesban)
		if len(countriesCaptcha) == 0 {
			//remove the rule if there are no countries left
			rg.Rules = removeRuleFromRuleGroup(rg.Rules, *ruleBan.Name)
		} else {
			ruleBan.Statement.GeoMatchStatement.CountryCodes = countriesban
		}
	}

	if ruleCaptcha == nil && len(countriesCaptcha) > 0 {
		w.logger.Infof("Creating new rule for countries captcha")
		//we don't already have a geomatch rule in the rule group, create it
		ruleCaptcha = &wafv2.Rule{
			Name: aws.String("crowdsec-rule-country-captcha"),
			Statement: &wafv2.Statement{
				GeoMatchStatement: &wafv2.GeoMatchStatement{
					CountryCodes: countriesCaptcha,
				},
			},
			Priority:         aws.Int64(30),
			VisibilityConfig: rg.VisibilityConfig,
			Action:           w.getRuleAction("captcha"),
		}
		rg.Rules = append(rg.Rules, ruleCaptcha)
	} else if ruleCaptcha != nil {
		w.logger.Infof("Updating existing rule %s for countries captcha", *ruleCaptcha.Name)
		countriesCaptcha = append(countriesCaptcha, ruleCaptcha.Statement.GeoMatchStatement.CountryCodes...)
		for _, c := range d.countriesDel["captcha"] {
			countriesCaptcha = removesStringPtr(countriesCaptcha, *c)
		}
		if len(d.countriesDel["fallback"]) > 0 && w.config.FallbackAction == "captcha" {
			for _, c := range d.countriesDel["fallback"] {
				countriesCaptcha = removesStringPtr(countriesCaptcha, *c)
			}
		}
		w.logger.Debugf("Countries captcha: %+v", countriesCaptcha)
		if len(countriesCaptcha) == 0 {
			//remove the rule if there are no countries left
			rg.Rules = removeRuleFromRuleGroup(rg.Rules, *ruleCaptcha.Name)
		} else {
			ruleCaptcha.Statement.GeoMatchStatement.CountryCodes = countriesCaptcha
		}
	}

	if ruleBan != nil || ruleCaptcha != nil {
		_, err = w.client.UpdateRuleGroup(&wafv2.UpdateRuleGroupInput{
			Name:             rg.Name,
			Rules:            rg.Rules,
			Scope:            aws.String(w.config.Scope),
			VisibilityConfig: rg.VisibilityConfig,
			Id:               rg.Id,
			LockToken:        aws.String(token),
		})
		w.logger.Debug("Updated RuleGroup for geomatch")
		if err != nil {
			return errors.Wrapf(err, "Failed to update RuleGroup  %s for geoset update", w.config.WebACLName)
		}
	}

	return nil
}

func (w WAF) Process() error {
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
			w.aclsInfo, w.setsInfos, w.ruleGroupsInfos, err = w.ListRessources()
			if err != nil {
				w.logger.Errorf("Failed to list ressources: %s", err)
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
		}
	}
}

func (w WAF) Dump() {
	w.logger.Debugf("WAF config: %+v", w.config)
	w.logger.Debugf("WAF sets: %+v", w.setsInfos)
}

func NewWaf(config AclConfig) (WAF, error) {
	var s *session.Session
	if config.Scope == "CLOUDFRONT" {
		config.Region = "us-east-1"
	}

	logger := log.WithFields(log.Fields{
		"region": config.Region,
		"scope":  config.Scope,
		"acl":    config.WebACLName,
	})

	w := WAF{
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

	w.t.Go(w.Process)
	return w, nil
}
