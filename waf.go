package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type WAF struct {
	config    *AclConfig
	client    *wafv2.WAFV2
	setsInfos map[string]IpSet
	logger    *log.Entry
}

type IpSet struct {
	ARN string
	Id  string
}

func (w WAF) ListRuleGroups(scope string) ([]string, error) {
	var marker *string
	ruleGroups := make([]string, 0)
	for {
		input := &wafv2.ListRuleGroupsInput{
			Scope:      aws.String(scope),
			NextMarker: marker,
		}
		output, err := w.client.ListRuleGroups(input)
		if err != nil {
			return nil, err
		}
		for _, ruleGroup := range output.RuleGroups {
			ruleGroups = append(ruleGroups, *ruleGroup.Name)
		}
		if output.NextMarker == nil {
			break
		}
		marker = output.NextMarker
	}
	return ruleGroups, nil
}

func (w WAF) CreateRuleGroup(ruleGroupName string) error {
	w.client.CreateRuleGroup(&wafv2.CreateRuleGroupInput{
		Name:  aws.String(ruleGroupName),
		Rules: []*wafv2.Rule{},
		Tags: []*wafv2.Tag{
			{
				Key:   aws.String("CrowdsecManaged"),
				Value: aws.String("true"),
			},
		},
	})
	return nil
}

func (w WAF) UpdateRuleGroup(ruleGroupName string) error {
	return nil
}

func (w WAF) ListWebACL() (map[string]string, error) {
	acls := make(map[string]string)
	r, err := w.client.ListWebACLs(&wafv2.ListWebACLsInput{
		Scope: aws.String(w.config.Scope),
	})
	if err != nil {
		return nil, err
	}
	for _, acl := range r.WebACLs {
		acls[*acl.Name] = *acl.Id
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

func (w WAF) DeleteIpSet(setName string) error {
	return nil
}

func (w WAF) getRuleAction() *wafv2.RuleAction {
	switch w.config.Action.Type {
	case "BLOCK":
		return &wafv2.RuleAction{
			Block: &wafv2.BlockAction{},
		}
	case "ALLOW":
		return &wafv2.RuleAction{
			Allow: &wafv2.AllowAction{},
		}
	case "COUNT":
		return &wafv2.RuleAction{
			Count: &wafv2.CountAction{},
		}
	case "CAPTCHA":
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

func (w WAF) AddIpSetToACL(acl *wafv2.WebACL, setARN string, token *string, ipType string) error {
	rules := make([]*wafv2.Rule, 0)

	for _, rule := range acl.Rules {
		if *rule.Name != w.config.RuleName+"-"+ipType {
			rules = append(rules, rule)
		}
	}

	rule := &wafv2.Rule{
		Name:   aws.String(w.config.RuleName + "-" + ipType),
		Action: w.getRuleAction(),
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

func (w WAF) Init() error {
	acls, err := w.ListWebACL()
	if err != nil {
		return errors.Wrap(err, "Failed to list WebACLs")
	}

	w.logger.Tracef("Found %d WebACLs", len(acls))
	w.logger.Tracef("ACLs: %+v", acls)

	if _, ok := acls[w.config.WebACLName]; !ok {
		return fmt.Errorf("WebACL %s does not exist in region %s", w.config.WebACLName, w.config.Region)
	}

	sets, err := w.ListIpSet()
	if err != nil {
		return errors.Wrap(err, "Failed to list IPSets")
	}

	w.logger.Tracef("Found %d IPSets", len(sets))
	w.logger.Tracef("IPSets: %+v", sets)

	if _, ok := sets[w.config.IPSetConfig.IPv4SetName]; !ok {
		w.logger.Infof("Creating IPSet %s", w.config.IPSetConfig.IPv4SetName)
		setInfos, err := w.CreateIpSet(w.config.IPSetConfig.IPv4SetName, "IPV4")
		if err != nil {
			return errors.Wrapf(err, "Failed to create IPv4 IPSet %s", w.config.IPSetConfig.IPv4SetName)
		}
		w.setsInfos[w.config.IPSetConfig.IPv4SetName] = IpSet{
			ARN: *setInfos.ARN,
			Id:  *setInfos.Id,
		}
	} else {
		w.logger.Debugf("IPSet %s already exists", w.config.IPSetConfig.IPv4SetName)
		w.logger.Tracef("IPSet details: %+v", sets[w.config.IPSetConfig.IPv4SetName])
		w.setsInfos[w.config.IPSetConfig.IPv4SetName] = sets[w.config.IPSetConfig.IPv4SetName]
	}

	if _, ok := sets[w.config.IPSetConfig.IPv6SetName]; !ok {
		w.logger.Infof("Creating IPSet %s", w.config.IPSetConfig.IPv6SetName)
		setInfos, err := w.CreateIpSet(w.config.IPSetConfig.IPv6SetName, "IPV6")
		if err != nil {
			return errors.Wrapf(err, "Failed to create IPv6 IPSet %s", w.config.IPSetConfig.IPv6SetName)
		}
		w.setsInfos[w.config.IPSetConfig.IPv6SetName] = IpSet{
			ARN: *setInfos.ARN,
			Id:  *setInfos.Id,
		}

	} else {
		w.logger.Debugf("IPSet %s already exists", w.config.IPSetConfig.IPv6SetName)
		w.logger.Tracef("IPSet details: %+v", sets[w.config.IPSetConfig.IPv6SetName])
		w.setsInfos[w.config.IPSetConfig.IPv6SetName] = sets[w.config.IPSetConfig.IPv6SetName]
	}

	acl, lockTocken, err := w.GetWebACL(w.config.WebACLName, acls[w.config.WebACLName])

	if err != nil {
		return errors.Wrapf(err, "Failed to get WebACL %s", w.config.WebACLName)
	}

	err = w.AddIpSetToACL(acl, w.setsInfos[w.config.IPSetConfig.IPv4SetName].ARN, lockTocken, "IPV4")
	if err != nil {
		return errors.Wrapf(err, "Failed to add IPv4 IPSet %s to WebACL %s in region %s", w.config.IPSetConfig.IPv4SetName, w.config.WebACLName, w.config.Region)
	}

	//As we just modified the ACL, we need to get it again to get a new lock token
	acl, lockTocken, err = w.GetWebACL(w.config.WebACLName, acls[w.config.WebACLName])

	if err != nil {
		return errors.Wrapf(err, "Failed to get WebACL %s", w.config.WebACLName)
	}

	err = w.AddIpSetToACL(acl, w.setsInfos[w.config.IPSetConfig.IPv6SetName].ARN, lockTocken, "IPV6")
	if err != nil {
		return errors.Wrapf(err, "Failed to add IPv6 IPSet %s to WebACL %s in region %s", w.config.IPSetConfig.IPv6SetName, w.config.WebACLName, w.config.Region)
	}

	return nil
}

func (w WAF) UpdateSetsContent(v4toAdd []*string, v6toAdd []*string, v4toDelete []*string, v6toDelete []*string) error {
	if len(v4toAdd) > 0 || len(v4toDelete) > 0 {
		err := w.UpdateIpSet(w.config.IPSetConfig.IPv4SetName, v4toAdd, v4toDelete)
		if err != nil {
			return errors.Wrapf(err, "Failed to update IPv4 IPSet %s", w.config.IPSetConfig.IPv4SetName)
		}
	}

	if len(v6toAdd) > 0 || len(v6toDelete) > 0 {

		err := w.UpdateIpSet(w.config.IPSetConfig.IPv6SetName, v6toAdd, v6toDelete)
		if err != nil {
			return errors.Wrapf(err, "Failed to update IPv6 IPSet %s", w.config.IPSetConfig.IPv6SetName)
		}
	}
	return nil
}

func (w WAF) Dump() {
	w.logger.Debugf("WAF config: %+v", w.config)
	w.logger.Debugf("WAF sets: %+v", w.setsInfos)
}

func NewWaf(config AclConfig) (WAF, error) {
	if config.Scope == "CLOUDFRONT" {
		config.Region = "us-east-1"
	}

	logger := log.WithFields(log.Fields{
		"region": config.Region,
		"scope":  config.Scope,
		"acl":    config.WebACLName,
	})

	w := WAF{setsInfos: make(map[string]IpSet), logger: logger}

	session := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(config.Region),
	}))
	client := wafv2.New(session)
	w.client = client
	w.config = &config
	return w, nil
}
