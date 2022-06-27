package main

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/service/wafv2"
	log "github.com/sirupsen/logrus"
)

type IPSetManager struct {
	IPSets    []*WAFIpSet
	setPrefix string
	scope     string
	client    *wafv2.WAFV2
	logger    *log.Entry
}

func (im *IPSetManager) FindAvailableSet(ipType string, decisionType string) (*WAFIpSet, error) {
	for _, ipset := range im.IPSets {
		if ipset.GetType() == ipType && ipset.GetDecisionType() == decisionType && ipset.Size() < 10000 {
			return ipset, nil
		}
	}
	return nil, fmt.Errorf("no available set found")
}

func (im *IPSetManager) alreadyInSets(ip string, decisionType string) bool {
	for _, ipset := range im.IPSets {
		if ipset.GetDecisionType() == decisionType && ipset.Contains(ip) {
			return true
		}
	}
	return false
}

func (im *IPSetManager) Commit() error {
	for _, ipset := range im.IPSets {
		im.logger.Debugf("checking if set %s is stale", ipset.GetName())
		if ipset.IsStale() {
			im.logger.Infof("set %s is stale, updating it", ipset.GetName())
			err := ipset.Commit()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (im *IPSetManager) AddIp(ip string, decisionType string) {
	var ipType string
	if strings.Contains(ip, ":") {
		ipType = "IPV6"
	} else {
		ipType = "IPV4"
	}

	if im.alreadyInSets(ip, decisionType) {
		im.logger.Debugf("ip %s already in set, skipping", ip)
		return
	}

	ipset, err := im.FindAvailableSet(ipType, decisionType)
	if err != nil {
		im.logger.Info("could not find empty set, creating new set")
		ipset = NewIpSet(im.setPrefix, ipType, decisionType, im.scope, im.client)
		im.IPSets = append(im.IPSets, ipset)
		ipset.Add(ip)
		return
	}
	ipset.Add(ip)
}

func (im *IPSetManager) DeleteIp(ip string, decisionType string) {
	for _, ipset := range im.IPSets {
		if ipset.GetDecisionType() == decisionType {
			im.logger.Tracef("deleting ip %s from set %s", ip, ipset.GetName())
			ipset.Remove(ip)
		}
	}
}

func (im *IPSetManager) DeleteEmptySets() {
	removed := make([]*WAFIpSet, 0)
	for _, ipset := range im.IPSets {
		if ipset.Size() == 0 {
			removed = append(removed, ipset)
		}
	}

	for _, ipset := range removed {
		im.logger.Infof("set %s is empty, deleting it.", ipset.GetName())
		err := ipset.DeleteIpSet()
		if err != nil {
			im.logger.Errorf("could not delete set %s: %s", ipset.GetName(), err)
		}
		im.IPSets = removeIpSetFromSlice(im.IPSets, ipset)
	}
}

func (im *IPSetManager) DeleteSets() {
	for _, ipset := range im.IPSets {
		im.logger.Infof("deleting set %s", ipset.GetName())
		err := ipset.DeleteIpSet()
		if err != nil {
			im.logger.Errorf("could not delete set %s: %s", ipset.GetName(), err)
		}
	}
}

func NewIPSetManager(setPrefix string, scope string, client *wafv2.WAFV2, logger *log.Entry) *IPSetManager {
	l := logger.WithField("component", "ipset_manager")
	return &IPSetManager{
		IPSets:    make([]*WAFIpSet, 0),
		setPrefix: setPrefix,
		client:    client,
		logger:    l,
		scope:     scope,
	}
}
