package waf

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

type WAFIpSet struct {
	ips          []string
	name         string
	arn          string
	ipType       string
	scope        string
	id           string
	decisionType string
	stale        bool
	client       *wafv2.Client
	logger       *log.Entry
}

func (w *WAFIpSet) Add(ip string) {
	if w.Size() >= 10000 {
		return
	}

	if w.Contains(ip) {
		return
	}

	w.ips = append(w.ips, ip)
	w.stale = true
}

func (w *WAFIpSet) Remove(ip string) {
	w.ips = removesString(w.ips, ip)
	w.stale = true
}

func (w *WAFIpSet) Contains(ip string) bool {
	return slices.Contains(w.ips, ip)
}

func (w *WAFIpSet) RemoveAll() {
	w.ips = nil
}

func (w *WAFIpSet) ContainsAll(ips []string) bool {
	for _, ip := range ips {
		if !w.Contains(ip) {
			return false
		}
	}

	return true
}

func (w *WAFIpSet) Size() int {
	return len(w.ips)
}

func (w *WAFIpSet) GetIPs() []string {
	return w.ips
}

func (w *WAFIpSet) GetName() string {
	return w.name
}

func (w *WAFIpSet) GetType() string {
	return w.ipType
}

func (w *WAFIpSet) GetDecisionType() string {
	return w.decisionType
}

func (w *WAFIpSet) IsStale() bool {
	return w.stale
}

func (w *WAFIpSet) ToStatement(ipHeader string, ipHeaderPosition string) *wafv2types.IPSetReferenceStatement {
	if ipHeader == "" {
		return &wafv2types.IPSetReferenceStatement{
			ARN: aws.String(w.arn),
		}
	}

	return &wafv2types.IPSetReferenceStatement{
		ARN: aws.String(w.arn),
		IPSetForwardedIPConfig: &wafv2types.IPSetForwardedIPConfig{
			HeaderName:       aws.String(ipHeader),
			FallbackBehavior: wafv2types.FallbackBehavior("NO_MATCH"),
			Position:         wafv2types.ForwardedIPPosition(ipHeaderPosition),
		},
	}
}

func (w *WAFIpSet) getIPSet() (*wafv2types.IPSet, *string, error) {
	w.logger.Debugf("Getting IPSet %s", w.name)

	if w.id == "" {
		return nil, nil, &wafv2types.WAFNonexistentItemException{}
	}

	r, err := w.client.GetIPSet(context.TODO(), &wafv2.GetIPSetInput{
		Name:  aws.String(w.name),
		Scope: wafv2types.Scope(w.scope),
		Id:    aws.String(w.id),
	})
	if err != nil {
		return nil, nil, err
	}

	return r.IPSet, r.LockToken, nil
}

func (w *WAFIpSet) createIpSet() (*wafv2types.IPSetSummary, error) {
	w.logger.Infof("Creating IPSet %s", w.name)
	w.logger.Tracef("Set name: %s | Type: %s | Decision: %s | Scope: %s | %d IPS", w.name, w.ipType, w.decisionType, w.scope, w.Size())

	r, err := w.client.CreateIPSet(context.TODO(), &wafv2.CreateIPSetInput{
		Name:             aws.String(w.name),
		Addresses:        w.ips,
		Scope:            wafv2types.Scope(w.scope),
		IPAddressVersion: wafv2types.IPAddressVersion(w.ipType),
	})
	if err != nil {
		return nil, err
	}

	return r.Summary, nil
}

func (w *WAFIpSet) DeleteIpSet() error {
	w.logger.Infof("Deleting IPSet %s", w.name)

	_, token, err := w.getIPSet()
	if err != nil {
		return err
	}

	_, err = w.client.DeleteIPSet(context.TODO(), &wafv2.DeleteIPSetInput{
		Name:      aws.String(w.name),
		Scope:     wafv2types.Scope(w.scope),
		Id:        aws.String(w.id),
		LockToken: token,
	})
	if err != nil {
		return err
	}

	return nil
}

func (w *WAFIpSet) Commit() error {
	w.logger.Infof("Updating IPSet %s", w.name)

	currSet, token, err := w.getIPSet()
	if err != nil {
		switch err.(type) {
		case *wafv2types.WAFNonexistentItemException:
		default:
			return err
		}
	}

	if currSet == nil {
		summary, err := w.createIpSet()
		if err != nil {
			return fmt.Errorf("failed to create IPSet %s: %w", w.name, err)
		}

		w.arn = *summary.ARN
		w.id = *summary.Id
	} else {
		_, err = w.client.UpdateIPSet(context.TODO(), &wafv2.UpdateIPSetInput{
			Name:      currSet.Name,
			Addresses: w.ips,
			Scope:     wafv2types.Scope(w.scope),
			Id:        currSet.Id,
			LockToken: token,
		})
		if err != nil {
			return err
		}
	}

	w.stale = false

	return nil
}

func NewIpSet(setPrefix string, ipType string, decisionType string, scope string, client *wafv2.Client) *WAFIpSet {
	u := uuid.New()
	setName := setPrefix + "-" + ipType + "-" + decisionType + "-" + u.String()

	return &WAFIpSet{
		name:         setName,
		ipType:       ipType,
		decisionType: decisionType,
		logger:       log.WithField("set", setName),
		scope:        scope,
		client:       client,
	}
}
