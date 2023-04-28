package main

import (
	"github.com/aws/aws-sdk-go/service/wafv2"
)

func removesStringPtr(slice []*string, s string) []*string {
	for i, item := range slice {
		if *item == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func removesString(slice []string, s string) []string {
	for i, item := range slice {
		if item == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func removeRuleFromRuleGroup(rules []*wafv2.Rule, name string) []*wafv2.Rule {
	for i, r := range rules {
		if *r.Name == name {
			return append(rules[:i], rules[i+1:]...)
		}
	}
	return rules
}

func removeIpSetFromSlice(sets []*WAFIpSet, ipset *WAFIpSet) []*WAFIpSet {
	for i, s := range sets {
		if s == ipset {
			return append(sets[:i], sets[i+1:]...)
		}
	}
	return sets
}

func uniqueStrPtr(s []*string) []*string {
	m := make(map[*string]bool)
	for _, v := range s {
		if _, ok := m[v]; !ok {
			m[v] = true
		}
	}
	var result []*string
	for k := range m {
		result = append(result, k)
	}
	return result
}
