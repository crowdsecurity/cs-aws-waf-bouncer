package main

import "github.com/aws/aws-sdk-go/service/wafv2"

func containsStringPtr(slice []*string, s string) bool {
	for _, item := range slice {
		if *item == s {
			return true
		}
	}
	return false
}

func removesStringPtr(slice []*string, s string) []*string {
	for i, item := range slice {
		if *item == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func removeRuleFromRuleGroup(rules []*wafv2.Rule, name string) []*wafv2.Rule {
	for i, r := range rules {
		if *r.Name == name {
			return append(rules[:i], rules[i+1:]...)
		}
	}
	return rules
}
