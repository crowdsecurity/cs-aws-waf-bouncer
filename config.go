package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type bouncerConfig struct {
	APIKey             string      `yaml:"api_key"`
	APIUrl             string      `yaml:"api_url"`
	UpdateFrequency    string      `yaml:"update_frequency"`
	InsecureSkipVerify bool        `yaml:"insecure_skip_verify"`
	Daemon             bool        `yaml:"daemon"`
	LogLevel           log.Level   `yaml:"log_level"`
	LogMedia           string      `yaml:"log_media"`
	LogDir             string      `yaml:"log_dir"`
	WebACLConfig       []AclConfig `yaml:"waf_config"`
}

type AclConfig struct {
	WebACLName     string `yaml:"web_acl_name"`
	RuleGroupName  string `yaml:"rule_group_name"`
	Region         string `yaml:"region"`
	Scope          string `yaml:"scope"`
	IpsetPrefix    string `yaml:"ipset_prefix"`
	FallbackAction string `yaml:"fallback_action"`
}

var validActions = []string{"ban", "captcha"}
var validScopes = []string{"REGIONAL", "CLOUDFRONT"}

func newConfig(configPath string) (bouncerConfig, error) {
	var config bouncerConfig

	content, err := os.ReadFile(configPath)
	ipsetPrefix := make(map[string]bool)
	ruleGroupNames := make(map[string]bool)
	if err != nil {
		return bouncerConfig{}, err
	}
	err = yaml.UnmarshalStrict(content, &config)
	if err != nil {
		return bouncerConfig{}, err
	}

	if err = types.SetDefaultLoggerConfig(config.LogMedia, config.LogDir, config.LogLevel, 10, 2, 1, aws.Bool(true)); err != nil {
		log.Fatal(err.Error())
	}

	if config.APIKey == "" {
		return bouncerConfig{}, fmt.Errorf("api_key is required")
	}
	if config.APIUrl == "" {
		return bouncerConfig{}, fmt.Errorf("api_url is required")
	}
	if config.UpdateFrequency == "" {
		config.UpdateFrequency = "10s"
	}
	/*if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}*/
	if len(config.WebACLConfig) == 0 {
		return bouncerConfig{}, fmt.Errorf("waf_config is required")
	}
	for _, c := range config.WebACLConfig {
		if c.FallbackAction == "" {
			return bouncerConfig{}, fmt.Errorf("fallback_action is required")
		}
		if !contains(validActions, c.FallbackAction) {
			return bouncerConfig{}, fmt.Errorf("fallback_action must be one of %v", validActions)
		}
		if c.RuleGroupName == "" {
			return bouncerConfig{}, fmt.Errorf("rule_group_name is required")
		}
		if c.Scope == "" {
			return bouncerConfig{}, fmt.Errorf("scope is required")
		}
		if !contains(validScopes, c.Scope) {
			return bouncerConfig{}, fmt.Errorf("scope must be one of %v", validScopes)
		}
		if c.IpsetPrefix == "" {
			return bouncerConfig{}, fmt.Errorf("ipset_prefix is required")
		}
		if c.Region == "" && strings.ToUpper(c.Scope) == "REGIONAL" {
			return bouncerConfig{}, fmt.Errorf("region is required when scope is REGIONAL")
		}
		if _, ok := ipsetPrefix[c.IpsetPrefix]; ok {
			return bouncerConfig{}, fmt.Errorf("ipset_prefix value must be unique")
		} else {
			ipsetPrefix[c.IpsetPrefix] = true
		}
		if _, ok := ruleGroupNames[c.RuleGroupName]; ok {
			return bouncerConfig{}, fmt.Errorf("rule_group_name value must be unique")
		} else {
			ruleGroupNames[c.RuleGroupName] = true
		}
	}
	return config, nil
}
