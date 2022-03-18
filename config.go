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
	AWSProfile     string `yaml:"aws_profile"`
}

var validActions = []string{"ban", "captcha"}
var validScopes = []string{"REGIONAL", "CLOUDFRONT"}

func getConfigFromEnv(config *bouncerConfig) {
	var key string
	var value string
	var acl *AclConfig
	acls := make(map[byte]*AclConfig, 0)

	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "BOUNCER_") {
			s := strings.Split(env, "=")
			if len(s) == 2 {
				key = strings.Split(env, "=")[0]
				value = strings.Split(env, "=")[1]
			} else {
				log.Warnf("Invalid environment variable: %s", env)
				continue
			}
			if strings.HasPrefix(key, "BOUNCER_WAF_CONFIG_") {
				k2 := strings.TrimPrefix(key, "BOUNCER_WAF_CONFIG_")
				if k2[0] < '0' || k2[0] > '9' || len(k2) < 3 {
					log.Warnf("Invalid name for %s: BOUNCER_WAF_CONFIG_* must be in the form BOUNCER_WAF_CONFIG_0_XXX, BOUNCER_WAF_CONFIG_1_XXX", key)
				}
				if _, ok := acls[k2[0]]; !ok {
					acl = &AclConfig{}
					acls[k2[0]] = acl
				} else {
					acl = acls[k2[0]]
				}
				k2 = k2[2:]
				switch k2 {
				case "WEB_ACL_NAME":
					acl.WebACLName = value
				case "RULE_GROUP_NAME":
					acl.RuleGroupName = value
				case "REGION":
					acl.Region = value
				case "SCOPE":
					acl.Scope = value
				case "IPSET_PREFIX":
					acl.IpsetPrefix = value
				case "FALLBACK_ACTION":
					acl.FallbackAction = value
				case "AWS_PROFILE":
					acl.AWSProfile = value
				}
			} else {
				switch key {
				case "BOUNCER_API_KEY":
					config.APIKey = value
				case "BOUNCER_API_URL":
					config.APIUrl = value
				case "BOUNCER_UPDATE_FREQUENCY":
					config.UpdateFrequency = value
				case "BOUNCER_INSECURE_SKIP_VERIFY":
					config.InsecureSkipVerify = value == "true"
				case "BOUNCER_DAEMON":
					config.Daemon = value == "true"
				case "BOUNCER_LOG_LEVEL":
					level, err := log.ParseLevel(value)
					if err != nil {
						log.Warnf("Invalid log level: %s, using INFO", value)
						config.LogLevel = log.InfoLevel
					} else {
						config.LogLevel = level
					}
				case "BOUNCER_LOG_MEDIA":
					config.LogMedia = value
				case "BOUNCER_LOG_DIR":
					config.LogDir = value
				}
			}
		}
	}
	for _, v := range acls {
		config.WebACLConfig = append(config.WebACLConfig, *v)
	}
}

func newConfig(configPath string) (bouncerConfig, error) {
	var config bouncerConfig
	ipsetPrefix := make(map[string]bool)
	ruleGroupNames := make(map[string]bool)

	if configPath != "" {
		content, err := os.ReadFile(configPath)
		if err != nil {
			return bouncerConfig{}, err
		}
		err = yaml.UnmarshalStrict(content, &config)
		if err != nil {
			return bouncerConfig{}, err
		}
	}

	getConfigFromEnv(&config)

	if config.LogMedia == "" {
		config.LogMedia = "stdout"
	}

	if config.LogLevel == 0 {
		config.LogLevel = log.InfoLevel
	}

	if err := types.SetDefaultLoggerConfig(config.LogMedia, config.LogDir, config.LogLevel, 10, 2, 1, aws.Bool(true)); err != nil {
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
