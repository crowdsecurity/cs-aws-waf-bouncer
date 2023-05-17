package cfg

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/yamlpatch"
)

type bouncerConfig struct {
	APIKey             string        `yaml:"api_key"`
	APIUrl             string        `yaml:"api_url"`
	UpdateFrequency    string        `yaml:"update_frequency"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
	Daemon             bool          `yaml:"daemon"`
	Logging            LoggingConfig `yaml:",inline"`
	WebACLConfig       []AclConfig   `yaml:"waf_config"`
	KeyPath            string        `yaml:"key_path"`
	CertPath           string        `yaml:"cert_path"`
	CAPath             string        `yaml:"ca_cert_path"`
	SupportedActions   []string      `yaml:"supported_actions"`
}

type AclConfig struct {
	WebACLName           string `yaml:"web_acl_name"`
	RuleGroupName        string `yaml:"rule_group_name"`
	Region               string `yaml:"region"`
	Scope                string `yaml:"scope"`
	IpsetPrefix          string `yaml:"ipset_prefix"`
	FallbackAction       string `yaml:"fallback_action"`
	AWSProfile           string `yaml:"aws_profile"`
	IPHeader             string `yaml:"ip_header"`
	IPHeaderPosition     string `yaml:"ip_header_position"`
	Capacity             int    `yaml:"capacity"`
	CloudWatchEnabled    bool   `yaml:"cloudwatch_enabled"`
	CloudWatchMetricName string `yaml:"cloudwatch_metric_name"`
	SampleRequests       bool   `yaml:"sample_requests"`
}

var ValidActions = []string{"ban", "captcha", "count"}
var validScopes = []string{"REGIONAL", "CLOUDFRONT"}
var validIpHeaderPosition = []string{"FIRST", "LAST", "ANY"}

func getConfigFromEnv(config *bouncerConfig) {
	var key string
	var value string
	var acl *AclConfig
	var err error
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
				case "IP_HEADER":
					acl.IPHeader = value
				case "IP_HEADER_POSITION":
					acl.IPHeaderPosition = value
				case "CAPACITY":
					acl.Capacity, err = strconv.Atoi(value)
					if err != nil {
						log.Warnf("Invalid value for %s: %s", key, value)
						acl.Capacity = 300
					}
				case "CLOUDWATCH_ENABLED":
					acl.CloudWatchEnabled, err = strconv.ParseBool(value)
					if err != nil {
						log.Warnf("Invalid value for %s: %s, defaulting to false", key, value)
						acl.CloudWatchEnabled = false
					}
				case "CLOUDWATCH_METRIC_NAME":
					acl.CloudWatchMetricName = value
				case "SAMPLE_REQUESTS":
					acl.SampleRequests, err = strconv.ParseBool(value)
					if err != nil {
						log.Warnf("Invalid value for %s: %s, defaulting to false", key, value)
						acl.SampleRequests = false
					}
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
						defaultLevel := log.InfoLevel
						config.Logging.LogLevel = &defaultLevel
					} else {
						config.Logging.LogLevel = &level
					}
				case "BOUNCER_LOG_MEDIA":
					config.Logging.LogMedia = value
				case "BOUNCER_LOG_DIR":
					config.Logging.LogDir = value
				case "BOUNCER_LOG_MAX_SIZE":
					config.Logging.LogMaxSize, err = strconv.Atoi(value)
					if err != nil {
						log.Warnf("Invalid log max size from env: %s, using 40", value)
						config.Logging.LogMaxSize = 40
					}
				case "BOUNCER_LOG_MAX_AGE":
					config.Logging.LogMaxAge, err = strconv.Atoi(value)
					if err != nil {
						log.Warnf("Invalid log max age from env: %s, using 7", value)
						config.Logging.LogMaxAge = 7
					}
				case "BOUNCER_LOG_MAX_FILES":
					config.Logging.LogMaxFiles, err = strconv.Atoi(value)
					if err != nil {
						log.Warnf("Invalid log max files from env: %s, using 7", value)
						config.Logging.LogMaxFiles = 7
					}
				case "BOUNCER_COMPRESS_LOGS":
					config.Logging.CompressLogs = aws.Bool(value == "true")
				case "BOUNCER_CERT_PATH":
					config.CertPath = value
				case "BOUNCER_KEY_PATH":
					config.KeyPath = value
				case "BOUNCER_CA_PATH":
					config.CAPath = value
				case "BOUNCER_SUPPORTED_ACTIONS":
					config.SupportedActions = strings.Split(value, ",")
				}

			}
		}
	}
	for _, v := range acls {
		config.WebACLConfig = append(config.WebACLConfig, *v)
	}
}

func (c *bouncerConfig) ValidateAndSetDefaults() error {
	if err := c.Logging.setup("crowdsec-aws-waf-bouncer.log"); err != nil {
		return err
	}

	if c.APIKey == "" && c.CertPath == "" && c.KeyPath == "" {
		return fmt.Errorf("api_key or certificates paths are required")
	}

	if c.APIUrl == "" {
		return fmt.Errorf("api_url is required")
	}

	if !strings.HasSuffix(c.APIUrl, "/") {
		c.APIUrl = c.APIUrl + "/"
	}

	if c.UpdateFrequency == "" {
		c.UpdateFrequency = "10s"
	}

	for _, action := range c.SupportedActions {
		if !slices.Contains(ValidActions, action) {
			return fmt.Errorf("supported_actions must be a list from %v", ValidActions)
		}
	}

	if len(c.SupportedActions) == 0 {
		c.SupportedActions = ValidActions
	}

	if len(c.WebACLConfig) == 0 {
		return fmt.Errorf("waf_config is required")
	}
	for _, c := range c.WebACLConfig {
		if c.FallbackAction == "" {
			return fmt.Errorf("fallback_action is required")
		}
		if !slices.Contains(ValidActions, c.FallbackAction) {
			return fmt.Errorf("fallback_action must be one of %v", ValidActions)
		}
		if c.RuleGroupName == "" {
			return fmt.Errorf("rule_group_name is required")
		}
		if c.Scope == "" {
			return fmt.Errorf("scope is required")
		}

		if c.IPHeader != "" && c.IPHeaderPosition == "" {
			return fmt.Errorf("ip_header_position is required when ip_header is set")
		}

		if c.IPHeaderPosition != "" && !slices.Contains(validIpHeaderPosition, c.IPHeaderPosition) {
			return fmt.Errorf("ip_header_position must be one of %v", validIpHeaderPosition)
		}

		if !slices.Contains(validScopes, c.Scope) {
			return fmt.Errorf("scope must be one of %v", validScopes)
		}
		if c.IpsetPrefix == "" {
			return fmt.Errorf("ipset_prefix is required")
		}
		if c.Region == "" && strings.ToUpper(c.Scope) == "REGIONAL" {
			return fmt.Errorf("region is required when scope is REGIONAL")
		}

		ipsetPrefix := make(map[string]bool)
		ruleGroupNames := make(map[string]bool)

		if _, ok := ipsetPrefix[c.IpsetPrefix]; ok {
			return fmt.Errorf("ipset_prefix value must be unique")
		} else {
			ipsetPrefix[c.IpsetPrefix] = true
		}
		if _, ok := ruleGroupNames[c.RuleGroupName]; ok {
			return fmt.Errorf("rule_group_name value must be unique")
		} else {
			ruleGroupNames[c.RuleGroupName] = true
		}

		if c.Capacity == 0 {
			c.Capacity = 300
		}
	}

	return nil
}

func MergedConfig(configPath string) ([]byte, error) {
	patcher := yamlpatch.NewPatcher(configPath, ".local")
	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func NewConfig(reader io.Reader) (bouncerConfig, error) {
	config := bouncerConfig{}

	content, err := io.ReadAll(reader)
	if err != nil {
		return bouncerConfig{}, err
	}

	if err = yaml.UnmarshalStrict(content, &config); err != nil {
		return bouncerConfig{}, err
	}

	if len(content) == 0 {
		log.Info("Empty or missing configuration file: using envvars only")
	}

	getConfigFromEnv(&config)

	if err := config.ValidateAndSetDefaults(); err != nil {
		return bouncerConfig{}, err
	}

	return config, nil
}
