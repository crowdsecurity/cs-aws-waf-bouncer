package cmd

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/coreos/go-systemd/v22/daemon"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"github.com/crowdsecurity/go-cs-lib/pkg/version"

	"github.com/crowdsecurity/cs-aws-waf-bouncer/pkg/cfg"
	"github.com/crowdsecurity/cs-aws-waf-bouncer/pkg/waf"
)

var wafInstances = make([]*waf.WAF, 0)

func resourceCleanup() {
	for _, w := range wafInstances {
		w.Logger.Infof("Cleaning up resources")
		err := w.Cleanup()
		if err != nil {
			log.Errorf("Error cleaning up WAF: %s", err)
		}
	}
}

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return fmt.Errorf("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return fmt.Errorf("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func processDecisions(decisions *models.DecisionsStreamResponse, supportedActions []string) waf.Decisions {
	d := waf.Decisions{
		V4Add:        make(map[string][]*string),
		V6Add:        make(map[string][]*string),
		V4Del:        make(map[string][]*string),
		V6Del:        make(map[string][]*string),
		CountriesAdd: make(map[string][]*string),
		CountriesDel: make(map[string][]*string),
	}

	for _, decision := range decisions.New {
		decisionType := strings.ToLower(*decision.Type)
		if !slices.Contains(supportedActions, decisionType) {
			decisionType = "fallback"
		}
		if strings.ToLower(*decision.Scope) == "ip" || strings.ToLower(*decision.Scope) == "range" {
			if strings.Contains(*decision.Value, ":") {
				if !strings.Contains(*decision.Value, "/") {
					d.V6Add[decisionType] = append(d.V6Add[decisionType], aws.String(fmt.Sprintf("%s/128", *decision.Value)))
				} else {
					d.V6Add[decisionType] = append(d.V6Add[decisionType], decision.Value)
				}
			} else {
				if !strings.Contains(*decision.Value, "/") {
					d.V4Add[decisionType] = append(d.V4Add[decisionType], aws.String(fmt.Sprintf("%s/32", *decision.Value)))
				} else {
					d.V4Add[decisionType] = append(d.V4Add[decisionType], decision.Value)
				}
			}
		} else if strings.ToLower(*decision.Scope) == "country" {
			d.CountriesAdd[decisionType] = append(d.CountriesAdd[decisionType], decision.Value)
		} else {
			log.Errorf("unsupported scope: %s", *decision.Scope)
		}
	}

	for _, decision := range decisions.Deleted {
		decisionType := strings.ToLower(*decision.Type)
		if !slices.Contains(supportedActions, decisionType) {
			decisionType = "fallback"
		}
		if strings.ToLower(*decision.Scope) == "ip" || strings.ToLower(*decision.Scope) == "range" {
			if strings.Contains(*decision.Value, ":") {
				if !strings.Contains(*decision.Value, "/") {
					d.V6Del[decisionType] = append(d.V6Del[decisionType], aws.String(fmt.Sprintf("%s/128", *decision.Value)))
				} else {
					d.V6Del[decisionType] = append(d.V6Del[decisionType], decision.Value)
				}
			} else {
				if !strings.Contains(*decision.Value, "/") {
					d.V4Del[decisionType] = append(d.V4Del[decisionType], aws.String(fmt.Sprintf("%s/32", *decision.Value)))
				} else {
					d.V4Del[decisionType] = append(d.V4Del[decisionType], decision.Value)
				}
			}
		} else if strings.ToLower(*decision.Scope) == "country" {
			d.CountriesDel[decisionType] = append(d.CountriesDel[decisionType], decision.Value)
		} else {
			log.Errorf("unsupported scope: %s", *decision.Scope)
		}
	}

	return d
}

func Execute() error {
	configPath := flag.String("c", "", "path to crowdsec-aws-waf-bouncer.yaml")
	bouncerVersion := flag.Bool("version", false, "display version and exit")
	traceMode := flag.Bool("trace", false, "set trace mode")
	debugMode := flag.Bool("debug", false, "set debug mode")
	testConfig := flag.Bool("t", false, "test config and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Printf("%s", version.FullString())
		return nil
	}

	configBytes := []byte{}
	var err error

	if configPath != nil && *configPath != "" {
		configBytes, err = cfg.MergedConfig(*configPath)
		if err != nil {
			return fmt.Errorf("could not read configuration: %w", err)
		}
	}

	if *showConfig {
		fmt.Println(string(configBytes))
		return nil
	}

	config, err := cfg.NewConfig(bytes.NewReader(configBytes))

	if debugMode != nil && *debugMode {
		log.SetLevel(log.DebugLevel)
	}

	if traceMode != nil && *traceMode {
		log.SetLevel(log.TraceLevel)
	}

	if err != nil {
		return fmt.Errorf("could not parse configuration: %w", err)
	}

	log.Infof("Starting crowdsec-aws-waf-bouncer %s", version.String())

	if *testConfig {
		for _, wafConfig := range config.WebACLConfig {
			log.Debugf("Create WAF instance with config: %+v", wafConfig)
			_, err := waf.NewWaf(wafConfig)
			if err != nil {
				return fmt.Errorf("configuration error: %w", err)
			}
		}
		log.Info("valid config")
		return nil
	}

	bouncer := &csbouncer.StreamBouncer{
		APIKey:             config.APIKey,
		APIUrl:             config.APIUrl,
		TickerInterval:     config.UpdateFrequency,
		InsecureSkipVerify: aws.Bool(config.InsecureSkipVerify),
		UserAgent:          fmt.Sprintf("crowdsec-aws-waf-bouncer/%s", version.String()),
		Scopes:             []string{"ip", "range", "country"},
		CertPath:           config.CertPath,
		KeyPath:            config.KeyPath,
		CAPath:             config.CAPath,
	}

	if err := bouncer.Init(); err != nil {
		return err
	}

	defer resourceCleanup()

	for _, wafConfig := range config.WebACLConfig {
		log.Debugf("Create WAF instance with config: %+v", wafConfig)
		w, err := waf.NewWaf(wafConfig)
		if err != nil {
			return fmt.Errorf("could not create waf instance: %w", err)
		}
		err = w.Init()
		if err != nil {
			if os.Getenv("CS_AWS_WAF_BOUNCER_TESTING") == "" {
				return fmt.Errorf("could not initialize waf instance: %w", err)
			}
			log.Errorf("could not initialize waf instance: %v+", err)
		}
		wafInstances = append(wafInstances, w)
	}

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		return HandleSignals(ctx)
	})

	g.Go(func() error {
		bouncer.Run(ctx)
		return fmt.Errorf("bouncer stream halted")
	})

	if config.Daemon {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Warnf("failed to notify: %v", err)
		}
	}

	g.Go(func() error {
		log.Info("Starting processing decisions")
		for {
			select {
			case <-ctx.Done():
				log.Info("terminating bouncer process")
				for _, w := range wafInstances {
					w.T.Kill(nil)
				}
				return nil
			case decisions := <-bouncer.Stream:
				log.Info("Polling decisions")

				d := processDecisions(decisions, config.SupportedActions)
				for _, w := range wafInstances {
					w.DecisionsChan <- d
				}
			}
		}
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("process terminated with error: %w", err)
	}

	return nil
}
