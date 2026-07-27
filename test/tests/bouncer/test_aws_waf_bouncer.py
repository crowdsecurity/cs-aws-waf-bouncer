def valid_waf_config():
    return {
        "web_acl_name": "testwebacl",
        "fallback_action": "ban",
        "rule_group_name": "crowdsec-rule-group-eu-west-1",
        "scope": "REGIONAL",
        "ipset_prefix": "crowdsec-ipset-a",
        "region": "eu-west-1",
    }


def test_no_api_key(crowdsec, bouncer, aw_cfg_factory):
    cfg = aw_cfg_factory()
    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: api_key or certificates paths are required*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()

    cfg["api_key"] = ""

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: api_key or certificates paths are required*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()


def test_no_lapi_url(bouncer, aw_cfg_factory):
    cfg = aw_cfg_factory()

    cfg["api_key"] = "not-used"

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: api_url is required*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()

    cfg["api_url"] = ""

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: api_url is required*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()


def test_partial_config(bouncer, aw_cfg_factory):
    cfg = aw_cfg_factory()
    cfg["api_key"] = "not-used"
    cfg["api_url"] = "http://localhost:8237"

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: waf_config is required*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()

    waf = {"web_acl_name": "testwebacl"}

    cfg["waf_config"] = [waf]

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: fallback_action is required*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()

    waf["fallback_action"] = "ban"

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: rule_group_name is required*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()

    waf["rule_group_name"] = "crowdsec-rule-group-eu-west-1"

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: scope is required*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()

    waf["scope"] = "REGIONAL"

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: ipset_prefix is required*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()

    waf["ipset_prefix"] = "crowdsec-ipset-a"

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: region is required when scope is REGIONAL*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()

    waf["region"] = "eu-west-1"

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not initialize waf instance: failed to list resources: operation error WAFV2: ListWebACLs, get identity: get credentials: failed to refresh cached credentials, no EC2 IMDS role found*"
            ]
        )

        # this requires more time
        aw.proc.wait(timeout=5)
        assert not aw.proc.is_running()


def test_decisions_filter_config(bouncer, aw_cfg_factory):
    """The LAPI-side filters and the per web ACL decisions_filter are accepted."""
    waf = valid_waf_config()
    waf["decisions_filter"] = {
        "include_origins": ["cscli", "crowdsec"],
        "exclude_origins": ["CAPI"],
        "scenarios_containing": ["http"],
        "scenarios_not_containing": ["crawl"],
    }

    cfg = aw_cfg_factory()
    cfg["api_key"] = "not-used"
    cfg["api_url"] = "http://localhost:8237"
    cfg["scenarios_containing"] = ["http"]
    cfg["scenarios_not_containing"] = ["crawl"]
    cfg["origins"] = ["cscli", "crowdsec"]
    cfg["waf_config"] = [waf]

    with bouncer(cfg) as aw:
        # the config parses: the bouncer gets past cfg.NewConfig() and starts up
        aw.wait_for_lines_fnmatch(
            [
                "*Starting crowdsec-aws-waf-bouncer*",
            ]
        )


def test_decisions_filter_unknown_key(bouncer, aw_cfg_factory):
    """decisions_filter has no 'origins' key: use include_origins/exclude_origins."""
    waf = valid_waf_config()
    waf["decisions_filter"] = {"origins": ["cscli"]}

    cfg = aw_cfg_factory()
    cfg["api_key"] = "not-used"
    cfg["api_url"] = "http://localhost:8237"
    cfg["waf_config"] = [waf]

    with bouncer(cfg) as aw:
        aw.wait_for_lines_fnmatch(
            [
                "*could not parse configuration: failed to unmarshal:*field origins not found*",
            ]
        )
        aw.proc.wait(timeout=0.2)
        assert not aw.proc.is_running()
