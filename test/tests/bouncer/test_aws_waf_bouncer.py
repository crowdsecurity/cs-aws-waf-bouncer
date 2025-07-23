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
