import json

extra_config = {
    'waf_config': [
        {
           'web_acl_name': 'testwebacl',
           'fallback_action': 'ban',
           'rule_group_name': 'crowdsec-rule-group-eu-west-1',
           'scope': 'REGIONAL',
           'ipset_prefix': 'crowdsec-ipset-a',
           'region': 'eu-west-1',
        }
    ]
}

def test_tls_server(crowdsec, certs_dir, api_key_factory, bouncer, aw_cfg_factory):
    """TLS with server-only certificate"""

    api_key = api_key_factory()

    lapi_env = {
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'LAPI_CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'LAPI_KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'USE_TLS': 'true',
        'LOCAL_API_URL': 'https://localhost:8080',
        'BOUNCER_KEY_custom': api_key,
    }

    certs = certs_dir(lapi_hostname='lapi')

    volumes = {
        certs: {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    with crowdsec(environment=lapi_env, volumes=volumes) as cs:
        cs.wait_for_log("*CrowdSec Local API listening*")
        # TODO: wait_for_https
        cs.wait_for_http(8080, '/health', want_status=None)

        port = cs.probe.get_bound_port('8080')
        cfg = aw_cfg_factory() | extra_config
        cfg['api_url'] = f'https://localhost:{port}'
        cfg['api_key'] = api_key

        with bouncer(cfg) as aw:
            aw.wait_for_lines_fnmatch([
                "*Using API key auth*",
                "*auth-api: auth with api key failed*",
                "*tls: failed to verify certificate: x509: certificate signed by unknown authority*",
            ])

        cfg['ca_cert_path'] = (certs / 'ca.crt').as_posix()

        with bouncer(cfg) as aw:
            aw.wait_for_lines_fnmatch([
                "*Using CA cert *ca.crt*",
                "*Using API key auth*",
                "*Starting processing decisions*",
                "*Polling decisions*",
            ])


def test_tls_mutual(crowdsec, certs_dir, api_key_factory, bouncer, aw_cfg_factory, bouncer_under_test):
    """TLS with two-way bouncer/lapi authentication"""

    lapi_env = {
        'CACERT_FILE': '/etc/ssl/crowdsec/ca.crt',
        'LAPI_CERT_FILE': '/etc/ssl/crowdsec/lapi.crt',
        'LAPI_KEY_FILE': '/etc/ssl/crowdsec/lapi.key',
        'USE_TLS': 'true',
        'LOCAL_API_URL': 'https://localhost:8080',
    }

    certs = certs_dir(lapi_hostname='lapi')

    volumes = {
        certs: {'bind': '/etc/ssl/crowdsec', 'mode': 'ro'},
    }

    with crowdsec(environment=lapi_env, volumes=volumes) as cs:
        cs.wait_for_log("*CrowdSec Local API listening*")
        # TODO: wait_for_https
        cs.wait_for_http(8080, '/health', want_status=None)

        port = cs.probe.get_bound_port('8080')
        cfg = aw_cfg_factory() | extra_config
        cfg['api_url'] = f'https://localhost:{port}'
        cfg['ca_cert_path'] = (certs / 'ca.crt').as_posix()

        cfg['cert_path'] = (certs / 'agent.crt').as_posix()
        cfg['key_path'] = (certs / 'agent.key').as_posix()

        with bouncer(cfg) as cb:
            cb.wait_for_lines_fnmatch([
                "*Starting crowdsec-aws-waf-bouncer*",
                "*Using CA cert*",
                "*Using cert auth with cert * and key *",
                "*API error: access forbidden*",
            ])

        cs.wait_for_log("*client certificate OU ?agent-ou? doesn't match expected OU ?bouncer-ou?*")

        cfg['cert_path'] = (certs / 'bouncer.crt').as_posix()
        cfg['key_path'] = (certs / 'bouncer.key').as_posix()

        with bouncer(cfg) as aw:
            aw.wait_for_lines_fnmatch([
                "*Starting crowdsec-aws-waf-bouncer*",
                "*Using CA cert*",
                "*Using cert auth with cert * and key *",
                "*Starting processing decisions*",
                "*Polling decisions*",
            ])

            # check that the bouncer is registered
            res = cs.cont.exec_run('cscli bouncers list -o json')
            assert res.exit_code == 0
            bouncers = json.loads(res.output)
            assert len(bouncers) == 1
            assert bouncers[0]['name'].startswith('@')
            assert bouncers[0]['auth_type'] == 'tls'
            assert bouncers[0]['type'] == bouncer_under_test
