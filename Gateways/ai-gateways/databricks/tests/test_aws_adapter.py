import base64
import json

import pytest

import lambda_adapter
from token_issuer import AuthError, check_client, issue, parse_client_auth, verify

KEY = b"k" * 32
ISS = "dbx-airs"
NOW = 1_800_000_000
CLIENT_ID, CLIENT_SECRET = "dbx-airs-client", "s3cr3t-Value_9"


def basic(cid, secret):
    return "Basic " + base64.b64encode(f"{cid}:{secret}".encode()).decode()


def test_issue_and_verify_round_trip():
    tok = issue(KEY, ISS, NOW)
    assert tok["token_type"] == "Bearer" and tok["expires_in"] == 3600
    assert verify(tok["access_token"], KEY, ISS, NOW + 10)


def test_lifetime_is_capped_at_3600():
    assert issue(KEY, ISS, NOW, lifetime=7200)["expires_in"] == 3600


@pytest.mark.parametrize("offset,ok", [(3600, True), (3660, True), (3661, False), (7200, False)])
def test_expiry_with_60_second_leeway(offset, ok):
    assert verify(issue(KEY, ISS, NOW)["access_token"], KEY, ISS, NOW + offset) is ok


def _forge(header, claims, key=KEY):
    import hashlib
    import hmac

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    signing = f"{b64(header)}.{b64(claims)}"
    sig = base64.urlsafe_b64encode(hmac.new(key, signing.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{signing}.{sig}"


CLAIMS = {"iss": ISS, "aud": "policy", "iat": NOW, "exp": NOW + 3600}


@pytest.mark.parametrize("token", [
    _forge({"alg": "HS256"}, dict(CLAIMS, aud="mcp")),                  # wrong audience
    _forge({"alg": "HS256"}, dict(CLAIMS, iss="someone")),              # wrong issuer
    _forge({"alg": "HS256"}, dict(CLAIMS, exp=NOW + 7200)),             # lifetime over 3600
    _forge({"alg": "none"}, CLAIMS),                                   # alg none
    _forge({"alg": "HS512"}, CLAIMS),                                  # other algorithm
    _forge({"alg": "HS256"}, CLAIMS, key=b"x" * 32),                    # wrong key
    "not.a.token", "", "a.b",
])
def test_bad_tokens_refused(token):
    assert verify(token, KEY, ISS, NOW + 1) is False


def test_tampered_token_refused():
    head, claims, sig = issue(KEY, ISS, NOW)["access_token"].split(".")
    other = base64.urlsafe_b64encode(json.dumps(dict(CLAIMS, aud="policy", exp=NOW + 3000)).encode()).rstrip(b"=")
    assert verify(f"{head}.{other.decode()}.{sig}", KEY, ISS, NOW + 1) is False


def test_client_auth_basic_and_form():
    assert parse_client_auth({"authorization": basic(CLIENT_ID, CLIENT_SECRET)},
                             {"grant_type": "client_credentials"}) == (CLIENT_ID, CLIENT_SECRET)
    assert parse_client_auth({}, {"grant_type": "client_credentials", "client_id": CLIENT_ID,
                                  "client_secret": CLIENT_SECRET}) == (CLIENT_ID, CLIENT_SECRET)


def test_client_auth_header_and_body_with_the_same_credentials_is_accepted():
    """Databricks' default credential exchange method, header_and_body, sends Basic AND the form fields."""
    both = {"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}
    assert parse_client_auth({"authorization": basic(CLIENT_ID, CLIENT_SECRET)}, both) == (CLIENT_ID, CLIENT_SECRET)
    id_only = {"grant_type": "client_credentials", "client_id": CLIENT_ID}
    assert parse_client_auth({"Authorization": basic(CLIENT_ID, CLIENT_SECRET)}, id_only) == (CLIENT_ID, CLIENT_SECRET)


@pytest.mark.parametrize("headers,form,error", [
    ({"authorization": basic(CLIENT_ID, CLIENT_SECRET)},
     {"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": "other"}, "invalid_request"),
    ({"authorization": basic(CLIENT_ID, CLIENT_SECRET)},
     {"grant_type": "client_credentials", "client_id": "other", "client_secret": CLIENT_SECRET}, "invalid_request"),
    ({"authorization": basic(CLIENT_ID, CLIENT_SECRET)},
     {"grant_type": "client_credentials", "client_secret": "other"}, "invalid_request"),
    ({}, {"grant_type": "client_credentials"}, "invalid_client"),
    ({"authorization": basic(CLIENT_ID, CLIENT_SECRET)}, {"grant_type": "password"}, "unsupported_grant_type"),
    ({"authorization": "Basic !!!"}, {"grant_type": "client_credentials"}, "invalid_client"),
])
def test_client_auth_errors(headers, form, error):
    with pytest.raises(AuthError) as e:
        parse_client_auth(headers, form)
    assert str(e.value) == error


def test_check_client():
    assert check_client(CLIENT_ID, CLIENT_SECRET, CLIENT_ID, CLIENT_SECRET)
    assert not check_client(CLIENT_ID, "wrong", CLIENT_ID, CLIENT_SECRET)
    assert not check_client("other", CLIENT_SECRET, CLIENT_ID, CLIENT_SECRET)


# ---------------------------------------------------------------- Lambda routing

REAL_LOAD = lambda_adapter.load_secrets      # before the autouse fixture swaps it out

SECRETS = {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "signing_key": "k" * 32,
           "airs_api_key": "airs-test-key"}


@pytest.fixture(autouse=True)
def fake_secrets(monkeypatch):
    monkeypatch.setattr(lambda_adapter, "load_secrets", lambda: SECRETS)
    monkeypatch.setattr(lambda_adapter, "now", lambda: NOW)


def req(method, path, body="", headers=None, b64=False):
    return {"rawPath": path, "requestContext": {"http": {"method": method}}, "headers": headers or {},
            "body": base64.b64encode(body.encode()).decode() if b64 else body, "isBase64Encoded": b64}


def token_for_tests():
    return issue(SECRETS["signing_key"].encode(), lambda_adapter.ISSUER, NOW)["access_token"]


@pytest.mark.parametrize("method,path", [("GET", "/policy"), ("POST", "/"), ("POST", "/docs"),
                                         ("GET", "/oauth/token"), ("POST", "/policy/x")])
def test_everything_else_is_404(method, path):
    assert lambda_adapter.handler(req(method, path), None)["statusCode"] == 404


def test_token_endpoint_issues_standard_json():
    r = lambda_adapter.handler(req("POST", "/oauth/token", "grant_type=client_credentials",
                                   {"authorization": basic(CLIENT_ID, CLIENT_SECRET),
                                    "content-type": "application/x-www-form-urlencoded"}), None)
    body = json.loads(r["body"])
    assert r["statusCode"] == 200 and set(body) == {"access_token", "token_type", "expires_in"}
    assert r["headers"]["cache-control"] == "no-store"


@pytest.mark.parametrize("form,headers,status", [
    ("grant_type=client_credentials", {"authorization": basic(CLIENT_ID, "wrong")}, 401),
    ("grant_type=password", {"authorization": basic(CLIENT_ID, CLIENT_SECRET)}, 400),
    (f"grant_type=client_credentials&client_id={CLIENT_ID}&client_secret=other",
     {"authorization": basic(CLIENT_ID, CLIENT_SECRET)}, 400),
])
def test_token_endpoint_refusals(form, headers, status):
    assert lambda_adapter.handler(req("POST", "/oauth/token", form, headers), None)["statusCode"] == status


def test_policy_needs_a_valid_token(monkeypatch):
    monkeypatch.setattr(lambda_adapter, "handle", lambda body, settings, **kw: {"result": "ALLOW"})
    body = json.dumps({"event": {"type": "model_call"}})
    assert lambda_adapter.handler(req("POST", "/policy", body), None)["statusCode"] == 401
    bad = {"authorization": "Bearer " + token_for_tests()[:-2] + "xx"}
    assert lambda_adapter.handler(req("POST", "/policy", body, bad), None)["statusCode"] == 401
    good = {"authorization": "Bearer " + token_for_tests()}
    r = lambda_adapter.handler(req("POST", "/policy", body, good, b64=True), None)
    assert r["statusCode"] == 200 and json.loads(r["body"]) == {"result": "ALLOW"}


def test_policy_unreadable_body_is_a_deny_not_an_error():
    good = {"authorization": "Bearer " + token_for_tests()}
    r = lambda_adapter.handler(req("POST", "/policy", "{not json", good), None)
    assert r["statusCode"] == 200 and json.loads(r["body"])["result"] == "DENY"


def test_token_endpoint_accepts_databricks_header_and_body():
    form = f"grant_type=client_credentials&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}"
    r = lambda_adapter.handler(req("POST", "/oauth/token", form, {"authorization": basic(CLIENT_ID, CLIENT_SECRET)}),
                               None)
    assert r["statusCode"] == 200 and set(json.loads(r["body"])) == {"access_token", "token_type", "expires_in"}


def test_policy_path_with_a_trailing_slash_reaches_the_policy():
    """The External policy calls <base_path>/ (as Databricks does); the API's $default route brings it here."""
    body = json.dumps({"event": {"type": "model_call"}})
    assert lambda_adapter.handler(req("POST", "/policy/", body), None)["statusCode"] == 401
    good = {"authorization": "Bearer " + token_for_tests()}
    r = lambda_adapter.handler(req("POST", "/policy/", "{not json", good), None)
    assert r["statusCode"] == 200 and json.loads(r["body"])["result"] == "DENY"


@pytest.mark.parametrize("path", ["/policy//", "/policy/x/", "//policy"])
def test_only_one_trailing_slash_is_forgiven(path):
    assert lambda_adapter.handler(req("POST", path), None)["statusCode"] == 404


# ---------------------------------------------------------------- fail closed with 200, caps, budget

def test_policy_answers_200_deny_when_secrets_cannot_load(monkeypatch, caplog):
    def boom():
        raise KeyError("/dbx-airs/c_signing_key")
    monkeypatch.setattr(lambda_adapter, "load_secrets", boom)
    r = lambda_adapter.handler(req("POST", "/policy/", json.dumps({"event": {"type": "model_call"}})), None)
    body = json.loads(r["body"])
    assert r["statusCode"] == 200 and body["result"] == "DENY" and body["reason"] == lambda_adapter.REASON_FAILED
    assert "c_signing_key" not in r["body"] and "c_signing_key" not in caplog.text and "KeyError" in caplog.text


def test_token_answers_503_when_secrets_cannot_load(monkeypatch):
    monkeypatch.setattr(lambda_adapter, "load_secrets", lambda: (_ for _ in ()).throw(TimeoutError("ssm slow")))
    r = lambda_adapter.handler(req("POST", "/oauth/token", "grant_type=client_credentials",
                                   {"authorization": basic(CLIENT_ID, CLIENT_SECRET)}), None)
    assert r["statusCode"] == 503 and json.loads(r["body"]) == {"error": "temporarily_unavailable"}


@pytest.mark.parametrize("form", ["grant_type=client_credentials&" + "a=" + "x" * 5000,
                                  "&".join(["grant_type=client_credentials"] + [f"f{i}=1" for i in range(12)])])
def test_token_refuses_oversized_or_many_field_bodies_before_reading_secrets(monkeypatch, form):
    monkeypatch.setattr(lambda_adapter, "load_secrets", lambda: pytest.fail("secrets read for a refused body"))
    r = lambda_adapter.handler(req("POST", "/oauth/token", form, {"authorization": basic(CLIENT_ID, CLIENT_SECRET)}),
                               None)
    assert r["statusCode"] == 400 and json.loads(r["body"]) == {"error": "invalid_request"}


@pytest.mark.parametrize("spent,budget", [(0.0, 3.5), (2.0, 2.3), (4.2, 0.5)])
def test_policy_scan_budget_shrinks_by_time_already_spent(monkeypatch, spent, budget):
    """Databricks allows 5 s per call: cold-start work (boto3, SSM) comes out of the AIRS budget."""
    ticks = iter([100.0, 100.0 + spent])
    monkeypatch.setattr(lambda_adapter, "clock", lambda: next(ticks))
    seen = {}

    def fake_handle(body, settings, **kw):
        seen["budget"] = settings.budget_s
        return {"result": "ALLOW"}
    monkeypatch.setattr(lambda_adapter, "handle", fake_handle)
    good = {"authorization": "Bearer " + token_for_tests()}
    lambda_adapter.handler(req("POST", "/policy", json.dumps({"event": {"type": "model_call"}}), good), None)
    assert seen["budget"] == pytest.approx(budget)


# ---------------------------------------------------------------- deploy-time AIRS address

def _seen_settings(monkeypatch):
    seen = {}

    def fake_handle(body, settings, **kw):
        seen["settings"] = settings
        return {"result": "ALLOW"}
    monkeypatch.setattr(lambda_adapter, "handle", fake_handle)
    return seen


def _call_policy():
    good = {"authorization": "Bearer " + token_for_tests()}
    return lambda_adapter.handler(req("POST", "/policy", json.dumps({"event": {"type": "model_call"}}), good), None)


def test_airs_url_is_the_us_endpoint_by_default(monkeypatch):
    monkeypatch.delenv("AIRS_URL", raising=False)
    seen = _seen_settings(monkeypatch)
    _call_policy()
    assert seen["settings"].airs_url == lambda_adapter.US_URL


def test_airs_url_can_name_another_https_endpoint(monkeypatch):
    monkeypatch.setenv("AIRS_URL", "https://192.0.2.1/v1/scan/sync/request")
    seen = _seen_settings(monkeypatch)
    _call_policy()
    assert seen["settings"].airs_url == "https://192.0.2.1/v1/scan/sync/request"


@pytest.mark.parametrize("url", ["http://192.0.2.1/v1/scan/sync/request", "ftp://x", "service.api.example"])
def test_a_non_https_airs_url_denies_without_scanning(monkeypatch, url):
    monkeypatch.setenv("AIRS_URL", url)
    seen = _seen_settings(monkeypatch)
    r = _call_policy()
    assert r["statusCode"] == 200 and json.loads(r["body"]) == {"result": "DENY", "reason": lambda_adapter.REASON_FAILED}
    assert "settings" not in seen



def test_the_handler_passes_its_start_time_so_latency_covers_secrets_and_token_checks(monkeypatch):
    seen = {}

    def fake_handle(body, settings, scan=None, started=None):
        seen["started"] = started
        return {"result": "ALLOW"}
    monkeypatch.setattr(lambda_adapter, "handle", fake_handle)
    monkeypatch.setattr(lambda_adapter, "clock", lambda: 123.0)
    _call_policy()
    assert seen["started"] == 123.0



# ---------------------------------------------------------------- secrets refresh after rotation

class FakeSSM:
    def __init__(self, values):
        self.values, self.calls = values, 0

    def get_parameters(self, Names, WithDecryption):
        self.calls += 1
        return {"Parameters": [{"Name": n, "Value": self.values[n]} for n in Names if n in self.values]}


def _ssm_env(monkeypatch, fake, t):
    for key, env in lambda_adapter.PARAMS.items():
        monkeypatch.setenv(env, "/p/" + key)
    monkeypatch.setattr(lambda_adapter, "_ssm_client", lambda: fake)
    monkeypatch.setattr(lambda_adapter, "clock", lambda: t["now"])
    lambda_adapter._cache.clear()
    monkeypatch.setitem(lambda_adapter._loaded, "at", None)


def test_secrets_are_cached_then_refreshed_after_the_ttl(monkeypatch):
    fake, t = FakeSSM({"/p/" + k: "v1-" + k for k in lambda_adapter.PARAMS}), {"now": 1000.0}
    _ssm_env(monkeypatch, fake, t)
    assert REAL_LOAD()["client_secret"] == "v1-client_secret" and fake.calls == 1
    t["now"] += lambda_adapter.SECRETS_TTL_S - 1
    assert REAL_LOAD()["client_secret"] == "v1-client_secret" and fake.calls == 1
    fake.values = {"/p/" + k: "v2-" + k for k in lambda_adapter.PARAMS}         # rotated in SSM
    t["now"] += 2
    assert REAL_LOAD()["client_secret"] == "v2-client_secret" and fake.calls == 2


def test_a_missing_parameter_fails_closed(monkeypatch):
    values = {"/p/" + k: "v" for k in lambda_adapter.PARAMS if k != "signing_key"}
    _ssm_env(monkeypatch, FakeSSM(values), {"now": 1.0})
    with pytest.raises(KeyError):
        REAL_LOAD()


# ---------------------------------------------------------------- the shape probe

from helpers import CARD  # noqa: E402

def test_shape_of_records_structure_and_lengths_never_values():
    data = {"choices": [{"index": 0, "delta": {"content": CARD}}], CARD: "x", "n": 4111111111111111, "ok": True}
    shape = lambda_adapter.shape_of(data)
    text = json.dumps(shape)
    assert "4111" not in text and "1111" not in text
    assert shape["choices"] == {"list": 1, "items": [{"index": "num", "delta": {"content": {"str": 19}}}]}
    assert shape["<key>"] == {"str": 1} and shape["ok"] == "bool"


def test_shape_of_is_bounded():
    deep = {"a": None}
    node = deep
    for _ in range(20):
        node["a"] = {"a": None}
        node = node["a"]
    assert "..." in json.dumps(lambda_adapter.shape_of(deep))
    assert lambda_adapter.shape_of(list(range(50)))["list"] == 50


def test_shape_line_only_when_the_switch_is_on(monkeypatch, caplog):
    import logging
    caplog.set_level(logging.INFO, logger="airs")
    monkeypatch.setattr(lambda_adapter, "handle", lambda body, settings, **kw: {"result": "ALLOW"})
    monkeypatch.delenv("SHAPE_LOG", raising=False)
    _call_policy()
    assert not any('"shape"' in r.getMessage() for r in caplog.records)
    monkeypatch.setenv("SHAPE_LOG", "true")
    _call_policy()
    shapes = [json.loads(r.getMessage()) for r in caplog.records if '"event": "shape"' in r.getMessage()]
    assert len(shapes) == 1 and shapes[0]["event_type"] == "model_call" and "data" in shapes[0]


def test_secret_values_are_stripped_when_loaded(monkeypatch):
    fake = FakeSSM({"/p/" + k: "v1-" + k + "\n" for k in lambda_adapter.PARAMS})
    _ssm_env(monkeypatch, fake, {"now": 1.0})
    assert REAL_LOAD() == {k: "v1-" + k for k in lambda_adapter.PARAMS}


def test_the_token_issuer_is_a_setting_with_a_neutral_default(monkeypatch):
    import importlib
    try:
        monkeypatch.delenv("TOKEN_ISSUER", raising=False)
        assert importlib.reload(lambda_adapter).ISSUER == "dbx-airs"
        monkeypatch.setenv("TOKEN_ISSUER", "my-adapter")
        assert importlib.reload(lambda_adapter).ISSUER == "my-adapter"
    finally:
        monkeypatch.delenv("TOKEN_ISSUER", raising=False)
        importlib.reload(lambda_adapter)
