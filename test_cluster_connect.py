"""Fail-closed tests for the AWS/EKS connect script.

Fakes only: a fake 1Password ``op``, fake STS (boto3), a fake ``aws configure set``
that persists to synthetic config/credentials files, and a fake ``aws eks
update-kubeconfig``. No real AWS/Kubernetes/1Password/cloud calls. Distinctive
fake secret values are used so leakage can be asserted against.
"""

import os
import sys
import time
import types
import subprocess
import configparser
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import errors
import aws_config
import credentials as credmod
import main as mainmod

# Distinctive fake secrets — must NEVER appear in logs.
FAKE_AK = "AKIAFAKELEAKCHECK0001"
FAKE_SK = "wSecretFAKELEAKCHECKzzzzzzzzzzzzzzzzzz0001"
FAKE_ST = "FAKESESSIONTOKENLEAKCHECK0001"
FAKE_OTP = "123456"


# --------------------------------------------------------------------------- #
# Fake boto3 / botocore
# --------------------------------------------------------------------------- #
class _FrozenCreds:
    access_key = "AKIASOURCEFAKE"
    secret_key = "sourceSecretFAKE"
    token = "sourceTokenFAKE"


class _BaseCreds:
    def get_frozen_credentials(self):
        return _FrozenCreds()


def _install_fake_boto3(monkeypatch, sts_behavior, *, has_source_creds=True):
    botocore = types.ModuleType("botocore")
    exc = types.ModuleType("botocore.exceptions")

    class ClientError(Exception):
        def __init__(self, error_response, operation_name):
            self.response = error_response
            self.operation_name = operation_name
            super().__init__(operation_name)

    class BotoCoreError(Exception):
        pass

    class ProfileNotFound(Exception):
        def __init__(self, profile=""):
            self.args = (profile,)

    exc.ClientError = ClientError
    exc.BotoCoreError = BotoCoreError
    exc.ProfileNotFound = ProfileNotFound
    botocore.exceptions = exc

    class _Session:
        def __init__(self, profile_name=None):
            self.profile_name = profile_name

        def get_credentials(self):
            return _BaseCreds() if has_source_creds else None

    class _Sts:
        def assume_role(self, **kw):
            return sts_behavior("assume_role", kw, exc)

        def get_session_token(self, **kw):
            return sts_behavior("get_session_token", kw, exc)

    boto3 = types.ModuleType("boto3")
    boto3.Session = _Session
    boto3.client = lambda service, **kw: _Sts()

    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", exc)
    return exc


def _success_sts(future_minutes=60):
    exp = datetime.now(timezone.utc) + timedelta(minutes=future_minutes)

    def behavior(op, kw, exc):
        return {
            "Credentials": {
                "AccessKeyId": FAKE_AK,
                "SecretAccessKey": FAKE_SK,
                "SessionToken": FAKE_ST,
                "Expiration": exp,
            }
        }

    return behavior


def _access_denied_sts():
    def behavior(op, kw, exc):
        raise exc.ClientError({"Error": {"Code": "AccessDenied"}}, "AssumeRole")

    return behavior


def _must_not_call_sts():
    def behavior(op, kw, exc):
        raise AssertionError("STS must not be called")

    return behavior


# --------------------------------------------------------------------------- #
# Fake subprocess dispatcher (op / aws configure set / aws eks update-kubeconfig)
# --------------------------------------------------------------------------- #
class SubprocessController:
    def __init__(self):
        self.op_returncode = 0
        self.op_stdout = (FAKE_OTP + "\n").encode()
        self.eks_returncode = 0
        self.commands = []

    def run(self, cmd, **kwargs):
        self.commands.append(list(cmd))
        head = cmd[:3]
        if cmd[:1] == ["op"]:
            return types.SimpleNamespace(returncode=self.op_returncode, stdout=self.op_stdout, stderr=b"secret-op-stderr")
        if head == ["aws", "configure", "set"]:
            self._configure_set(cmd)
            return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        if head == ["aws", "eks", "update-kubeconfig"]:
            return types.SimpleNamespace(returncode=self.eks_returncode, stdout=b"", stderr=b"provider stderr")
        raise AssertionError(f"unexpected command: {cmd}")

    @staticmethod
    def _configure_set(cmd):
        key, value, profile = cmd[3], cmd[4], cmd[6]
        cred_keys = {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
        if key in cred_keys:
            path = os.environ["AWS_SHARED_CREDENTIALS_FILE"]
            section = profile
        else:
            path = os.environ["AWS_CONFIG_FILE"]
            section = f"profile {profile}"
        cp = configparser.ConfigParser()
        cp.read(path)
        if not cp.has_section(section):
            cp.add_section(section)
        cp.set(section, key, value)
        with open(path, "w") as fh:
            cp.write(fh)


@pytest.fixture
def sp(monkeypatch):
    controller = SubprocessController()
    monkeypatch.setattr(subprocess, "run", controller.run)
    return controller


@pytest.fixture
def aws_env(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    creds = tmp_path / "credentials"
    cfg.write_text("")
    creds.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    return {"config": cfg, "credentials": creds}


def _write_config(path, sections):
    cp = configparser.ConfigParser()
    for name, opts in sections.items():
        cp.add_section(name)
        for k, v in opts.items():
            cp.set(name, k, v)
    with open(path, "w") as fh:
        cp.write(fh)


def _role_config(**overrides):
    base = {
        "profile warriorbetprod": {
            "role_arn": "arn:aws:iam::195275669729:role/warriorbetprod",
            "source_profile": "shared",
            "mfa_serial": "arn:aws:iam::195275669729:mfa/igor",
            "region": "eu-west-1",
            "cluster_name": "legends-prod",
        },
        "profile shared": {"region": "eu-west-1"},
    }
    base["profile warriorbetprod"].update(overrides)
    return base


def _load(path):
    cp = configparser.ConfigParser()
    cp.read(path)
    return cp


def _fp(cfg, cluster="legends-prod", region="eu-west-1",
        role="arn:aws:iam::195275669729:role/warriorbetprod",
        src="shared", mfa="arn:aws:iam::195275669729:mfa/igor",
        profile="warriorbetprod2auth"):
    return aws_config.compute_target_fingerprint(
        profile=profile, role_arn=role, source_profile=src,
        mfa_serial=mfa, region=region, cluster_name=cluster,
    )


# =========================================================================== #
# Strict configuration validation (before STS)
# =========================================================================== #
def test_validate_rejects_mfa_arn_in_role_arn():
    with pytest.raises(errors.ConfigError):
        aws_config.validate_profile_config(
            role_based=True,
            role_arn="arn:aws:iam::1:mfa/igor",       # swapped
            mfa_serial="arn:aws:iam::1:mfa/igor",
            source_profile="shared",
        )


def test_validate_rejects_role_arn_in_mfa_serial():
    with pytest.raises(errors.ConfigError):
        aws_config.validate_profile_config(
            role_based=True,
            role_arn="arn:aws:iam::1:role/r",
            mfa_serial="arn:aws:iam::1:role/r",        # swapped
            source_profile="shared",
        )


def test_validate_rejects_equal_and_missing():
    with pytest.raises(errors.ConfigError):
        aws_config.validate_profile_config(role_based=True, role_arn="", mfa_serial="arn:aws:iam::1:mfa/x", source_profile="shared")
    with pytest.raises(errors.ConfigError):
        aws_config.validate_profile_config(role_based=True, role_arn="arn:aws:iam::1:role/r", mfa_serial="", source_profile="shared")
    with pytest.raises(errors.ConfigError):
        aws_config.validate_profile_config(role_based=True, role_arn="arn:aws:iam::1:role/r", mfa_serial="arn:aws:iam::1:mfa/x", source_profile="")


def test_validate_accepts_well_formed():
    aws_config.validate_profile_config(
        role_based=True,
        role_arn="arn:aws:iam::1:role/r",
        mfa_serial="arn:aws:iam::1:mfa/x",
        source_profile="shared",
    )


def test_main_role_arn_with_mfa_fails_before_sts(aws_env, sp, monkeypatch):
    _write_config(aws_env["config"], _role_config(role_arn="arn:aws:iam::1:mfa/igor"))
    _install_fake_boto3(monkeypatch, _must_not_call_sts())
    monkeypatch.setattr(sys, "argv", ["main.py", "--force-refresh", "warriorbetprod"])
    rc = mainmod.main()
    assert rc == errors.EX_CONFIG
    # op must not have been asked for an OTP either (fails before MFA/STS)
    assert not any(c[:1] == ["op"] for c in sp.commands)


# =========================================================================== #
# Fingerprint + credential-cache validity
# =========================================================================== #
def test_fingerprint_changes_with_role():
    a = _fp(None, role="arn:aws:iam::1:role/legendsprod")
    b = _fp(None, role="arn:aws:iam::1:role/legendbetprod")
    assert a != b


def _valid_cache_config(path, creds_path, fingerprint, *, expiration=None, timestamp=None):
    expiration = expiration or (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    timestamp = str(int(time.time())) if timestamp is None else timestamp
    cp = configparser.ConfigParser()
    cp.add_section("profile warriorbetprod2auth")
    cp.set("profile warriorbetprod2auth", "profile_timestamp", timestamp)
    cp.set("profile warriorbetprod2auth", "credential_fingerprint", fingerprint)
    cp.set("profile warriorbetprod2auth", "credential_expiration", expiration)
    with open(path, "w") as fh:
        cp.write(fh)
    creds = configparser.ConfigParser()
    creds.add_section("warriorbetprod2auth")
    creds.set("warriorbetprod2auth", "aws_access_key_id", FAKE_AK)
    creds.set("warriorbetprod2auth", "aws_secret_access_key", FAKE_SK)
    creds.set("warriorbetprod2auth", "aws_session_token", FAKE_ST)
    with open(creds_path, "w") as fh:
        creds.write(fh)


def test_cache_valid_when_everything_matches(aws_env):
    fp = _fp(None)
    _valid_cache_config(aws_env["config"], aws_env["credentials"], fp)
    assert credmod.credentials_are_valid(_load(aws_env["config"]), "warriorbetprod2auth", True, fp) is True


def test_cache_invalid_on_fingerprint_change(aws_env):
    _valid_cache_config(aws_env["config"], aws_env["credentials"], _fp(None, role="arn:aws:iam::1:role/legendsprod"))
    expected_new = _fp(None, role="arn:aws:iam::1:role/legendbetprod")
    assert credmod.credentials_are_valid(_load(aws_env["config"]), "warriorbetprod2auth", True, expected_new) is False


def test_cache_invalid_missing_timestamp(aws_env):
    fp = _fp(None)
    _valid_cache_config(aws_env["config"], aws_env["credentials"], fp)
    cp = _load(aws_env["config"])
    cp.remove_option("profile warriorbetprod2auth", "profile_timestamp")
    with open(aws_env["config"], "w") as fh:
        cp.write(fh)
    assert credmod.credentials_are_valid(_load(aws_env["config"]), "warriorbetprod2auth", True, fp) is False


def test_cache_invalid_when_expired(aws_env):
    fp = _fp(None)
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    _valid_cache_config(aws_env["config"], aws_env["credentials"], fp, expiration=past)
    assert credmod.credentials_are_valid(_load(aws_env["config"]), "warriorbetprod2auth", True, fp) is False


def test_cache_invalid_when_credentials_incomplete(aws_env):
    fp = _fp(None)
    _valid_cache_config(aws_env["config"], aws_env["credentials"], fp)
    creds = configparser.ConfigParser()
    creds.read(aws_env["credentials"])
    creds.remove_option("warriorbetprod2auth", "aws_session_token")
    with open(aws_env["credentials"], "w") as fh:
        creds.write(fh)
    assert credmod.credentials_are_valid(_load(aws_env["config"]), "warriorbetprod2auth", True, fp) is False


def test_cache_invalid_on_malformed_timestamp(aws_env):
    fp = _fp(None)
    _valid_cache_config(aws_env["config"], aws_env["credentials"], fp, timestamp="not-a-number")
    assert credmod.credentials_are_valid(_load(aws_env["config"]), "warriorbetprod2auth", True, fp) is False


def test_stale_credentials_for_different_role_are_refreshed(aws_env, sp, monkeypatch, caplog):
    # A valid-looking cache exists but its fingerprint is for the OLD role. The
    # config now points at a different role -> cache rejected -> refresh via STS.
    _write_config(aws_env["config"], _role_config())
    _valid_cache_config(aws_env["config"], aws_env["credentials"],
                        _fp(None, role="arn:aws:iam::1:role/OLD-legendsprod"))
    # Re-write the config sections lost by the cache helper (which rewrote the file).
    cp = configparser.ConfigParser(); cp.read(aws_env["config"])
    for name, opts in _role_config().items():
        if not cp.has_section(name):
            cp.add_section(name)
        for k, v in opts.items():
            cp.set(name, k, v)
    with open(aws_env["config"], "w") as fh:
        cp.write(fh)
    _install_fake_boto3(monkeypatch, _success_sts())
    monkeypatch.setattr(sys, "argv", ["main.py", "warriorbetprod"])
    rc = mainmod.main()
    assert rc == 0, caplog.text
    # STS was called (refresh happened) and new metadata persisted.
    assert any(c[:2] == ["aws", "configure"] for c in sp.commands)


# =========================================================================== #
# MFA item resolution
# =========================================================================== #
def test_mfa_item_explicit_override():
    cp = configparser.ConfigParser()
    cp.add_section("profile legendbetprod")
    cp.set("profile legendbetprod", "mfa_item", "AmazonSHARED")
    item = aws_config.resolve_mfa_item(cp, "legendbetprod", role_based=True, source_profile="legendbetprod", env_name="legendbetprod")
    assert item == "AmazonSHARED"


def test_mfa_item_backward_compatible_derivation():
    cp = configparser.ConfigParser()
    cp.add_section("profile warriorbetprod")
    item = aws_config.resolve_mfa_item(cp, "warriorbetprod", role_based=True, source_profile="shared", env_name="warriorbetprod")
    assert item == "AmazonSHARED"


def test_mfa_item_user_based_fallback():
    cp = configparser.ConfigParser()
    cp.add_section("profile dev")
    item = aws_config.resolve_mfa_item(cp, "dev", role_based=False, source_profile="", env_name="dev")
    assert item == "AmazonDEV"


def test_mfa_item_rejects_unsafe():
    cp = configparser.ConfigParser()
    cp.add_section("profile dev")
    cp.set("profile dev", "mfa_item", "bad;rm -rf /")
    with pytest.raises(errors.ConfigError):
        aws_config.resolve_mfa_item(cp, "dev", role_based=False, source_profile="", env_name="dev")


# =========================================================================== #
# Fail-closed exits: STS AccessDenied, failed update-kubeconfig, missing MFA
# =========================================================================== #
def test_sts_access_denied_exits_nonzero_no_traceback(aws_env, sp, monkeypatch, caplog):
    _write_config(aws_env["config"], _role_config())
    _install_fake_boto3(monkeypatch, _access_denied_sts())
    monkeypatch.setattr(sys, "argv", ["main.py", "--force-refresh", "warriorbetprod"])
    rc = mainmod.main()
    assert rc == errors.EX_STS
    assert "Traceback" not in caplog.text
    assert "AccessDenied" in caplog.text  # concise, safe error code only


def test_failed_update_kubeconfig_exits_nonzero(aws_env, sp, monkeypatch, caplog):
    _write_config(aws_env["config"], _role_config())
    _install_fake_boto3(monkeypatch, _success_sts())
    sp.eks_returncode = 1
    monkeypatch.setattr(sys, "argv", ["main.py", "--force-refresh", "warriorbetprod"])
    rc = mainmod.main()
    assert rc == errors.EX_KUBE
    assert "Traceback" not in caplog.text


def test_missing_mfa_token_exits_nonzero(aws_env, sp, monkeypatch):
    _write_config(aws_env["config"], _role_config())
    _install_fake_boto3(monkeypatch, _must_not_call_sts())
    sp.op_returncode = 1  # op fails -> no OTP
    monkeypatch.setattr(sys, "argv", ["main.py", "--force-refresh", "warriorbetprod"])
    rc = mainmod.main()
    assert rc == errors.EX_MFA


# =========================================================================== #
# Successful flow + no secret leakage
# =========================================================================== #
def test_successful_flow_creates_valid_metadata_and_leaks_nothing(aws_env, sp, monkeypatch, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    _write_config(aws_env["config"], _role_config())
    _install_fake_boto3(monkeypatch, _success_sts())
    monkeypatch.setattr(sys, "argv", ["main.py", "--force-refresh", "warriorbetprod"])
    rc = mainmod.main()
    assert rc == 0, caplog.text

    # Credentials file has the three temp fields.
    creds = _load(aws_env["credentials"])
    assert creds.get("warriorbetprod2auth", "aws_access_key_id") == FAKE_AK
    assert creds.get("warriorbetprod2auth", "aws_session_token") == FAKE_ST

    # Config profile has fingerprint + expiration + timestamp; cache now validates.
    cfg = _load(aws_env["config"])
    expected_fp = _fp(None)
    assert cfg.get("profile warriorbetprod2auth", "credential_fingerprint") == expected_fp
    assert cfg.has_option("profile warriorbetprod2auth", "credential_expiration")
    assert credmod.credentials_are_valid(cfg, "warriorbetprod2auth", True, expected_fp) is True

    # No secret/token material leaked to logs.
    blob = caplog.text
    for secret in (FAKE_AK, FAKE_SK, FAKE_ST, FAKE_OTP, "secret-op-stderr", "provider stderr"):
        assert secret not in blob, f"leaked: {secret!r}"


def test_second_run_uses_cache_without_sts(aws_env, sp, monkeypatch, caplog):
    _write_config(aws_env["config"], _role_config())
    _install_fake_boto3(monkeypatch, _success_sts())
    monkeypatch.setattr(sys, "argv", ["main.py", "--force-refresh", "warriorbetprod"])
    assert mainmod.main() == 0
    # Second run without force-refresh: STS must NOT be called again.
    _install_fake_boto3(monkeypatch, _must_not_call_sts())
    monkeypatch.setattr(sys, "argv", ["main.py", "warriorbetprod"])
    assert mainmod.main() == 0
    assert not any(c[:1] == ["op"] for c in sp.commands[-3:])  # no new OTP fetch
