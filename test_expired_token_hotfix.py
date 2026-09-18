#!/usr/bin/env python3
"""Hermetic, fake-only tests for the expired-token refresh hotfix.

Covers the Phase-1 behaviour changes:
  * an STS AssumeRole request never asks for more than 3600 seconds, even when a
    larger duration argument or ROLE_MAX_DURATION is supplied;
  * a role/STS failure (such as a rejected duration) blocks credential
    persistence AND the kubeconfig update;
  * AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE are honoured consistently for
    both the reuse read and the credential write;
  * an explicitly-set but unusable AWS file override fails closed instead of
    silently using the default ~/.aws path;
  * valid credentials are reused while expired/near-expiry credentials refresh.

No test reads the real ~/.aws tree, a real kubeconfig, real credentials, an MFA
device, or the network. boto3/botocore are stubbed in sys.modules so the modules
import with only the Python standard library; every AWS boundary is faked and all
file I/O uses throwaway temporary directories.

Run with:  python3 -m unittest test_expired_token_hotfix -v
"""
import configparser
import os
import sys
import tempfile
import types
import unittest
from argparse import Namespace
from datetime import datetime, timezone, timedelta
from unittest import mock

# --- Hermetic import shims -------------------------------------------------
_boto3 = types.ModuleType("boto3")
_boto3.Session = lambda *a, **k: None
_boto3.client = lambda *a, **k: None
sys.modules.setdefault("boto3", _boto3)

_botocore = types.ModuleType("botocore")
_botocore_exc = types.ModuleType("botocore.exceptions")


class _BotoCoreError(Exception):
    """Stand-in for botocore.exceptions.BotoCoreError."""


class _ProfileNotFound(_BotoCoreError):
    pass


_botocore_exc.BotoCoreError = _BotoCoreError
_botocore_exc.ProfileNotFound = _ProfileNotFound
_botocore.exceptions = _botocore_exc
sys.modules.setdefault("botocore", _botocore)
sys.modules.setdefault("botocore.exceptions", _botocore_exc)

_botocore_config = types.ModuleType("botocore.config")


class _Config:
    def __init__(self, **kwargs):
        self.kwargs = dict(kwargs)


_botocore_config.Config = _Config
_botocore.config = _botocore_config
sys.modules.setdefault("botocore.config", _botocore_config)

import aws_config as cfg_mod        # noqa: E402
import credentials as creds_mod     # noqa: E402
import main as main_mod             # noqa: E402
import settings as settings_mod     # noqa: E402

MFA_CODE = "424242"
FAKE_MFA_SERIAL = "arn:aws:iam::000000000000:mfa/fake"
AWS_ENV_KEYS = ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE")


def _future(hours=1):
    return datetime.now(timezone.utc) + timedelta(hours=hours)


def _clean_aws_env(**overrides):
    """A patch.dict context that starts from a KNOWN AWS-env baseline.

    Any ambient operator AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE is removed
    first so a test never accidentally reads real files; ``overrides`` then set
    exactly the values under test.
    """
    to_set = {k: v for k, v in overrides.items() if v is not None}

    class _Ctx:
        def __enter__(self_inner):
            self_inner._saved = {k: os.environ.get(k) for k in AWS_ENV_KEYS}
            for k in AWS_ENV_KEYS:      # start from a known-empty AWS baseline
                os.environ.pop(k, None)
            for k, v in to_set.items():  # then apply exactly the values under test
                os.environ[k] = v
            return self_inner

        def __exit__(self_inner, *exc):
            for k in AWS_ENV_KEYS:
                os.environ.pop(k, None)
                if self_inner._saved[k] is not None:
                    os.environ[k] = self_inner._saved[k]
            return False

    return _Ctx()


def _role_config(profile="env", source="shared"):
    cp = configparser.ConfigParser()
    section = f"profile {profile}"
    cp.add_section(section)
    cp.set(section, "role_arn", "arn:aws:iam::222222222222:role/devops")
    cp.set(section, "source_profile", source)
    return cp


def _capturing_role_boto3(response=None, assume_side_effect=None):
    """Fake boto3 whose sts client records assume_role kwargs or raises."""
    b = mock.MagicMock()
    frozen = mock.Mock(access_key="src-ak", secret_key="src-sk", token="src-tok")
    (b.Session.return_value.get_credentials.return_value
     .get_frozen_credentials.return_value) = frozen
    client = b.client.return_value
    if assume_side_effect is not None:
        client.assume_role.side_effect = assume_side_effect
    else:
        client.assume_role.return_value = response
    return b, client


def _good_sts_creds():
    return {"AccessKeyId": "ak-fake", "SecretAccessKey": "sk-fake",
            "SessionToken": "tok-fake", "Expiration": _future()}


def _write_creds_file(path, profile="env2auth", expiration_iso=None):
    lines = [f"[{profile}]",
             "aws_access_key_id = AK",
             "aws_secret_access_key = SK",
             "aws_session_token = TOK"]
    if expiration_iso is not None:
        lines.append(f"{creds_mod.EXPIRATION_METADATA_KEY} = {expiration_iso}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# ===========================================================================
# 1) STS AssumeRole duration is capped at 3600 seconds
# ===========================================================================
class RoleSessionDurationTests(unittest.TestCase):
    def _assume_role_duration(self, duration=None):
        b, client = _capturing_role_boto3(response={"Credentials": _good_sts_creds()})
        cfg = _role_config()
        with mock.patch.object(creds_mod, "boto3", b):
            if duration is None:
                out = creds_mod.get_temporary_credentials(cfg, "env", FAKE_MFA_SERIAL, MFA_CODE)
            else:
                out = creds_mod.get_temporary_credentials(
                    cfg, "env", FAKE_MFA_SERIAL, MFA_CODE, duration=duration)
        self.assertTrue(out)
        _, kwargs = client.assume_role.call_args
        return kwargs["DurationSeconds"]

    def test_default_duration_is_capped_at_3600(self):
        self.assertEqual(self._assume_role_duration(), 3600)

    def test_never_requests_more_than_3600_with_large_argument(self):
        self.assertLessEqual(self._assume_role_duration(duration=999999), 3600)

    def test_never_requests_more_than_3600_with_user_max_argument(self):
        self.assertLessEqual(
            self._assume_role_duration(duration=settings_mod.USER_MAX_DURATION), 3600)

    def test_settings_role_max_duration_is_at_most_one_hour(self):
        self.assertLessEqual(settings_mod.ROLE_MAX_DURATION, 3600)


# ===========================================================================
# 2) A role/STS failure blocks persistence AND the kubeconfig update
# ===========================================================================
class RoleFailureBlocksPersistenceAndConnectTests(unittest.TestCase):
    def test_assume_role_failure_returns_empty_and_main_skips_write_and_connect(self):
        cfg = _role_config()
        cfg.read = lambda *a, **k: []  # main calls config.read(...) — never touch ~/.aws
        b, _ = _capturing_role_boto3(
            assume_side_effect=Exception("DurationSeconds exceeds MaxSessionDuration"))
        configure = mock.MagicMock(return_value=True)
        connect = mock.MagicMock(return_value=True)
        with _clean_aws_env(), \
                mock.patch.object(main_mod, "parse_args",
                                  return_value=Namespace(environment="env-dev", force_refresh=True)), \
                mock.patch.object(main_mod.configparser, "ConfigParser", return_value=cfg), \
                mock.patch.object(main_mod, "read_aws_config",
                                  return_value={"cluster_name": "c", "region": "eu-west-1",
                                                "mfa_serial": FAKE_MFA_SERIAL}), \
                mock.patch.object(main_mod, "is_role_profile", return_value=True), \
                mock.patch.object(main_mod, "credentials_are_valid", return_value=False), \
                mock.patch.object(main_mod, "get_mfa_token", return_value=MFA_CODE), \
                mock.patch.object(main_mod, "configure_aws_credentials", configure), \
                mock.patch.object(main_mod, "connect_to_cluster", connect), \
                mock.patch.object(creds_mod, "boto3", b):
            rc = main_mod.main()
        self.assertEqual(rc, 1)
        configure.assert_not_called()   # no partial/stale persistence
        connect.assert_not_called()     # no kubeconfig update


# ===========================================================================
# 3) AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE are honoured consistently
# ===========================================================================
class EnvPathHonouredTests(unittest.TestCase):
    def test_config_file_path_honours_env(self):
        with _clean_aws_env(AWS_CONFIG_FILE="/tmp/custom-x/config"):
            self.assertEqual(cfg_mod.config_file_path(), "/tmp/custom-x/config")

    def test_credentials_file_path_honours_env(self):
        with _clean_aws_env(AWS_SHARED_CREDENTIALS_FILE="/tmp/custom-x/credentials"):
            self.assertEqual(cfg_mod.credentials_file_path(), "/tmp/custom-x/credentials")

    def test_default_when_env_unset(self):
        with _clean_aws_env():
            self.assertTrue(cfg_mod.config_file_path().endswith(os.path.join(".aws", "config")))
            self.assertTrue(
                cfg_mod.credentials_file_path().endswith(os.path.join(".aws", "credentials")))

    def test_reuse_reads_expiration_from_env_credentials_path(self):
        with tempfile.TemporaryDirectory() as d:
            creds = os.path.join(d, "credentials")
            _write_creds_file(creds, "env2auth", _future(hours=2).isoformat())
            with _clean_aws_env(AWS_SHARED_CREDENTIALS_FILE=creds):
                # No explicit path -> must resolve via the environment override.
                self.assertTrue(creds_mod.credentials_are_valid("env2auth"))

    def test_write_targets_env_credentials_path_not_home(self):
        with tempfile.TemporaryDirectory() as d:
            creds = os.path.join(d, "credentials")
            with _clean_aws_env(AWS_SHARED_CREDENTIALS_FILE=creds):
                self.assertTrue(
                    creds_mod.configure_aws_credentials("env2auth", _good_sts_creds()))
            self.assertTrue(os.path.isfile(creds))  # wrote to the override, not ~/.aws
            cp = configparser.ConfigParser()
            cp.optionxform = str
            cp.read(creds, encoding="utf-8")
            self.assertTrue(cp.has_option("env2auth", creds_mod.EXPIRATION_METADATA_KEY))


# ===========================================================================
# 4) An explicit unusable env override fails closed (no silent home fallback)
# ===========================================================================
class UnusableEnvPathFailsClosedTests(unittest.TestCase):
    def test_empty_credentials_env_resolves_to_none(self):
        with _clean_aws_env(AWS_SHARED_CREDENTIALS_FILE="   "):
            self.assertIsNone(cfg_mod.credentials_file_path())

    def test_empty_config_env_resolves_to_none(self):
        with _clean_aws_env(AWS_CONFIG_FILE=""):
            self.assertIsNone(cfg_mod.config_file_path())

    def test_empty_credentials_env_denies_reuse(self):
        with _clean_aws_env(AWS_SHARED_CREDENTIALS_FILE=""):
            self.assertFalse(creds_mod.credentials_are_valid("env2auth"))

    def test_empty_credentials_env_refuses_write(self):
        with _clean_aws_env(AWS_SHARED_CREDENTIALS_FILE="  "):
            self.assertFalse(
                creds_mod.configure_aws_credentials("env2auth", _good_sts_creds()))

    def test_empty_config_env_aborts_main(self):
        connect = mock.MagicMock(return_value=True)
        with _clean_aws_env(AWS_CONFIG_FILE=""), \
                mock.patch.object(main_mod, "parse_args",
                                  return_value=Namespace(environment="env-dev", force_refresh=False)), \
                mock.patch.object(main_mod, "connect_to_cluster", connect):
            self.assertEqual(main_mod.main(), 1)
            connect.assert_not_called()

    def test_empty_credentials_env_aborts_main_before_side_effects(self):
        connect = mock.MagicMock(return_value=True)
        mfa = mock.MagicMock(return_value=MFA_CODE)
        with _clean_aws_env(AWS_SHARED_CREDENTIALS_FILE="   "), \
                mock.patch.object(main_mod, "parse_args",
                                  return_value=Namespace(environment="env-dev", force_refresh=False)), \
                mock.patch.object(main_mod, "get_mfa_token", mfa), \
                mock.patch.object(main_mod, "connect_to_cluster", connect):
            self.assertEqual(main_mod.main(), 1)
            mfa.assert_not_called()
            connect.assert_not_called()


# ===========================================================================
# 5) Predictable refresh: valid reuse; expired/near-expiry refresh once
# ===========================================================================
class ReuseVsRefreshTests(unittest.TestCase):
    def _drive_main(self, expiration_iso):
        with tempfile.TemporaryDirectory() as d:
            creds = os.path.join(d, "credentials")
            _write_creds_file(creds, "env2auth", expiration_iso)
            mfa = mock.MagicMock(return_value=MFA_CODE)
            sts = mock.MagicMock(return_value=_good_sts_creds())
            configure = mock.MagicMock(return_value=True)
            connect = mock.MagicMock(return_value=True)
            with _clean_aws_env(AWS_SHARED_CREDENTIALS_FILE=creds), \
                    mock.patch.object(main_mod, "parse_args",
                                      return_value=Namespace(environment="env-dev", force_refresh=False)), \
                    mock.patch.object(main_mod, "configparser", mock.MagicMock()), \
                    mock.patch.object(main_mod, "read_aws_config",
                                      return_value={"cluster_name": "c", "region": "eu-west-1",
                                                    "mfa_serial": FAKE_MFA_SERIAL}), \
                    mock.patch.object(main_mod, "is_role_profile", return_value=False), \
                    mock.patch.object(main_mod, "get_mfa_token", mfa), \
                    mock.patch.object(main_mod, "get_temporary_credentials", sts), \
                    mock.patch.object(main_mod, "configure_aws_credentials", configure), \
                    mock.patch.object(main_mod, "connect_to_cluster", connect):
                rc = main_mod.main()
            return rc, mfa, sts, connect

    def test_valid_credentials_are_reused(self):
        rc, mfa, sts, connect = self._drive_main(_future(hours=2).isoformat())
        self.assertEqual(rc, 0)
        mfa.assert_not_called()       # reuse: no MFA
        sts.assert_not_called()       # reuse: no STS
        connect.assert_called_once()

    def test_expired_credentials_refresh_once(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        rc, mfa, sts, connect = self._drive_main(past)
        self.assertEqual(rc, 0)
        mfa.assert_called_once()
        sts.assert_called_once()
        connect.assert_called_once()

    def test_near_expiry_credentials_refresh_once(self):
        near = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
        rc, mfa, sts, connect = self._drive_main(near)
        self.assertEqual(rc, 0)
        mfa.assert_called_once()      # inside the safety margin -> refresh
        sts.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
