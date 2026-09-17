#!/usr/bin/env python3
"""
Hermetic, fake-only regression tests for the AWS/EKS connection CLI.

No test reads real ~/.aws, a real kubeconfig, real credentials, environment
secrets, or calls an external tool/network. Every AWS boundary is mocked; the
AWS SDK (boto3/botocore) is stubbed in sys.modules so the modules import with
only the Python standard library; the credential writer/reader are exercised
against throwaway temporary directories, never the real shared credentials
file.

Run with:  python3 -m unittest test_aws_cluster_connect -v
"""
import configparser
import logging
import os
import stat
import subprocess
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
    """Stand-in for botocore.exceptions.BotoCoreError (expected config errors)."""


class _ProfileNotFound(_BotoCoreError):
    pass


_botocore_exc.BotoCoreError = _BotoCoreError
_botocore_exc.ProfileNotFound = _ProfileNotFound
_botocore.exceptions = _botocore_exc
sys.modules.setdefault("botocore", _botocore)
sys.modules.setdefault("botocore.exceptions", _botocore_exc)

import main as main_mod          # noqa: E402
import credentials as creds_mod  # noqa: E402
import kube as kube_mod          # noqa: E402
import mfa as mfa_mod            # noqa: E402

# --- Secret-like sentinels (fake values only) ------------------------------
ACCESS_KEY = "AKIA-FAKE-ACCESSKEY-0000"
SECRET_KEY = "SECRET-fake-secretaccesskey-1111"
SESSION_TOKEN = "SECRET-fake-sessiontoken-2222"
MFA_CODE = "424242"
SECRET_VALUES = (ACCESS_KEY, SECRET_KEY, SESSION_TOKEN, MFA_CODE)
CRED_SENTINEL = "CRED-SENTINEL-7766"
PATH_SENTINEL = "PATH-SENTINEL-5544"

FAKE_CREDS = {
    "AccessKeyId": ACCESS_KEY,
    "SecretAccessKey": SECRET_KEY,
    "SessionToken": SESSION_TOKEN,
    "Expiration": "2099-01-01T00:00:00Z",
}
CONFIG_DATA = {
    "cluster_name": "fake-cluster",
    "region": "eu-west-1",
    "mfa_serial": "arn:aws:iam::000000000000:mfa/fake",
}
RESP_NO_CREDS = {"ResponseMetadata": {"RequestId": "RESP-SENTINEL-NOCREDS"}}
RESP_INCOMPLETE_CREDS = {"Credentials": {"AccessKeyId": "AKIA-partial-RESP-SENTINEL-BADKEYS"}}
RESP_SENTINELS = ("RESP-SENTINEL-NOCREDS", "RESP-SENTINEL-BADKEYS")
FAKE_MFA_SERIAL = "arn:aws:iam::000000000000:mfa/fake"

_UNSET = object()


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class _CaptureLogs:
    def __enter__(self):
        self.handler = _ListHandler()
        self.root = logging.getLogger()
        self._old_level = self.root.level
        self.root.addHandler(self.handler)
        self.root.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        self.root.removeHandler(self.handler)
        self.root.setLevel(self._old_level)
        return False

    @property
    def text(self):
        return "\n".join(self.handler.messages)


def _success_mocks(**overrides):
    m = dict(
        read_aws_config=mock.MagicMock(return_value=dict(CONFIG_DATA)),
        is_role_profile=mock.MagicMock(return_value=False),
        credentials_are_valid=mock.MagicMock(return_value=False),
        get_mfa_token=mock.MagicMock(return_value=MFA_CODE),
        get_temporary_credentials=mock.MagicMock(return_value=dict(FAKE_CREDS)),
        configure_aws_credentials=mock.MagicMock(return_value=True),
        connect_to_cluster=mock.MagicMock(return_value=True),
    )
    m.update(overrides)
    return m


def _run_main(mocks, *, force_refresh=True, environment="env-dev"):
    with _CaptureLogs() as cap:
        with mock.patch.object(main_mod, "parse_args",
                               return_value=Namespace(environment=environment,
                                                      force_refresh=force_refresh)), \
                mock.patch.object(main_mod, "configparser", mock.MagicMock()), \
                mock.patch.multiple(main_mod, **mocks):
            rc = main_mod.main()
    return rc, mocks, cap.text


# --- Builders --------------------------------------------------------------
def _role_config(profile="env", source="shared"):
    cp = configparser.ConfigParser()
    section = f"profile {profile}"
    cp.add_section(section)
    cp.set(section, "role_arn", "arn:aws:iam::222222222222:role/devops")
    cp.set(section, "source_profile", source)
    return cp


def _role_config_missing_source(profile="env"):
    cp = configparser.ConfigParser()
    section = f"profile {profile}"
    cp.add_section(section)
    cp.set(section, "role_arn", "arn:aws:iam::222222222222:role/devops")
    return cp


def _user_config(profile="env"):
    cp = configparser.ConfigParser()
    section = f"profile {profile}"
    cp.add_section(section)
    cp.set(section, "region", "eu-west-1")
    return cp


def _fake_boto3(response):
    b = mock.MagicMock()
    frozen = mock.Mock(access_key="src-access", secret_key="src-secret", token="src-token")
    b.Session.return_value.get_credentials.return_value.get_frozen_credentials.return_value = frozen
    client = b.client.return_value
    client.assume_role.return_value = response
    client.get_session_token.return_value = response
    return b


def _sentinel_creds(**over):
    base = {
        "AccessKeyId": CRED_SENTINEL + "-ak",
        "SecretAccessKey": CRED_SENTINEL + "-sk",
        "SessionToken": CRED_SENTINEL + "-tok",
        "Expiration": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    base.update(over)
    return base


def _good_creds(expiration=None):
    if expiration is None:
        expiration = datetime.now(timezone.utc) + timedelta(hours=1)
    return {"AccessKeyId": "AKIA-good", "SecretAccessKey": "sk-good",
            "SessionToken": "tok-good", "Expiration": expiration}


def _write_credentials_file(path, profile="env2auth", expiration_value=_UNSET):
    lines = [f"[{profile}]",
             "aws_access_key_id = AK",
             "aws_secret_access_key = SK",
             "aws_session_token = TOK"]
    if expiration_value is not _UNSET:
        lines.append(f"{creds_mod.EXPIRATION_METADATA_KEY} = {expiration_value}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# ===========================================================================
# main() orchestration + exit-code contract
# ===========================================================================
class MainFlowTests(unittest.TestCase):
    def test_success_reuse_path_returns_zero(self):
        mocks = _success_mocks(credentials_are_valid=mock.MagicMock(return_value=True))
        rc, m, _ = _run_main(mocks, force_refresh=False)
        self.assertEqual(rc, 0)
        m["connect_to_cluster"].assert_called_once()
        m["get_mfa_token"].assert_not_called()
        m["get_temporary_credentials"].assert_not_called()

    def test_success_refresh_path_returns_zero(self):
        mocks = _success_mocks()
        rc, m, _ = _run_main(mocks, force_refresh=True)
        self.assertEqual(rc, 0)
        m["get_mfa_token"].assert_called_once()
        m["get_temporary_credentials"].assert_called_once()
        m["configure_aws_credentials"].assert_called_once()
        m["connect_to_cluster"].assert_called_once()

    def test_missing_config_returns_nonzero(self):
        mocks = _success_mocks(read_aws_config=mock.MagicMock(return_value=None))
        rc, m, _ = _run_main(mocks)
        self.assertNotEqual(rc, 0)
        m["connect_to_cluster"].assert_not_called()

    def test_mfa_failure_returns_nonzero_and_skips_downstream(self):
        mocks = _success_mocks(get_mfa_token=mock.MagicMock(return_value=""))
        rc, m, _ = _run_main(mocks)
        self.assertNotEqual(rc, 0)
        m["get_temporary_credentials"].assert_not_called()
        m["configure_aws_credentials"].assert_not_called()
        m["connect_to_cluster"].assert_not_called()

    def test_sts_failure_returns_nonzero_and_skips_connect(self):
        mocks = _success_mocks(get_temporary_credentials=mock.MagicMock(return_value={}))
        rc, m, _ = _run_main(mocks)
        self.assertNotEqual(rc, 0)
        m["configure_aws_credentials"].assert_not_called()
        m["connect_to_cluster"].assert_not_called()

    def test_credential_write_failure_prevents_connect(self):
        mocks = _success_mocks(configure_aws_credentials=mock.MagicMock(return_value=False))
        rc, m, _ = _run_main(mocks)
        self.assertNotEqual(rc, 0)
        m["connect_to_cluster"].assert_not_called()

    def test_connect_failure_returns_nonzero(self):
        mocks = _success_mocks(connect_to_cluster=mock.MagicMock(return_value=False))
        rc, _, _ = _run_main(mocks)
        self.assertNotEqual(rc, 0)

    def test_exit_status_is_stable_and_deterministic(self):
        codes = set()
        for _ in range(3):
            mocks = _success_mocks(connect_to_cluster=mock.MagicMock(return_value=False))
            rc, _, _ = _run_main(mocks)
            codes.add(rc)
        self.assertEqual(codes, {1})

    def test_no_secret_like_values_in_logs(self):
        for label, mocks in (
            ("success", _success_mocks()),
            ("connect-fail", _success_mocks(connect_to_cluster=mock.MagicMock(return_value=False))),
            ("write-fail", _success_mocks(configure_aws_credentials=mock.MagicMock(return_value=False))),
        ):
            _, _, log = _run_main(mocks)
            for secret in SECRET_VALUES:
                self.assertNotIn(secret, log, f"secret leaked in {label} logs")


# ===========================================================================
# main() reuse decision driven by the REAL persisted-expiration reader
# ===========================================================================
class MainReusesPersistedExpirationTests(unittest.TestCase):
    def _drive_main(self, expiration_value, *, downstream):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            _write_credentials_file(path, "env2auth", expiration_value)
            with mock.patch.object(creds_mod, "_default_credentials_path", return_value=path), \
                    mock.patch.object(main_mod, "parse_args",
                                      return_value=Namespace(environment="env-dev", force_refresh=False)), \
                    mock.patch.object(main_mod, "configparser", mock.MagicMock()), \
                    mock.patch.object(main_mod, "read_aws_config", return_value=dict(CONFIG_DATA)), \
                    mock.patch.object(main_mod, "is_role_profile", return_value=False), \
                    mock.patch.multiple(main_mod, **downstream):
                rc = main_mod.main()
            return rc

    def test_valid_stored_expiration_skips_mfa_and_sts(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        downstream = dict(
            get_mfa_token=mock.MagicMock(return_value=MFA_CODE),
            get_temporary_credentials=mock.MagicMock(return_value=dict(FAKE_CREDS)),
            configure_aws_credentials=mock.MagicMock(return_value=True),
            connect_to_cluster=mock.MagicMock(return_value=True),
        )
        rc = self._drive_main(future, downstream=downstream)
        self.assertEqual(rc, 0)
        downstream["get_mfa_token"].assert_not_called()       # reuse: no MFA
        downstream["get_temporary_credentials"].assert_not_called()  # reuse: no STS
        downstream["connect_to_cluster"].assert_called_once()

    def test_expired_stored_expiration_triggers_refresh(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        downstream = dict(
            get_mfa_token=mock.MagicMock(return_value=MFA_CODE),
            get_temporary_credentials=mock.MagicMock(return_value=_good_creds()),
            configure_aws_credentials=mock.MagicMock(return_value=True),
            connect_to_cluster=mock.MagicMock(return_value=True),
        )
        rc = self._drive_main(past, downstream=downstream)
        self.assertEqual(rc, 0)
        downstream["get_mfa_token"].assert_called_once()      # invalid -> refresh
        downstream["get_temporary_credentials"].assert_called_once()

    def test_missing_stored_expiration_triggers_refresh(self):
        downstream = dict(
            get_mfa_token=mock.MagicMock(return_value=MFA_CODE),
            get_temporary_credentials=mock.MagicMock(return_value=_good_creds()),
            configure_aws_credentials=mock.MagicMock(return_value=True),
            connect_to_cluster=mock.MagicMock(return_value=True),
        )
        rc = self._drive_main(_UNSET, downstream=downstream)  # no metadata key at all
        self.assertEqual(rc, 0)
        downstream["get_mfa_token"].assert_called_once()


# ===========================================================================
# credentials.credentials_are_valid — real persisted-expiration reuse reader
# ===========================================================================
class PersistedExpirationReuseTests(unittest.TestCase):
    def _valid(self, expiration_value):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            _write_credentials_file(path, "env2auth", expiration_value)
            return creds_mod.credentials_are_valid("env2auth", credentials_path=path)

    def test_valid_beyond_margin_allows_reuse(self):
        self.assertTrue(self._valid((datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()))

    def test_within_safety_margin_denies_reuse(self):
        # Inside the 60s margin -> deny.
        self.assertFalse(self._valid((datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()))

    def test_expired_denies_reuse(self):
        self.assertFalse(self._valid((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()))

    def test_naive_expiration_denies_reuse(self):
        self.assertFalse(self._valid("2999-01-01T00:00:00"))  # no tz offset

    def test_malformed_expiration_denies_reuse(self):
        self.assertFalse(self._valid("not-a-timestamp"))

    def test_missing_metadata_key_denies_reuse(self):
        self.assertFalse(self._valid(_UNSET))

    def test_missing_file_denies_reuse(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")  # never created
            self.assertFalse(creds_mod.credentials_are_valid("env2auth", credentials_path=path))

    def test_symlinked_credentials_denies_reuse(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real")
            _write_credentials_file(real, "env2auth",
                                    (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
            link = os.path.join(d, "credentials")
            os.symlink(real, link)
            self.assertFalse(creds_mod.credentials_are_valid("env2auth", credentials_path=link))

    def test_reader_never_writes(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            _write_credentials_file(path, "env2auth", "not-a-timestamp")
            before = open(path, encoding="utf-8").read()
            creds_mod.credentials_are_valid("env2auth", credentials_path=path)
            self.assertEqual(open(path, encoding="utf-8").read(), before)
            self.assertEqual(os.listdir(d), ["credentials"])  # no temp/repair artifacts


# ===========================================================================
# credentials.configure_aws_credentials — secure atomic writer
# ===========================================================================
class CredentialsFileWriterTests(unittest.TestCase):
    def test_success_writes_profile_creds_expiration_and_0600(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            exp = datetime.now(timezone.utc) + timedelta(hours=1)
            creds = _good_creds(exp)
            self.assertTrue(creds_mod.configure_aws_credentials("env2auth", creds, credentials_path=path))
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            cp = configparser.ConfigParser()
            cp.optionxform = str
            cp.read(path, encoding="utf-8")
            self.assertEqual(cp.get("env2auth", "aws_access_key_id"), creds["AccessKeyId"])
            self.assertEqual(cp.get("env2auth", "aws_secret_access_key"), creds["SecretAccessKey"])
            self.assertEqual(cp.get("env2auth", "aws_session_token"), creds["SessionToken"])
            stored = cp.get("env2auth", creds_mod.EXPIRATION_METADATA_KEY)
            parsed = datetime.fromisoformat(stored)
            self.assertIsNotNone(parsed.tzinfo)                 # aware, UTC ISO-8601
            self.assertEqual(parsed, exp)                       # round-trips exactly

    def test_preserves_unrelated_profiles_and_options(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[other]\naws_access_key_id = OTHER-AK\nregion = eu-west-1\n"
                         "custom_key = keepme\n\n[env2auth]\nkept = stale\n")
            self.assertTrue(creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=path))
            cp = configparser.ConfigParser()
            cp.optionxform = str
            cp.read(path, encoding="utf-8")
            self.assertEqual(cp.get("other", "aws_access_key_id"), "OTHER-AK")
            self.assertEqual(cp.get("other", "region"), "eu-west-1")
            self.assertEqual(cp.get("other", "custom_key"), "keepme")
            self.assertEqual(cp.get("env2auth", "aws_secret_access_key"), "sk-good")
            self.assertEqual(cp.get("env2auth", "kept"), "stale")  # existing key not dropped

    def test_writer_makes_no_subprocess_or_cli_call(self):
        self.assertFalse(hasattr(creds_mod, "subprocess"))  # module does not even import it
        with tempfile.TemporaryDirectory() as d, \
                mock.patch("subprocess.run") as run, \
                mock.patch("subprocess.Popen") as popen, \
                mock.patch("subprocess.check_output") as check_output:
            path = os.path.join(d, "credentials")
            self.assertTrue(creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=path))
            run.assert_not_called()
            popen.assert_not_called()
            check_output.assert_not_called()

    def test_invalid_profile_names_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            for bad in ("", "env 2auth", "env2auth\n[injected]", "a[b]", "env\t2", "env\x002", 123):
                self.assertFalse(
                    creds_mod.configure_aws_credentials(bad, _good_creds(), credentials_path=path))
            self.assertFalse(os.path.exists(path))  # nothing written

    def test_invalid_credential_mapping_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            cases = [
                "not-a-dict",
                {"AccessKeyId": "", "SecretAccessKey": "s", "SessionToken": "t",
                 "Expiration": datetime.now(timezone.utc) + timedelta(hours=1)},
                {"AccessKeyId": "a", "SecretAccessKey": "s", "SessionToken": "t"},  # no Expiration
                {"AccessKeyId": "a", "SecretAccessKey": "s", "SessionToken": "t",
                 "Expiration": "2099-01-01T00:00:00Z"},                              # not a datetime
                {"AccessKeyId": "a", "SecretAccessKey": "s", "SessionToken": "t",
                 "Expiration": datetime(2099, 1, 1)},                               # naive
            ]
            for creds in cases:
                self.assertFalse(
                    creds_mod.configure_aws_credentials("env2auth", creds, credentials_path=path))
            self.assertFalse(os.path.exists(path))

    def test_missing_parent_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nope", "credentials")  # 'nope' does not exist
            self.assertFalse(creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=path))

    def test_symlink_target_rejected_and_original_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real")
            original = "[keep]\nk = v\n"
            with open(real, "w", encoding="utf-8") as fh:
                fh.write(original)
            link = os.path.join(d, "credentials")
            os.symlink(real, link)
            self.assertFalse(creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=link))
            self.assertEqual(open(real, encoding="utf-8").read(), original)

    def test_non_regular_target_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "credentials")
            os.mkdir(target)  # a directory, not a regular file
            self.assertFalse(creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=target))

    def test_parse_failure_of_existing_file_leaves_it_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            original = "bad line without a section\n"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(original)
            self.assertFalse(creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=path))
            self.assertEqual(open(path, encoding="utf-8").read(), original)

    def test_replace_failure_leaves_original_and_no_temp_files(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            original = "[env2auth]\naws_access_key_id = OLD\n"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(original)
            with mock.patch("os.replace", side_effect=OSError("simulated replace failure")):
                self.assertFalse(
                    creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=path))
            self.assertEqual(open(path, encoding="utf-8").read(), original)  # untouched
            leftovers = [n for n in os.listdir(d)
                         if n.startswith(".aws_cluster_connect.") and n.endswith(".tmp")]
            self.assertEqual(leftovers, [])  # our temp file was cleaned up

    def test_failure_logs_contain_no_secret_or_path_sentinels(self):
        with tempfile.TemporaryDirectory() as d:
            subdir = os.path.join(d, PATH_SENTINEL + "-dir")
            os.mkdir(subdir)
            path = os.path.join(subdir, "credentials")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[env2auth]\n")
            with _CaptureLogs() as cap, mock.patch("os.replace", side_effect=OSError("x")):
                creds_mod.configure_aws_credentials("env2auth", _sentinel_creds(), credentials_path=path)
            for token in (CRED_SENTINEL, PATH_SENTINEL) + SECRET_VALUES:
                self.assertNotIn(token, cap.text)

    def test_concurrent_writers_serialize_and_both_persist(self):
        # Exercise the advisory-lock path deterministically (no timing flakiness):
        # two sequential writers to the same file each fully succeed and the last
        # write wins, with all data intact and 0600 preserved.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            first = _good_creds(datetime.now(timezone.utc) + timedelta(hours=1))
            second = {"AccessKeyId": "AKIA-second", "SecretAccessKey": "sk-second",
                      "SessionToken": "tok-second",
                      "Expiration": datetime.now(timezone.utc) + timedelta(hours=2)}
            self.assertTrue(creds_mod.configure_aws_credentials("env2auth", first, credentials_path=path))
            self.assertTrue(creds_mod.configure_aws_credentials("env2auth", second, credentials_path=path))
            cp = configparser.ConfigParser()
            cp.optionxform = str
            cp.read(path, encoding="utf-8")
            self.assertEqual(cp.get("env2auth", "aws_access_key_id"), "AKIA-second")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


# ===========================================================================
# credentials.get_temporary_credentials — malformed STS response (fail closed)
# ===========================================================================
class MalformedStsResponseTests(unittest.TestCase):
    def _assert_clean_logs(self, log):
        for token in SECRET_VALUES + RESP_SENTINELS:
            self.assertNotIn(token, log)

    def test_role_path_missing_credentials_returns_empty(self):
        cfg = _role_config()
        with _CaptureLogs() as cap, mock.patch.object(creds_mod, "boto3", _fake_boto3(dict(RESP_NO_CREDS))):
            out = creds_mod.get_temporary_credentials(cfg, "env", FAKE_MFA_SERIAL, MFA_CODE)
        self.assertEqual(out, {})
        self._assert_clean_logs(cap.text)

    def test_role_path_incomplete_credentials_returns_empty(self):
        cfg = _role_config()
        with _CaptureLogs() as cap, mock.patch.object(creds_mod, "boto3", _fake_boto3(dict(RESP_INCOMPLETE_CREDS))):
            out = creds_mod.get_temporary_credentials(cfg, "env", FAKE_MFA_SERIAL, MFA_CODE)
        self.assertEqual(out, {})
        self._assert_clean_logs(cap.text)

    def test_user_path_missing_credentials_returns_empty(self):
        cfg = _user_config()
        with _CaptureLogs() as cap, mock.patch.object(creds_mod, "boto3", _fake_boto3(dict(RESP_NO_CREDS))):
            out = creds_mod.get_temporary_credentials(cfg, "env", FAKE_MFA_SERIAL, MFA_CODE)
        self.assertEqual(out, {})
        self._assert_clean_logs(cap.text)


# ===========================================================================
# credentials.get_temporary_credentials — malformed role profile (fail closed)
# ===========================================================================
class MalformedRoleProfileTests(unittest.TestCase):
    def test_missing_source_profile_returns_empty_without_calling_sts(self):
        cfg = _role_config_missing_source()
        fake = _fake_boto3({"Credentials": {}})
        with mock.patch.object(creds_mod, "boto3", fake):
            out = creds_mod.get_temporary_credentials(cfg, "env", FAKE_MFA_SERIAL, MFA_CODE)
        self.assertEqual(out, {})
        fake.client.assert_not_called()
        fake.Session.assert_not_called()

    def test_empty_source_profile_returns_empty(self):
        cfg = _role_config(source="   ")
        fake = _fake_boto3({"Credentials": {}})
        with mock.patch.object(creds_mod, "boto3", fake):
            out = creds_mod.get_temporary_credentials(cfg, "env", FAKE_MFA_SERIAL, MFA_CODE)
        self.assertEqual(out, {})
        fake.client.assert_not_called()


# ===========================================================================
# credentials._valid_sts_credentials — semantic value / Expiration validation
# ===========================================================================
class SemanticCredentialValidationTests(unittest.TestCase):
    def _reject(self, creds):
        cfg = _user_config()
        with _CaptureLogs() as cap, mock.patch.object(creds_mod, "boto3",
                                                      _fake_boto3({"Credentials": creds})):
            out = creds_mod.get_temporary_credentials(cfg, "env", FAKE_MFA_SERIAL, MFA_CODE)
        self.assertEqual(out, {})
        for token in SECRET_VALUES + RESP_SENTINELS + (CRED_SENTINEL,):
            self.assertNotIn(token, cap.text)

    def test_expiration_string_is_rejected(self):
        self._reject(_sentinel_creds(Expiration="2099-01-01T00:00:00Z"))

    def test_expiration_none_is_rejected(self):
        self._reject(_sentinel_creds(Expiration=None))

    def test_expiration_naive_datetime_is_rejected(self):
        self._reject(_sentinel_creds(Expiration=datetime(2099, 1, 1, 0, 0, 0)))

    def test_expiration_already_expired_is_rejected(self):
        self._reject(_sentinel_creds(Expiration=datetime.now(timezone.utc) - timedelta(hours=1)))

    def test_empty_access_key_is_rejected(self):
        self._reject(_sentinel_creds(AccessKeyId=""))

    def test_empty_secret_key_is_rejected(self):
        self._reject(_sentinel_creds(SecretAccessKey=""))

    def test_empty_session_token_is_rejected(self):
        self._reject(_sentinel_creds(SessionToken=""))

    def test_non_string_access_key_is_rejected(self):
        self._reject(_sentinel_creds(AccessKeyId=None))

    def test_valid_future_expiration_accepted_and_not_cached(self):
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        good = {"AccessKeyId": "AKIA-good", "SecretAccessKey": "sk-good",
                "SessionToken": "tok-good", "Expiration": exp}
        cfg = _user_config()
        fake = _fake_boto3({"Credentials": good})
        with mock.patch.object(creds_mod, "boto3", fake):
            first = creds_mod.get_temporary_credentials(cfg, "env", FAKE_MFA_SERIAL, MFA_CODE)
            second = creds_mod.get_temporary_credentials(cfg, "env", FAKE_MFA_SERIAL, MFA_CODE)
        self.assertEqual(first, good)
        self.assertEqual(second, good)
        # No in-process caching: STS is re-invoked every call (no reuse beyond expiry).
        self.assertEqual(fake.client.return_value.get_session_token.call_count, 2)
        self.assertFalse(hasattr(creds_mod, "credentials_cache"))


# ===========================================================================
# credentials.get_aws_session — expected config errors handled; bugs not masked
# ===========================================================================
class GetAwsSessionTests(unittest.TestCase):
    def test_profile_not_found_returns_none(self):
        b = mock.MagicMock()
        b.Session.side_effect = creds_mod.ProfileNotFound("env")
        with mock.patch.object(creds_mod, "boto3", b):
            self.assertIsNone(creds_mod.get_aws_session("env"))

    def test_botocore_config_error_returns_none(self):
        b = mock.MagicMock()
        b.Session.side_effect = creds_mod.BotoCoreError()
        with mock.patch.object(creds_mod, "boto3", b):
            self.assertIsNone(creds_mod.get_aws_session("env"))

    def test_programmer_error_is_not_masked(self):
        b = mock.MagicMock()
        b.Session.side_effect = TypeError("a real bug")
        with mock.patch.object(creds_mod, "boto3", b):
            with self.assertRaises(TypeError):
                creds_mod.get_aws_session("env")


# ===========================================================================
# End-to-end: a malformed STS response through main() skips write + connect
# ===========================================================================
class MalformedStsMainIntegrationTests(unittest.TestCase):
    def test_malformed_sts_via_main_skips_write_and_connect(self):
        cfg = _role_config()
        cfg.read = lambda *a, **k: []  # main calls config.read(...) — never touch ~/.aws
        configure = mock.MagicMock(return_value=True)
        connect = mock.MagicMock(return_value=True)
        with _CaptureLogs() as cap:
            with mock.patch.object(main_mod, "parse_args",
                                   return_value=Namespace(environment="env-dev", force_refresh=True)), \
                    mock.patch.object(main_mod.configparser, "ConfigParser", return_value=cfg), \
                    mock.patch.object(main_mod, "read_aws_config", return_value=dict(CONFIG_DATA)), \
                    mock.patch.object(main_mod, "is_role_profile", return_value=True), \
                    mock.patch.object(main_mod, "credentials_are_valid", return_value=False), \
                    mock.patch.object(main_mod, "get_mfa_token", return_value=MFA_CODE), \
                    mock.patch.object(main_mod, "configure_aws_credentials", configure), \
                    mock.patch.object(main_mod, "connect_to_cluster", connect), \
                    mock.patch.object(creds_mod, "boto3", _fake_boto3(dict(RESP_NO_CREDS))):
                rc = main_mod.main()
        self.assertEqual(rc, 1)
        configure.assert_not_called()
        connect.assert_not_called()
        for token in SECRET_VALUES + RESP_SENTINELS:
            self.assertNotIn(token, cap.text)


# ===========================================================================
# kube.connect_to_cluster — subprocess outcome propagation
# ===========================================================================
class ConnectToClusterTests(unittest.TestCase):
    def test_true_on_zero_exit(self):
        with mock.patch.object(kube_mod.subprocess, "run",
                               return_value=mock.Mock(returncode=0)):
            self.assertTrue(kube_mod.connect_to_cluster("c", "eu-west-1", "p"))

    def test_false_on_nonzero_exit(self):
        with mock.patch.object(kube_mod.subprocess, "run",
                               return_value=mock.Mock(returncode=254)):
            self.assertFalse(kube_mod.connect_to_cluster("c", "eu-west-1", "p"))

    def test_false_when_aws_binary_missing(self):
        with mock.patch.object(kube_mod.subprocess, "run",
                               side_effect=FileNotFoundError("aws")):
            self.assertFalse(kube_mod.connect_to_cluster("c", "eu-west-1", "p"))


# ===========================================================================
# mfa.get_mfa_token — failure returns empty, no secret leakage
# ===========================================================================
class MfaTokenTests(unittest.TestCase):
    def test_success_returns_stripped_token(self):
        with mock.patch.object(mfa_mod.subprocess, "check_output",
                               return_value=b"123456\n"):
            self.assertEqual(mfa_mod.get_mfa_token("AmazonFAKE"), "123456")

    def test_failure_returns_empty_string(self):
        err = subprocess.CalledProcessError(1, ["op", "item", "get", "AmazonFAKE", "--otp"])
        with mock.patch.object(mfa_mod.subprocess, "check_output", side_effect=err):
            self.assertEqual(mfa_mod.get_mfa_token("AmazonFAKE"), "")

    def test_failure_does_not_log_captured_output(self):
        err = subprocess.CalledProcessError(
            1, ["op", "item", "get", "AmazonFAKE", "--otp"], output=b"999111")
        with _CaptureLogs() as cap:
            with mock.patch.object(mfa_mod.subprocess, "check_output", side_effect=err):
                mfa_mod.get_mfa_token("AmazonFAKE")
        self.assertNotIn("999111", cap.text)


# ===========================================================================
# Phase 2B concurrency + TOCTOU hardening
# ===========================================================================
class ConcurrencyAndToctouTests(unittest.TestCase):
    def test_lock_is_acquired_before_reading_existing_file(self):
        """The read-modify-write reads the existing file only AFTER the lock is
        held (no pre-lock parse) — the change that removes the lost-update race."""
        events = []
        real_lock = creds_mod._open_locked
        real_read = creds_mod._read_regular_file_text

        def spy_lock(directory):
            events.append("lock")
            return real_lock(directory)

        def spy_read(path):
            events.append("read")
            return real_read(path)

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[other]\naws_access_key_id = OTHER\n")
            with mock.patch.object(creds_mod, "_open_locked", spy_lock), \
                    mock.patch.object(creds_mod, "_read_regular_file_text", spy_read):
                self.assertTrue(
                    creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=path))
        self.assertIn("lock", events)
        self.assertIn("read", events)
        self.assertLess(events.index("lock"), events.index("read"))  # lock BEFORE read

    def test_second_writer_reads_first_writers_committed_result(self):
        """Two writers starting from the same base file: the second reads the
        first's committed content under the lock, so neither update is lost."""
        reads = []
        real_read = creds_mod._read_regular_file_text

        def spy_read(path):
            content = real_read(path)
            reads.append(content)
            return content

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[base]\nk = v\n")
            with mock.patch.object(creds_mod, "_read_regular_file_text", spy_read):
                self.assertTrue(creds_mod.configure_aws_credentials("aone", _good_creds(), credentials_path=path))
                self.assertTrue(creds_mod.configure_aws_credentials("btwo", _good_creds(), credentials_path=path))
            # The second writer's read observed the first writer's committed profile.
            self.assertIsNotNone(reads[-1])
            self.assertIn("aone", reads[-1])
            self.assertIn("base", reads[-1])
            cp = configparser.ConfigParser()
            cp.optionxform = str
            cp.read(path, encoding="utf-8")
            # No lost update: base + both writers' profiles are all present.
            self.assertTrue(cp.has_section("base"))
            self.assertTrue(cp.has_section("aone"))
            self.assertTrue(cp.has_section("btwo"))
            self.assertEqual(cp.get("base", "k"), "v")

    def test_writer_rejects_expired_expiration_and_leaves_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            original = "[env2auth]\naws_access_key_id = OLD\n"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(original)
            expired = _good_creds(datetime.now(timezone.utc) - timedelta(hours=1))
            self.assertFalse(creds_mod.configure_aws_credentials("env2auth", expired, credentials_path=path))
            self.assertEqual(open(path, encoding="utf-8").read(), original)

    def test_symlinked_credentials_target_fails_closed_without_touching_target(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real")
            original = "[keep]\nk = v\n"
            with open(real, "w", encoding="utf-8") as fh:
                fh.write(original)
            link = os.path.join(d, "credentials")
            os.symlink(real, link)
            self.assertFalse(creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=link))
            self.assertEqual(open(real, encoding="utf-8").read(), original)  # target untouched
            self.assertTrue(os.path.islink(link))                            # link not replaced

    def test_symlinked_lock_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "credentials")
            original = "[env2auth]\naws_access_key_id = OLD\n"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(original)
            target = os.path.join(d, "lock-target")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write("x")
            os.symlink(target, os.path.join(d, ".aws_cluster_connect.lock"))
            self.assertFalse(creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=path))
            self.assertEqual(open(path, encoding="utf-8").read(), original)  # unchanged

    def test_non_regular_credentials_target_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "credentials")
            os.mkfifo(target)  # a FIFO is not a regular file
            self.assertFalse(creds_mod.configure_aws_credentials("env2auth", _good_creds(), credentials_path=target))

    def test_reader_fd_based_read_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real")
            _write_credentials_file(real, "env2auth",
                                    (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
            link = os.path.join(d, "credentials")
            os.symlink(real, link)
            self.assertIsNone(creds_mod._read_regular_file_text(link))
            self.assertFalse(creds_mod.credentials_are_valid("env2auth", credentials_path=link))


if __name__ == "__main__":
    unittest.main(verbosity=2)
