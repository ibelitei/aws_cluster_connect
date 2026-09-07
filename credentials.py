# credentials.py
"""Credential validity, temporary-credential acquisition, and secure writing.

Fail-closed cache model: cached credentials are reused ONLY when every check
passes -- complete credential fields, a matching non-secret target fingerprint,
a present and future expiration, a well-formed timestamp, and the duration
bound. Any missing/malformed/mismatched value refreshes. Nothing here logs
credential material, tokens, or raw provider stderr.
"""

import os
import time
import configparser
from datetime import datetime, timezone
from typing import Dict, Optional

from settings import ROLE_MAX_DURATION, USER_MAX_DURATION
from aws_config import profile_key, credentials_file_path
from errors import StsError, CredentialWriteError, ConfigError

_REQUIRED_CRED_FIELDS = ("aws_access_key_id", "aws_secret_access_key", "aws_session_token")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_expiration(raw: str) -> Optional[datetime]:
    """Parse a stored ISO-8601 expiration into a tz-aware datetime, or None."""
    if not raw:
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _credentials_complete(profile: str) -> bool:
    """True only when the shared credentials file has all three temp fields set."""
    path = credentials_file_path()
    if not os.path.isfile(path):
        return False
    parser = configparser.ConfigParser()
    try:
        parser.read(path)
    except configparser.Error:
        return False
    if not parser.has_section(profile):
        return False
    for field in _REQUIRED_CRED_FIELDS:
        value = parser.get(profile, field, fallback="")
        if not value or not value.strip():
            return False
    return True


def credentials_are_valid(
    config: configparser.ConfigParser,
    profile: str,
    is_role_based: bool,
    expected_fingerprint: str,
) -> bool:
    """Fail-closed validity for cached credentials of ``profile``.

    Returns True only when ALL hold:
      * the config section exists and 'profile_timestamp' is present + numeric;
      * 'credential_fingerprint' is present and equals ``expected_fingerprint``;
      * 'credential_expiration' is present, parseable, and in the future;
      * the shared credentials file has complete temp credential fields;
      * elapsed time is within the role/user duration bound.
    A missing timestamp/profile is INVALID (never treated as newly valid).
    """
    key = profile_key(profile)
    if not config.has_section(key):
        return False

    ts_raw = config.get(key, "profile_timestamp", fallback=None)
    if ts_raw is None:
        return False
    try:
        timestamp = int(str(ts_raw).strip())
    except (TypeError, ValueError):
        return False

    fingerprint = config.get(key, "credential_fingerprint", fallback=None)
    if not fingerprint or fingerprint != expected_fingerprint:
        return False

    expiration = _parse_expiration(config.get(key, "credential_expiration", fallback=""))
    if expiration is None or _now_utc() >= expiration:
        return False

    if not _credentials_complete(profile):
        return False

    max_valid_duration = ROLE_MAX_DURATION if is_role_based else USER_MAX_DURATION
    if int(time.time()) - timestamp >= max_valid_duration:
        return False

    return True


def _expiration_iso(credentials: Dict[str, object]) -> str:
    """Normalise a credentials Expiration (datetime or str) to ISO-8601 UTC."""
    expiration = credentials.get("Expiration")
    if isinstance(expiration, datetime):
        dt = expiration if expiration.tzinfo else expiration.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    parsed = _parse_expiration(str(expiration)) if expiration is not None else None
    if parsed is None:
        raise StsError("STS response is missing a usable credential expiration")
    return parsed.isoformat()


def get_temporary_credentials(
    config: configparser.ConfigParser,
    profile: str,
    mfa_serial: str,
    mfa_token: str,
    duration: int = USER_MAX_DURATION,
) -> Dict[str, object]:
    """Fetch temporary credentials via STS (assume_role or get_session_token).

    Any botocore ClientError (e.g. AccessDenied, invalid MFA) is converted to a
    concise StsError carrying only the AWS error CODE -- never a traceback, keys,
    the OTP, or raw stderr. Returns a dict with AccessKeyId/SecretAccessKey/
    SessionToken/Expiration.
    """
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError, ProfileNotFound

    key = profile_key(profile)
    is_role_based = config.has_section(key) and config.has_option(key, "role_arn")

    try:
        if is_role_based:
            role_arn = config.get(key, "role_arn")
            source_profile = config.get(key, "source_profile")
            role_duration = min(duration, ROLE_MAX_DURATION)

            source_session = boto3.Session(profile_name=source_profile)
            source_creds = source_session.get_credentials()
            if source_creds is None:
                raise StsError("source profile has no resolvable credentials")
            frozen = source_creds.get_frozen_credentials()
            sts_client = boto3.client(
                "sts",
                aws_access_key_id=frozen.access_key,
                aws_secret_access_key=frozen.secret_key,
                aws_session_token=frozen.token,
            )
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"{profile}-session",
                DurationSeconds=role_duration,
                SerialNumber=mfa_serial,
                TokenCode=mfa_token,
            )
        else:
            session = boto3.Session(profile_name=profile)
            base_creds = session.get_credentials()
            if base_creds is None:
                raise StsError("profile has no resolvable base credentials")
            frozen = base_creds.get_frozen_credentials()
            sts_client = boto3.client(
                "sts",
                aws_access_key_id=frozen.access_key,
                aws_secret_access_key=frozen.secret_key,
            )
            response = sts_client.get_session_token(
                DurationSeconds=duration,
                SerialNumber=mfa_serial,
                TokenCode=mfa_token,
            )
    except ProfileNotFound as exc:
        raise ConfigError(f"AWS profile not found: {exc.args and exc.args[0] or 'unknown'}") from None
    except ClientError as exc:
        code = "Unknown"
        try:
            code = exc.response["Error"]["Code"]
        except (AttributeError, KeyError, TypeError):
            pass
        raise StsError(f"STS request failed ({code})") from None
    except BotoCoreError as exc:
        raise StsError(f"STS request failed ({type(exc).__name__})") from None

    credentials = (response or {}).get("Credentials")
    if not isinstance(credentials, dict):
        raise StsError("STS response contained no Credentials")
    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"):
        if not credentials.get(field):
            raise StsError("STS response was missing required credential fields")
    return credentials


def configure_aws_credentials(
    profile: str,
    credentials: Dict[str, object],
    *,
    fingerprint: str,
) -> None:
    """Persist temporary credentials + non-secret validity metadata.

    Writes the three credential fields to the shared credentials file and, into
    the config profile, the target fingerprint, the credential expiration, and a
    fresh timestamp -- all via ``aws configure set`` with a fixed argument
    vector. Any non-zero write fails closed with CredentialWriteError (no
    traceback, no secret material logged).
    """
    import subprocess

    expiration_iso = _expiration_iso(credentials)
    secret_commands = [
        ["aws", "configure", "set", "aws_access_key_id", str(credentials["AccessKeyId"]), "--profile", profile],
        ["aws", "configure", "set", "aws_secret_access_key", str(credentials["SecretAccessKey"]), "--profile", profile],
        ["aws", "configure", "set", "aws_session_token", str(credentials["SessionToken"]), "--profile", profile],
    ]
    meta_commands = [
        ["aws", "configure", "set", "profile_timestamp", str(int(time.time())), "--profile", profile],
        ["aws", "configure", "set", "credential_fingerprint", fingerprint, "--profile", profile],
        ["aws", "configure", "set", "credential_expiration", expiration_iso, "--profile", profile],
    ]

    # Describe each command WITHOUT its argument values so secrets never reach logs.
    labels = [
        "aws_access_key_id", "aws_secret_access_key", "aws_session_token",
        "profile_timestamp", "credential_fingerprint", "credential_expiration",
    ]
    for label, cmd in zip(labels, secret_commands + meta_commands):
        proc = subprocess.run(cmd, capture_output=True)
        if proc.returncode != 0:
            raise CredentialWriteError(
                f"failed to write '{label}' for profile '{profile}' (exit {proc.returncode})"
            )
