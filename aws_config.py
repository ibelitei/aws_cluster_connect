# aws_config.py
"""AWS ~/.aws/config parsing, strict validation, and the non-secret target
fingerprint used to decide whether cached credentials may be reused.

All values handled here are configuration IDENTIFIERS (profile names, ARNs,
region, cluster name). None are secrets; nothing here logs credential material.
"""

import os
import re
import hashlib
import logging
import configparser
from typing import Optional, Dict

from errors import ConfigError

# Fingerprint format version. Bump if the field set/order below changes so old
# fingerprints are treated as a mismatch (fail closed -> refresh).
FINGERPRINT_VERSION = "v1"

_ARN_ROLE = ":role/"
_ARN_MFA = ":mfa/"

# 1Password item names are non-secret identifiers; allow a conservative charset.
_SAFE_MFA_ITEM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$")


def config_file_path() -> str:
    """Resolve the AWS config file, honouring AWS_CONFIG_FILE (as the AWS CLI does)."""
    return os.path.expanduser(os.environ.get("AWS_CONFIG_FILE", "~/.aws/config"))


def credentials_file_path() -> str:
    """Resolve the shared credentials file, honouring AWS_SHARED_CREDENTIALS_FILE."""
    return os.path.expanduser(
        os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")
    )


def profile_key(profile: str) -> str:
    """The section name for a profile in ~/.aws/config ('profile <name>')."""
    return profile if profile.startswith("profile ") else f"profile {profile}"


def read_aws_config(config: configparser.ConfigParser, base_profile: str) -> Optional[Dict[str, str]]:
    """Read cluster_name/region/mfa_serial/role_arn/source_profile for a profile.

    Returns None (never a traceback) when the section or a required field is
    missing; the caller fails closed on None.
    """
    key = profile_key(base_profile)
    if not config.has_section(key):
        logging.error("[read_aws_config] No config section for profile '%s'.", base_profile)
        return None
    try:
        cluster_name = config.get(key, "cluster_name")
    except (configparser.NoSectionError, configparser.NoOptionError):
        logging.error("[read_aws_config] Profile '%s' is missing 'cluster_name'.", base_profile)
        return None
    return {
        "cluster_name": cluster_name,
        "region": config.get(key, "region", fallback="ap-northeast-1"),
        "mfa_serial": config.get(key, "mfa_serial", fallback=""),
        "role_arn": config.get(key, "role_arn", fallback=""),
        "source_profile": config.get(key, "source_profile", fallback=""),
    }


def is_role_profile(config: configparser.ConfigParser, profile: str) -> bool:
    """True when the profile declares a role_arn (SwitchRole profile)."""
    key = profile_key(profile)
    return config.has_section(key) and config.has_option(key, "role_arn")


def validate_profile_config(
    *,
    role_based: bool,
    role_arn: str,
    mfa_serial: str,
    source_profile: str,
) -> None:
    """Strictly validate identity configuration BEFORE any AWS/STS request.

    Raises ConfigError (concise, no secrets) on any problem so ``main`` exits
    non-zero without a traceback and without contacting AWS.
    """
    mfa_serial = (mfa_serial or "").strip()
    role_arn = (role_arn or "").strip()
    source_profile = (source_profile or "").strip()

    # mfa_serial is always required and must be an MFA-device ARN (never a role ARN).
    if not mfa_serial:
        raise ConfigError("mfa_serial is required but missing")
    if _ARN_ROLE in mfa_serial:
        raise ConfigError("mfa_serial looks like a role ARN (contains ':role/')")
    if _ARN_MFA not in mfa_serial:
        raise ConfigError("mfa_serial must be an MFA-device ARN containing ':mfa/'")

    if role_based:
        if not role_arn:
            raise ConfigError("role_arn is required for a role-based profile")
        if _ARN_MFA in role_arn:
            raise ConfigError("role_arn looks like an MFA-device ARN (contains ':mfa/')")
        if _ARN_ROLE not in role_arn:
            raise ConfigError("role_arn must be an IAM role ARN containing ':role/'")
        if role_arn == mfa_serial:
            raise ConfigError("role_arn and mfa_serial must not be equal")
        if not source_profile:
            raise ConfigError("source_profile is required for a role-based profile")


def compute_target_fingerprint(
    *,
    profile: str,
    role_arn: str,
    source_profile: str,
    mfa_serial: str,
    region: str,
    cluster_name: str,
) -> str:
    """A non-secret SHA-256 fingerprint of the identity target.

    If ANY of these change (e.g. the role ARN moves from legendsprod to
    legendbetprod), the fingerprint changes and cached credentials for the old
    target are rejected. All inputs are non-secret identifiers.
    """
    parts = [
        FINGERPRINT_VERSION,
        profile or "",
        role_arn or "",
        source_profile or "",
        mfa_serial or "",
        region or "",
        cluster_name or "",
    ]
    canonical = "\x1f".join(parts)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def resolve_mfa_item(
    config: configparser.ConfigParser,
    user_profile: str,
    *,
    role_based: bool,
    source_profile: str,
    env_name: str,
) -> str:
    """Resolve the 1Password item name for the MFA OTP.

    Precedence: an explicit, validated ``mfa_item`` config key, else the
    backward-compatible derivation ``Amazon<SOURCE_PROFILE_UPPER>`` for
    role-based profiles (e.g. AmazonSHARED) or ``Amazon<ENV_UPPER>`` otherwise.
    """
    key = profile_key(user_profile)
    explicit = ""
    if config.has_section(key) and config.has_option(key, "mfa_item"):
        explicit = (config.get(key, "mfa_item") or "").strip()
    if explicit:
        if not _SAFE_MFA_ITEM.match(explicit):
            raise ConfigError("mfa_item contains unsupported characters")
        return explicit
    if role_based and source_profile:
        return f"Amazon{source_profile.upper()}"
    return f"Amazon{env_name.upper()}"
