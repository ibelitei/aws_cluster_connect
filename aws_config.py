# aws_config.py
import os
import logging
import configparser
from typing import Optional, Dict, Tuple


def _resolve_env_path(env_var: str, default_parts: Tuple[str, ...]) -> Optional[str]:
    """Resolve an AWS file path from an environment override, or the default.

    Mirrors the AWS CLI/SDK contract: when ``env_var`` is unset the default
    home-directory path is used, and when it is set the override is honoured.
    An override that is set but blank is UNUSABLE -- we return None so the
    caller fails closed rather than silently reading/writing the default
    ``~/.aws`` file. The operator's real files are never opened here; only the
    string path is computed.
    """
    raw = os.environ.get(env_var)
    if raw is None:
        return os.path.expanduser(os.path.join(*default_parts))
    stripped = raw.strip()
    if not stripped:
        logging.error(
            "[aws_config] %s is set but empty; refusing to fall back to the default path.",
            env_var,
        )
        return None
    return os.path.expanduser(stripped)


def config_file_path() -> Optional[str]:
    """Path to the AWS config file, honouring AWS_CONFIG_FILE (None if unusable)."""
    return _resolve_env_path("AWS_CONFIG_FILE", ("~", ".aws", "config"))


def credentials_file_path() -> Optional[str]:
    """Path to the shared credentials file, honouring AWS_SHARED_CREDENTIALS_FILE
    (None if the override is set but unusable)."""
    return _resolve_env_path("AWS_SHARED_CREDENTIALS_FILE", ("~", ".aws", "credentials"))


def read_aws_config(config: configparser.ConfigParser, base_profile: str) -> Optional[Dict[str, str]]:
    """
    Reads AWS configuration for the specified profile (base_profile)
    from an already loaded ConfigParser (representing ~/.aws/config).
    Returns a dictionary with cluster_name, region, mfa_serial if found.
    """
    profile_key = f'profile {base_profile}' if not base_profile.startswith('profile ') else base_profile
    try:
        return {
            'cluster_name': config.get(profile_key, 'cluster_name'),
            'region': config.get(profile_key, 'region', fallback='ap-northeast-1'),
            'mfa_serial': config.get(profile_key, 'mfa_serial', fallback='')
        }
    except (configparser.NoSectionError, configparser.NoOptionError) as exc:
        logging.error(f"[read_aws_config] Error reading from profile '{base_profile}': {exc}")
        return None

def is_role_profile(config: configparser.ConfigParser, profile: str) -> bool:
    """
    Checks whether the given profile has a 'role_arn' in config,
    indicating a role-based (SwitchRole) profile.
    """
    profile_key = f'profile {profile}' if not profile.startswith('profile ') else profile
    return config.has_section(profile_key) and config.has_option(profile_key, 'role_arn')
