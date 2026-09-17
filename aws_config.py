# aws_config.py
import logging
import configparser
from typing import Optional, Dict

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
