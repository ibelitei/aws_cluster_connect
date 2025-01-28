# aws_config.py
import os
import time
import logging
import configparser
from typing import Optional, Dict

def create_or_update_profile(config: configparser.ConfigParser, profile_key: str) -> None:
    """
    Ensures the given profile_key section exists in config,
    and sets an initial or updated profile_timestamp.
    """
    if not config.has_section(profile_key):
        config.add_section(profile_key)
    config.set(profile_key, 'profile_timestamp', str(int(time.time())))

def read_profile_timestamp(config: configparser.ConfigParser, profile: str) -> int:
    """
    Reads 'profile_timestamp' from the given profile in ~/.aws/config.
    If it does not exist, this function creates/updates the profile,
    returning the new timestamp.
    """
    profile_key = f'profile {profile}' if not profile.startswith('profile ') else profile
    try:
        if not config.has_section(profile_key):
            create_or_update_profile(config, profile_key)
        return int(config.get(profile_key, 'profile_timestamp'))
    except (configparser.NoSectionError, configparser.NoOptionError) as exc:
        logging.error(f"[read_profile_timestamp] Error reading timestamp for profile '{profile}': {exc}")
        create_or_update_profile(config, profile_key)
        return int(time.time())

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
