# credentials.py
import time
import logging
from datetime import datetime
from typing import Dict
import boto3
import configparser
import os

from botocore.exceptions import ProfileNotFound
from aws_config import read_profile_timestamp, create_or_update_profile
from settings import ROLE_MAX_DURATION, USER_MAX_DURATION

# In-memory cache for temporary credentials
credentials_cache: Dict[str, tuple[Dict[str, str], datetime]] = {}

def get_aws_session(profile: str):
    """
    Attempts to create a boto3 Session for a given AWS CLI profile.
    Returns None if the profile is not found.
    """
    try:
        return boto3.Session(profile_name=profile)
    except ProfileNotFound:
        logging.error(f"[get_aws_session] Profile '{profile}' not found.")
        return None

def credentials_are_valid(
        config: configparser.ConfigParser,
        profile: str,
        is_role_based: bool
) -> bool:
    """
    Determines if the credentials for 'profile' are still valid
    based on a custom maximum duration:
      - Roles: 1 hour (ROLE_MAX_DURATION)
      - IAM user: 36 hours (USER_MAX_DURATION)
    We read the 'profile_timestamp' from the config, compare with current time.
    """
    max_valid_duration = ROLE_MAX_DURATION if is_role_based else USER_MAX_DURATION
    profile_timestamp = read_profile_timestamp(config, profile)
    current_time = int(time.time())
    elapsed = current_time - profile_timestamp

    logging.debug(
        f"[credentials_are_valid] Profile '{profile}' - Elapsed: {elapsed}s / Allowed: {max_valid_duration}s"
    )

    return elapsed < max_valid_duration

def get_temporary_credentials(
        config: configparser.ConfigParser,
        profile: str,
        mfa_serial: str,
        mfa_token: str,
        duration: int = USER_MAX_DURATION
) -> Dict[str, str]:
    """
    Fetches temporary AWS credentials.
      - If the profile is role-based (has role_arn), calls sts.assume_role.
      - Otherwise, calls sts.get_session_token (classic IAM user + MFA).
    'duration' can be up to 36 hours, but for roles we limit to ROLE_MAX_DURATION.
    Returns a dict of new credentials: {AccessKeyId, SecretAccessKey, SessionToken, Expiration}.
    """
    now = datetime.now()

    # Return cached credentials if still valid in memory
    if profile in credentials_cache and now < credentials_cache[profile][1]:
        logging.debug(f"[get_temporary_credentials] Using cached credentials for '{profile}'.")
        return credentials_cache[profile][0]

    profile_key = f'profile {profile}' if not profile.startswith('profile ') else profile
    is_role_based = config.has_section(profile_key) and config.has_option(profile_key, 'role_arn')

    if is_role_based:
        logging.info(f"[get_temporary_credentials] Detected role_arn in profile '{profile}'. Using assume_role with MFA.")
        role_arn = config.get(profile_key, 'role_arn')
        source_profile = config.get(profile_key, 'source_profile')

        # Limit role duration
        role_duration = min(duration, ROLE_MAX_DURATION)

        source_session = boto3.Session(profile_name=source_profile)
        source_creds = source_session.get_credentials().get_frozen_credentials()

        sts_client = boto3.client(
            'sts',
            aws_access_key_id=source_creds.access_key,
            aws_secret_access_key=source_creds.secret_key,
            aws_session_token=source_creds.token
        )
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"{profile}-session",
            DurationSeconds=role_duration,
            SerialNumber=mfa_serial,
            TokenCode=mfa_token
        )
        new_credentials = response['Credentials']
        credentials_cache[profile] = (new_credentials, new_credentials['Expiration'])
        return new_credentials
    else:
        # Classic IAM user
        session = get_aws_session(profile)
        if not session:
            logging.error(f"[get_temporary_credentials] Could not create session for profile '{profile}'.")
            return {}

        base_creds = session.get_credentials().get_frozen_credentials()
        sts_client = boto3.client(
            'sts',
            aws_access_key_id=base_creds.access_key,
            aws_secret_access_key=base_creds.secret_key
        )
        response = sts_client.get_session_token(
            DurationSeconds=duration,
            SerialNumber=mfa_serial,
            TokenCode=mfa_token
        )
        new_credentials = response['Credentials']
        credentials_cache[profile] = (new_credentials, new_credentials['Expiration'])
        return new_credentials

def configure_aws_credentials(profile: str, credentials: Dict[str, str]) -> None:
    """
    Writes the temporary credentials into the specified AWS CLI profile
    in ~/.aws/credentials. Also updates 'profile_timestamp' for custom validity checks.
    """
    import subprocess

    logging.debug(f"[configure_aws_credentials] Writing creds to profile '{profile}'.")
    commands = [
        ['aws', 'configure', 'set', 'aws_access_key_id', credentials['AccessKeyId'], '--profile', profile],
        ['aws', 'configure', 'set', 'aws_secret_access_key', credentials['SecretAccessKey'], '--profile', profile],
        ['aws', 'configure', 'set', 'aws_session_token', credentials['SessionToken'], '--profile', profile],
        ['aws', 'configure', 'set', 'profile_timestamp', str(int(time.time())), '--profile', profile]
    ]
    for cmd in commands:
        subprocess.run(cmd)
