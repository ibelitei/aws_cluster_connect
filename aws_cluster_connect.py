import subprocess
import sys
import os
import logging
import boto3
from datetime import datetime
from botocore.exceptions import ProfileNotFound
import configparser
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variable for caching credentials
credentials_cache = {}


def read_aws_config(base_profile):
    """
    Reads AWS configuration for the given base profile.
    """
    config = configparser.ConfigParser()
    config.read(os.path.expanduser('~/.aws/config'))  # Path to AWS config file

    profile_key = f'profile {base_profile}' if not base_profile.startswith('profile ') else base_profile
    try:
        return {
            'cluster_name': config.get(profile_key, 'cluster_name'),
            'region': config.get(profile_key, 'region', fallback='ap-northeast-1'),
            'mfa_serial': config.get(profile_key, 'mfa_serial', fallback=None)
        }
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        logging.error(f"Error reading from profile '{base_profile}' in AWS config: {e}")
        return None


def get_mfa_token(service_name):
    """
    Retrieves MFA token for the specified service.
    """
    try:
        return subprocess.check_output(['op', 'item', 'get', service_name, '--otp']).decode().strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error retrieving MFA token for service {service_name}: {e}")
        return None


def get_aws_session(profile):
    """
    Retrieves a boto3 session for the specified AWS profile.
    """
    try:
        return boto3.Session(profile_name=profile)
    except ProfileNotFound:
        logging.error(f"Profile '{profile}' not found.")
        return None


def get_temporary_credentials(profile, mfa_serial, mfa_token, duration=3600):
    """
    Fetches temporary credentials.
    """
    global credentials_cache
    current_time = datetime.now()

    if profile in credentials_cache and current_time < credentials_cache[profile][1]:
        return credentials_cache[profile][0]

    session = get_aws_session(profile)
    if not session:
        return None

    credentials = session.get_credentials().get_frozen_credentials()
    sts_client = boto3.client('sts', aws_access_key_id=credentials.access_key, aws_secret_access_key=credentials.secret_key)
    response = sts_client.get_session_token(DurationSeconds=duration, SerialNumber=mfa_serial, TokenCode=mfa_token)

    new_credentials = response['Credentials']
    credentials_cache[profile] = (new_credentials, new_credentials['Expiration'])
    return new_credentials


def configure_aws_credentials(profile, credentials):
    """
    Configures AWS credentials for the specified profile.
    """
    commands = [
        ['aws', 'configure', 'set', 'aws_access_key_id', credentials['AccessKeyId'], '--profile', profile],
        ['aws', 'configure', 'set', 'aws_secret_access_key', credentials['SecretAccessKey'], '--profile', profile],
        ['aws', 'configure', 'set', 'aws_session_token', credentials['SessionToken'], '--profile', profile],
        ['aws', 'configure', 'set', 'profile_timestamp', str(int(time.time())), '--profile', profile]
    ]
    for cmd in commands:
        subprocess.run(cmd)


def connect_to_cluster(cluster_name, region, profile):
    """
    Connects to the specified AWS EKS cluster.
    """
    subprocess.run(['aws', 'eks', 'update-kubeconfig', '--name', cluster_name, '--region', region, '--profile', profile])


def read_profile_timestamp(profile):
    """
    Reads the timestamp from the specified AWS profile in the config file.
    """
    config_file_path = os.path.expanduser('~/.aws/config')
    config = configparser.ConfigParser()
    config.read(config_file_path)

    profile_key = 'profile ' + profile if not profile.startswith('profile ') else profile
    try:
        return int(config.get(profile_key, 'profile_timestamp'))
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        logging.error(f"Error reading timestamp for profile '{profile}': {e}")
        return None


def main(environment):
    logging.debug(f"Starting script for environment: {environment}")

    env_name = environment.split('-')[0]
    mfa_service_name = f"Amazon{env_name.upper()}"
    user_profile = env_name.lower()
    mfa_profile = f"{user_profile}2auth"

    aws_config = read_aws_config(user_profile)
    if not aws_config:
        return

    profile_timestamp = read_profile_timestamp(mfa_profile)
    current_time = int(time.time())

    if profile_timestamp and current_time - profile_timestamp < 3600:
        logging.info("Using existing credentials.")
        connect_to_cluster(aws_config['cluster_name'], aws_config['region'], mfa_profile)
        return
    else:
        logging.info("Existing credentials are expired or not found. Generating new credentials.")

    mfa_token = get_mfa_token(mfa_service_name)
    if not mfa_token:
        return

    temp_credentials = get_temporary_credentials(user_profile, aws_config['mfa_serial'], mfa_token)
    if not temp_credentials:
        return

    configure_aws_credentials(mfa_profile, temp_credentials)
    connect_to_cluster(aws_config['cluster_name'], aws_config['region'], mfa_profile)


if __name__ == "__main__":
    main(sys.argv[1])
