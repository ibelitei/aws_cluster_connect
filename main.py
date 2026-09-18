#!/usr/bin/env python3
"""
main.py

Main entry point for the AWS/EKS connection script.
Incorporates argparse, a shared config object,
and other best-practices improvements.

Exit contract:
  0  -> the complete intended flow succeeded (credentials in place AND
        kubeconfig updated for the target cluster).
  1  -> any expected failure (missing config, MFA/STS/credential-write/
        kubeconfig-update failure). A credential-write failure prevents the
        EKS connection attempt. Error output never contains secrets, MFA
        values, session tokens, or the argv carrying them.
"""

import sys
import logging
import configparser
import argparse

from aws_config import (
    read_aws_config,
    is_role_profile,
    config_file_path,
    credentials_file_path,
)
from credentials import (
    credentials_are_valid,
    get_temporary_credentials,
    configure_aws_credentials,
)
from mfa import get_mfa_token
from kube import connect_to_cluster

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Stable process exit statuses.
EXIT_OK = 0
EXIT_FAILURE = 1

def parse_args() -> argparse.Namespace:
    """
    Parses command-line arguments using argparse.
    Example usage:
      python main.py --force-refresh env-dev
    """
    parser = argparse.ArgumentParser(
        description="AWS/EKS connection script with MFA and role support."
    )
    parser.add_argument(
        "environment",
        help="The environment name, e.g. 'env-dev'"
    )
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Force credentials renewal even if not expired."
    )
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    environment = args.environment
    force_refresh = args.force_refresh

    logging.debug(f"[main] Starting script for environment: {environment}, force_refresh={force_refresh}")

    # Resolve AWS file locations up front, honouring AWS_CONFIG_FILE and
    # AWS_SHARED_CREDENTIALS_FILE (as the AWS CLI/SDK do). An override that is
    # set but unusable fails closed HERE rather than silently using the default
    # ~/.aws paths or burning an MFA/STS call before the write fails.
    cfg_path = config_file_path()
    creds_path = credentials_file_path()
    if cfg_path is None or creds_path is None:
        logging.error(
            "[main] AWS_CONFIG_FILE or AWS_SHARED_CREDENTIALS_FILE is set but unusable; aborting."
        )
        return EXIT_FAILURE

    # Load the AWS config once, pass around as needed
    config = configparser.ConfigParser()
    config.read(cfg_path)

    # Derive the base environment name / profile
    env_name = environment.split('-')[0].lower()
    user_profile = env_name
    mfa_profile = f"{user_profile}2auth"

    # 1) Read AWS config for the user profile
    aws_config_data = read_aws_config(config, user_profile)
    if not aws_config_data:
        logging.error("[main] Could not find required config fields for '%s'.", user_profile)
        return EXIT_FAILURE

    # 2) Check if this is a role-based or user-based profile
    role_based = is_role_profile(config, user_profile)

    # If not forcing refresh, reuse only when the target profile's persisted REAL
    # STS expiration (in the shared credentials file) is still valid with margin.
    # This never reads or writes ~/.aws/config for the reuse decision.
    if not force_refresh and credentials_are_valid(mfa_profile):
        logging.info("[main] Using existing credentials.")
        if not connect_to_cluster(aws_config_data['cluster_name'], aws_config_data['region'], mfa_profile):
            logging.error("[main] Failed to update kubeconfig with existing credentials.")
            return EXIT_FAILURE
        return EXIT_OK

    logging.info("[main] Credentials are expired or force-refresh requested. Generating new credentials...")

    # 3) Determine the 1Password item name
    profile_key = f'profile {user_profile}' if not user_profile.startswith('profile ') else user_profile
    if role_based and config.has_section(profile_key) and config.has_option(profile_key, 'source_profile'):
        source_profile = config.get(profile_key, 'source_profile')
        mfa_service_name = f"Amazon{source_profile.upper()}"
    else:
        mfa_service_name = f"Amazon{env_name.upper()}"

    # 4) Retrieve the MFA token
    mfa_token = get_mfa_token(mfa_service_name)
    if not mfa_token:
        logging.error("[main] No MFA token retrieved. Aborting.")
        return EXIT_FAILURE

    # 5) Get temporary credentials
    temp_creds = get_temporary_credentials(
        config,
        user_profile,
        aws_config_data['mfa_serial'],
        mfa_token
    )
    if not temp_creds:
        logging.error("[main] Failed to obtain temporary credentials.")
        return EXIT_FAILURE

    # 6) Store credentials in mfa_profile. A write failure MUST prevent the
    #    connection attempt (do not connect with incomplete credentials).
    if not configure_aws_credentials(mfa_profile, temp_creds):
        logging.error("[main] Failed to store temporary credentials; not connecting.")
        return EXIT_FAILURE

    # 7) Connect to the EKS cluster
    if not connect_to_cluster(aws_config_data['cluster_name'], aws_config_data['region'], mfa_profile):
        logging.error("[main] Failed to update kubeconfig.")
        return EXIT_FAILURE

    return EXIT_OK

if __name__ == "__main__":
    sys.exit(main())
