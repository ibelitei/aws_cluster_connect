#!/usr/bin/env python3
"""main.py

Entry point for the AWS/EKS connection script. Fail-closed by design: EVERY
operational failure exits non-zero with a concise, secret-free message and NO
Python traceback.
"""

import sys
import logging
import argparse
import configparser

from aws_config import (
    config_file_path,
    read_aws_config,
    is_role_profile,
    validate_profile_config,
    compute_target_fingerprint,
    resolve_mfa_item,
)
from credentials import (
    credentials_are_valid,
    get_temporary_credentials,
    configure_aws_credentials,
)
from mfa import get_mfa_token
from kube import connect_to_cluster
from errors import ClusterConnectError, ConfigError, EX_GENERAL

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AWS/EKS connection script with MFA and role support."
    )
    parser.add_argument("environment", help="The environment name, e.g. 'env-dev'")
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Force credential renewal even if the cache looks valid.",
    )
    return parser.parse_args()


def _run(args: argparse.Namespace) -> None:
    environment = args.environment
    force_refresh = args.force_refresh
    logging.debug("[main] environment=%s force_refresh=%s", environment, force_refresh)

    config = configparser.ConfigParser()
    config.read(config_file_path())

    env_name = environment.split("-")[0].lower()
    user_profile = env_name
    mfa_profile = f"{user_profile}2auth"

    aws_config_data = read_aws_config(config, user_profile)
    if not aws_config_data:
        raise ConfigError(f"missing required config for profile '{user_profile}'")

    role_based = is_role_profile(config, user_profile)
    role_arn = aws_config_data["role_arn"]
    source_profile = aws_config_data["source_profile"]
    mfa_serial = aws_config_data["mfa_serial"]
    region = aws_config_data["region"]
    cluster_name = aws_config_data["cluster_name"]

    # Strict configuration validation BEFORE any AWS/STS request.
    validate_profile_config(
        role_based=role_based,
        role_arn=role_arn,
        mfa_serial=mfa_serial,
        source_profile=source_profile,
    )

    # Non-secret fingerprint of the identity target; a change forces a refresh.
    expected_fingerprint = compute_target_fingerprint(
        profile=mfa_profile,
        role_arn=role_arn,
        source_profile=source_profile,
        mfa_serial=mfa_serial,
        region=region,
        cluster_name=cluster_name,
    )

    if not force_refresh and credentials_are_valid(
        config, mfa_profile, role_based, expected_fingerprint
    ):
        logging.info("[main] Using existing valid credentials for '%s'.", mfa_profile)
        connect_to_cluster(cluster_name, region, mfa_profile)
        return

    logging.info("[main] Refreshing credentials for '%s'.", mfa_profile)

    mfa_item = resolve_mfa_item(
        config,
        user_profile,
        role_based=role_based,
        source_profile=source_profile,
        env_name=env_name,
    )
    mfa_token = get_mfa_token(mfa_item)

    temp_creds = get_temporary_credentials(config, user_profile, mfa_serial, mfa_token)
    configure_aws_credentials(mfa_profile, temp_creds, fingerprint=expected_fingerprint)
    connect_to_cluster(cluster_name, region, mfa_profile)


def main() -> int:
    try:
        args = parse_args()
        _run(args)
        return 0
    except ClusterConnectError as exc:
        logging.error("[main] %s", exc)
        return exc.exit_code
    except KeyboardInterrupt:
        logging.error("[main] Interrupted.")
        return EX_GENERAL
    except Exception as exc:  # never leak a traceback for operational failures
        logging.error("[main] Unexpected failure (%s).", type(exc).__name__)
        return EX_GENERAL


if __name__ == "__main__":
    sys.exit(main())
