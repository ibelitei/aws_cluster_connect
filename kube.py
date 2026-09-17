# kube.py
import subprocess
import logging


def connect_to_cluster(cluster_name: str, region: str, profile: str) -> bool:
    """
    Calls 'aws eks update-kubeconfig' to set or update the local kubeconfig
    for the specified EKS cluster, using the given AWS profile.

    Returns True only if 'aws eks update-kubeconfig' exits successfully; returns
    False on a non-zero exit or if 'aws' cannot be run, so the caller can fail
    closed. cluster_name/region/profile are non-secret identifiers; no secret
    material is passed to, or logged by, this function.
    """
    logging.info(
        "[connect_to_cluster] Updating kubeconfig for cluster '%s' using profile '%s'.",
        cluster_name, profile,
    )
    try:
        result = subprocess.run([
            'aws', 'eks', 'update-kubeconfig',
            '--name', cluster_name,
            '--region', region,
            '--profile', profile,
        ])
    except OSError as exc:
        logging.error("[connect_to_cluster] Could not run 'aws' (%s).", type(exc).__name__)
        return False

    if result.returncode != 0:
        logging.error(
            "[connect_to_cluster] 'aws eks update-kubeconfig' failed (exit %s).",
            result.returncode,
        )
        return False
    return True
