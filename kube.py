# kube.py
"""EKS kubeconfig update. A FAILED update must never be reported as success."""

import subprocess
import logging

from errors import KubeError


def connect_to_cluster(cluster_name: str, region: str, profile: str) -> None:
    """Run 'aws eks update-kubeconfig' and REQUIRE a zero exit status.

    Raises KubeError (concise, no traceback, no raw provider stderr) when the
    update fails, so the caller exits non-zero. Never claims success on failure.
    """
    logging.info(
        "[connect_to_cluster] Updating kubeconfig for cluster '%s' via profile '%s'.",
        cluster_name, profile,
    )
    try:
        proc = subprocess.run(
            [
                "aws", "eks", "update-kubeconfig",
                "--name", cluster_name,
                "--region", region,
                "--profile", profile,
            ],
            capture_output=True,
        )
    except FileNotFoundError:
        raise KubeError("the 'aws' CLI was not found on PATH") from None
    except OSError as exc:
        raise KubeError(f"could not run 'aws eks update-kubeconfig' ({type(exc).__name__})") from None

    if proc.returncode != 0:
        # Do NOT surface raw provider stderr; report only that it failed + the code.
        raise KubeError(
            f"'aws eks update-kubeconfig' failed for cluster '{cluster_name}' (exit {proc.returncode})"
        )
    logging.info("[connect_to_cluster] kubeconfig updated for cluster '%s'.", cluster_name)
