# kube.py
import subprocess
import logging

def connect_to_cluster(cluster_name: str, region: str, profile: str) -> None:
    """
    Calls 'aws eks update-kubeconfig' to set or update the local kubeconfig
    for the specified EKS cluster, using the given AWS profile.
    """
    logging.info(f"[connect_to_cluster] Updating kubeconfig for cluster '{cluster_name}' using profile '{profile}'.")
    subprocess.run([
        'aws', 'eks', 'update-kubeconfig',
        '--name', cluster_name,
        '--region', region,
        '--profile', profile
    ])
