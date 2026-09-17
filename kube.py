# kube.py
import os
import stat
import subprocess
import logging
from typing import List, Optional, Tuple

from settings import UPDATE_KUBECONFIG_TIMEOUT_SECONDS

# Sentinel so callers/tests can pass an explicit kubeconfig value (including None)
# distinctly from "resolve it from the environment".
_ENV_DEFAULT = object()


def _resolve_kubeconfig_target(raw: Optional[str]) -> Tuple[Optional[List[str]], Optional[str]]:
    """Resolve the isolated-kubeconfig write target from the DSF ``KUBECONFIG`` contract.

    ``raw`` is the value of the ``KUBECONFIG`` environment variable (or None when unset).
    DSF supplies exactly ONE isolated session file via ``KUBECONFIG``; we honour that same
    variable rather than inventing a competing mechanism.

    Returns ``(extra_argv, None)`` on success, where ``extra_argv`` is:
      * ``[]``  -> LEGACY standalone behaviour: ``KUBECONFIG`` is unset, so
        ``aws eks update-kubeconfig`` writes to its own default (global ~/.kube/config);
      * ``["--kubeconfig", <path>]`` -> a single, validated, safe isolated target.
    Returns ``(None, reason)`` when ``KUBECONFIG`` is SET but UNUSABLE (empty, multi-path,
    a symlink, a non-regular existing file, or a missing parent directory). The caller then
    fails closed BEFORE invoking AWS and NEVER falls back to the global kubeconfig. ``reason``
    is a short, path-free string safe to log.
    """
    if raw is None:
        return [], None                                   # legacy: no isolated target supplied
    if raw.strip() == "":
        return None, "KUBECONFIG is set but empty"
    if os.pathsep in raw:
        # Multiple entries: we will not guess which one is the isolated session file.
        return None, "KUBECONFIG contains multiple path entries"
    path = os.path.expanduser(raw)
    try:
        link_stat = os.lstat(path)
    except FileNotFoundError:
        link_stat = None                                  # may be created by update-kubeconfig
    except OSError:
        return None, "KUBECONFIG target could not be inspected"
    if link_stat is not None:
        if stat.S_ISLNK(link_stat.st_mode):
            return None, "KUBECONFIG target is a symlink"
        if not stat.S_ISREG(link_stat.st_mode):
            return None, "KUBECONFIG target is not a regular file"
    parent = os.path.dirname(path) or "."
    if not os.path.isdir(parent):
        return None, "KUBECONFIG parent directory does not exist"
    return ["--kubeconfig", path], None


def connect_to_cluster(cluster_name: str, region: str, profile: str, kubeconfig=_ENV_DEFAULT) -> bool:
    """
    Calls 'aws eks update-kubeconfig' to set or update the local kubeconfig for the
    specified EKS cluster, using the given AWS profile.

    Target selection (backward compatible):
      * No isolated target (``KUBECONFIG`` unset) -> LEGACY behaviour: the AWS CLI writes
        to its own default (global ~/.kube/config).
      * One explicit isolated target via ``KUBECONFIG`` -> the write is pinned with
        ``--kubeconfig <target>``; the global kubeconfig is never touched.
      * ``KUBECONFIG`` set but unusable (empty / multi-path / symlink / non-regular /
        missing parent dir) -> FAIL CLOSED before invoking AWS; never silently fall back
        to the global kubeconfig.
    ``kubeconfig`` defaults to the ``KUBECONFIG`` environment variable; tests pass an
    explicit value.

    The subprocess is shell-free (fixed argv) and time-boxed
    (``UPDATE_KUBECONFIG_TIMEOUT_SECONDS``); its stdout/stderr are captured and never
    surfaced, so no path, endpoint, account, or command output leaks. Returns True only on
    a zero exit; returns False (fail closed) on validation failure, timeout, a non-zero exit,
    or if 'aws' cannot be run. cluster_name/region/profile are non-secret identifiers.
    """
    raw = os.environ.get("KUBECONFIG") if kubeconfig is _ENV_DEFAULT else kubeconfig
    extra_argv, reason = _resolve_kubeconfig_target(raw)
    if reason is not None:
        # Isolated target supplied but unusable: do NOT invoke AWS and do NOT touch the
        # global kubeconfig. (reason is path-free.)
        logging.error("[connect_to_cluster] Refusing to update kubeconfig: %s.", reason)
        return False

    logging.info(
        "[connect_to_cluster] Updating kubeconfig for cluster '%s' using profile '%s'%s.",
        cluster_name, profile, " (isolated target)" if extra_argv else "",
    )
    argv = [
        'aws', 'eks', 'update-kubeconfig',
        '--name', cluster_name,
        '--region', region,
        '--profile', profile,
    ] + extra_argv
    try:
        result = subprocess.run(
            argv,
            capture_output=True,                    # redact: never surface AWS command output
            timeout=UPDATE_KUBECONFIG_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        logging.error(
            "[connect_to_cluster] 'aws eks update-kubeconfig' timed out after %ss.",
            UPDATE_KUBECONFIG_TIMEOUT_SECONDS,
        )
        return False
    except OSError as exc:
        logging.error("[connect_to_cluster] Could not run 'aws' (%s).", type(exc).__name__)
        return False

    if result.returncode != 0:
        # Report only the exit code; never the captured stdout/stderr (may carry paths/endpoints).
        logging.error(
            "[connect_to_cluster] 'aws eks update-kubeconfig' failed (exit %s).",
            result.returncode,
        )
        return False
    return True
