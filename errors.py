"""Typed operational errors and fixed process exit codes.

Every failure the script can encounter maps to one of these exceptions; ``main``
catches them and exits with the corresponding code WITHOUT printing a traceback.
Messages are intentionally concise and MUST NOT contain secrets (keys, tokens,
OTPs, credential contents, or raw provider stderr).
"""

EX_OK = 0
EX_GENERAL = 1
EX_CONFIG = 2        # missing/malformed/invalid configuration
EX_MFA = 3           # missing / empty MFA (OTP) token
EX_STS = 4           # STS ClientError (AccessDenied, invalid MFA, ...)
EX_CRED_WRITE = 5    # failure writing temporary credentials
EX_KUBE = 6          # aws eks update-kubeconfig returned non-zero


class ClusterConnectError(Exception):
    """Base class for all operational failures; carries a fixed exit code."""

    exit_code = EX_GENERAL


class ConfigError(ClusterConnectError):
    exit_code = EX_CONFIG


class MfaError(ClusterConnectError):
    exit_code = EX_MFA


class StsError(ClusterConnectError):
    exit_code = EX_STS


class CredentialWriteError(ClusterConnectError):
    exit_code = EX_CRED_WRITE


class KubeError(ClusterConnectError):
    exit_code = EX_KUBE
