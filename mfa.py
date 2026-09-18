# mfa.py
import subprocess
import logging


def get_mfa_token(service_name: str) -> str:
    """
    Retrieves an MFA token (TOTP) for the specified service using the 1Password CLI.
    Example: op item get AmazonDEV --otp

    Returns an empty string if an error occurs so the caller can fail closed.
    The TOTP value is never logged, and the raw exception (which may carry
    captured command output) is not logged either — only the non-secret service
    name and the exception type are reported.
    """
    try:
        output = subprocess.check_output(
            ['op', 'item', 'get', service_name, '--otp'],
            stderr=subprocess.DEVNULL,
        )
        return output.decode().strip()
    except (subprocess.CalledProcessError, OSError) as exc:
        logging.error(
            "[get_mfa_token] Could not retrieve MFA token for '%s' (%s).",
            service_name, type(exc).__name__,
        )
        return ""
