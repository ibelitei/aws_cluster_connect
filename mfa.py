# mfa.py
import subprocess
import logging

def get_mfa_token(service_name: str) -> str:
    """
    Retrieves an MFA token (TOTP) for the specified service using the 1Password CLI.
    Example: op item get AmazonDEV --otp
    Returns an empty string if an error occurs.
    """
    try:
        output = subprocess.check_output(['op', 'item', 'get', service_name, '--otp'])
        return output.decode().strip()
    except subprocess.CalledProcessError as exc:
        logging.error(f"[get_mfa_token] Error retrieving MFA token for '{service_name}': {exc}")
        return ""
