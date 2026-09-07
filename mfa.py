# mfa.py
"""1Password OTP retrieval via a fixed argument vector (never a shell)."""

import subprocess

from errors import MfaError


def get_mfa_token(service_name: str) -> str:
    """Return a one-time MFA code for the given 1Password item.

    Invokes ``op item get <item> --otp`` with a fixed argv. On any failure raises
    MfaError with a concise message -- it never logs the OTP, the item's secret
    contents, or the raw ``op`` stderr.
    """
    try:
        proc = subprocess.run(
            ["op", "item", "get", service_name, "--otp"],
            capture_output=True,
        )
    except FileNotFoundError:
        raise MfaError("the 1Password CLI ('op') was not found on PATH") from None
    except OSError as exc:
        raise MfaError(f"could not run the 1Password CLI ({type(exc).__name__})") from None

    if proc.returncode != 0:
        # Never include proc.stderr (raw provider output) in the message.
        raise MfaError(f"1Password returned no OTP for the configured MFA item (exit {proc.returncode})")

    token = proc.stdout.decode("utf-8", "replace").strip()
    if not token:
        raise MfaError("1Password returned an empty OTP for the configured MFA item")
    return token
