# credentials.py
import os
import re
import stat
import logging
import tempfile
import configparser
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional
import boto3

from botocore.exceptions import ProfileNotFound, BotoCoreError
from settings import ROLE_MAX_DURATION, USER_MAX_DURATION

try:
    import fcntl  # POSIX advisory locking (macOS/Linux)
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None

# Project-specific metadata key recording the REAL STS expiration alongside the
# temporary credentials in the shared credentials file. It is intentionally NOT
# an AWS-standard key, so unrelated tooling ignores it and we never overload a
# standard option. Serialized as an unambiguous UTC ISO-8601 string.
EXPIRATION_METADATA_KEY = "aws_cluster_connect_expiration"

# Reuse safety margin: refuse to reuse credentials that expire within this many
# seconds, so an in-flight operation never races the real expiration.
REUSE_SAFETY_MARGIN_SECONDS = 60

# Fixed lock-file name kept in the SAME directory as the credentials file.
_LOCK_FILENAME = ".aws_cluster_connect.lock"

# Secret string fields a well-formed STS 'Credentials' mapping must carry.
_REQUIRED_SECRET_KEYS = ("AccessKeyId", "SecretAccessKey", "SessionToken")

# Conservative profile-name allowlist: rejects control characters and INI
# section-injection characters ('[' / ']' / newlines) by construction, while
# accepting the derived '<env>2auth' names.
_PROFILE_NAME_RE = re.compile(r"\A[A-Za-z0-9._-]+\Z")


def _default_credentials_path() -> str:
    """Standard shared credentials path, resolved only at call time."""
    return os.path.expanduser(os.path.join("~", ".aws", "credentials"))


def _is_aware(value) -> bool:
    """True only for a timezone-AWARE datetime (naive datetimes return False)."""
    return isinstance(value, datetime) and value.tzinfo is not None \
        and value.tzinfo.utcoffset(value) is not None


def _read_regular_file_text(path: str) -> Optional[str]:
    """
    Read `path` as text WITHOUT following a symlink and only if it is a regular
    file. TOCTOU-safe: opens with O_NOFOLLOW, fstat-verifies S_ISREG on the SAME
    descriptor, and reads through that verified descriptor. Returns None for a
    missing file, a symlink, a non-regular file, a platform without O_NOFOLLOW,
    or any OS error — it never follows a symlink and never raises.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # cannot guarantee no-symlink-follow -> fail closed
        return None
    try:
        fd = os.open(path, os.O_RDONLY | nofollow)
    except OSError:
        # ELOOP (symlinked final component), ENOENT, EACCES, ...
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
            return handle.read()
    except OSError:
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _open_locked(directory: str) -> Optional[int]:
    """
    Open and exclusively flock a same-directory lock file, refusing to follow a
    symlink or to lock a non-regular target. Returns the locked file descriptor,
    or None on any unsafe/unsupported/failed condition (caller fails closed).
    """
    if fcntl is None:  # pragma: no cover - non-POSIX
        return None
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    lock_path = os.path.join(directory, _LOCK_FILENAME)
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | nofollow, 0o600)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            return None
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        return None


def _close_locked(fd: int) -> None:
    if fd is None:
        return
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def _valid_sts_credentials(response) -> Dict[str, str]:
    """
    Return the 'Credentials' mapping from an STS response ONLY if it is
    semantically usable; otherwise return {}. Validity requires:
      * the response and its 'Credentials' are dict mappings;
      * AccessKeyId / SecretAccessKey / SessionToken are non-empty strings;
      * 'Expiration' is a timezone-AWARE datetime that is still in the future
        (compared against the current UTC time).
    Never logs or returns any part of the raw response payload.
    """
    if not isinstance(response, dict):
        return {}
    creds = response.get("Credentials")
    if not isinstance(creds, dict):
        return {}
    for key in _REQUIRED_SECRET_KEYS:
        value = creds.get(key)
        if not isinstance(value, str) or not value:
            return {}
    expiration = creds.get("Expiration")
    if not _is_aware(expiration):
        return {}
    if expiration <= datetime.now(timezone.utc):
        return {}
    return creds


def _valid_profile_name(profile) -> bool:
    return isinstance(profile, str) and bool(_PROFILE_NAME_RE.match(profile))


def get_aws_session(profile: str):
    """
    Attempts to create a boto3 Session for a given AWS CLI profile.
    Returns None on an expected configuration failure (unknown profile or a
    malformed AWS config), so the caller can fail closed. Only expected botocore
    configuration errors are handled here — programmer errors are NOT masked.
    """
    try:
        return boto3.Session(profile_name=profile)
    except (ProfileNotFound, BotoCoreError) as exc:
        logging.error(
            "[get_aws_session] Could not create session for profile '%s' (%s).",
            profile, type(exc).__name__,
        )
        return None


def _read_persisted_expiration(profile: str, credentials_path: str) -> Optional[datetime]:
    """
    Return the timezone-aware UTC expiration persisted for `profile` in the
    shared credentials file, or None. STRICTLY read-only and TOCTOU-safe: it
    reads through a symlink-refusing, fstat-verified descriptor
    (`_read_regular_file_text`) and never writes, repairs, or creates anything.
    Fails closed (returns None) on a missing/unsafe path, parse error, missing
    section/key, or a malformed or naive expiration value. Never logs file
    content or paths.
    """
    if not isinstance(profile, str) or not profile:
        return None
    content = _read_regular_file_text(credentials_path)
    if content is None:
        return None
    parser = configparser.ConfigParser()
    parser.optionxform = str  # preserve option-name case
    try:
        parser.read_string(content)
    except configparser.Error:
        return None
    if not parser.has_section(profile) or not parser.has_option(profile, EXPIRATION_METADATA_KEY):
        return None
    raw = parser.get(profile, EXPIRATION_METADATA_KEY)
    try:
        parsed = datetime.fromisoformat(raw)
    except (ValueError, TypeError):
        return None
    if not _is_aware(parsed):
        return None
    return parsed.astimezone(timezone.utc)


def credentials_are_valid(profile: str, credentials_path: Optional[str] = None) -> bool:
    """
    Read-only reuse decision based on the REAL STS expiration persisted for
    `profile` (not a locally invented timestamp/duration). Returns True only
    when a timezone-aware expiration exists and is still later than
    now(UTC) + REUSE_SAFETY_MARGIN_SECONDS. Returns False for a missing,
    malformed, naive, expired, or near-expiry value. Never writes or repairs
    any state during the check.
    """
    path = credentials_path or _default_credentials_path()
    expiration = _read_persisted_expiration(profile, path)
    if expiration is None:
        logging.debug("[credentials_are_valid] No usable persisted expiration for '%s'.", profile)
        return False
    deadline = datetime.now(timezone.utc) + timedelta(seconds=REUSE_SAFETY_MARGIN_SECONDS)
    return expiration > deadline


def get_temporary_credentials(
        config: configparser.ConfigParser,
        profile: str,
        mfa_serial: str,
        mfa_token: str,
        duration: int = USER_MAX_DURATION
) -> Dict[str, str]:
    """
    Fetches temporary AWS credentials.
      - If the profile is role-based (has role_arn), calls sts.assume_role.
      - Otherwise, calls sts.get_session_token (classic IAM user + MFA).
    'duration' can be up to USER_MAX_DURATION, but for roles we limit to ROLE_MAX_DURATION.
    Returns a dict of new credentials on success, or an EMPTY dict on any failure
    (unknown/malformed profile, STS error, or a successful STS call whose response
    lacks a semantically valid Credentials mapping) so the caller can fail closed.
    Credentials are NOT cached in-process: each call re-derives from STS, so a
    stale value can never be reused beyond its real expiration. Error logs never
    include the MFA token, the returned secrets, or the raw STS response/exception.
    """
    profile_key = f'profile {profile}' if not profile.startswith('profile ') else profile
    is_role_based = config.has_section(profile_key) and config.has_option(profile_key, 'role_arn')

    if is_role_based:
        logging.info(f"[get_temporary_credentials] Detected role_arn in profile '{profile}'. Using assume_role with MFA.")

        # Missing/invalid required role fields are a controlled failure, never a
        # raw configparser traceback.
        try:
            role_arn = config.get(profile_key, 'role_arn')
            source_profile = config.get(profile_key, 'source_profile')
        except (configparser.NoSectionError, configparser.NoOptionError) as exc:
            logging.error(
                "[get_temporary_credentials] Role profile '%s' is missing required fields (%s).",
                profile, type(exc).__name__,
            )
            return {}
        if not (role_arn and role_arn.strip()) or not (source_profile and source_profile.strip()):
            logging.error(
                "[get_temporary_credentials] Role profile '%s' has an empty role_arn or source_profile.",
                profile,
            )
            return {}

        # Limit role duration
        role_duration = min(duration, ROLE_MAX_DURATION)

        try:
            source_session = boto3.Session(profile_name=source_profile)
            source_creds = source_session.get_credentials().get_frozen_credentials()

            sts_client = boto3.client(
                'sts',
                aws_access_key_id=source_creds.access_key,
                aws_secret_access_key=source_creds.secret_key,
                aws_session_token=source_creds.token
            )
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"{profile}-session",
                DurationSeconds=role_duration,
                SerialNumber=mfa_serial,
                TokenCode=mfa_token
            )
        except Exception as exc:
            logging.error(
                "[get_temporary_credentials] assume_role failed for profile '%s' (%s).",
                profile, type(exc).__name__,
            )
            return {}

        new_credentials = _valid_sts_credentials(response)
        if not new_credentials:
            logging.error(
                "[get_temporary_credentials] assume_role response for profile '%s' lacked valid credentials.",
                profile,
            )
            return {}
        return new_credentials
    else:
        # Classic IAM user
        session = get_aws_session(profile)
        if not session:
            logging.error(f"[get_temporary_credentials] Could not create session for profile '{profile}'.")
            return {}

        try:
            base_creds = session.get_credentials().get_frozen_credentials()
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=base_creds.access_key,
                aws_secret_access_key=base_creds.secret_key
            )
            response = sts_client.get_session_token(
                DurationSeconds=duration,
                SerialNumber=mfa_serial,
                TokenCode=mfa_token
            )
        except Exception as exc:
            logging.error(
                "[get_temporary_credentials] get_session_token failed for profile '%s' (%s).",
                profile, type(exc).__name__,
            )
            return {}

        new_credentials = _valid_sts_credentials(response)
        if not new_credentials:
            logging.error(
                "[get_temporary_credentials] get_session_token response for profile '%s' lacked valid credentials.",
                profile,
            )
            return {}
        return new_credentials


def configure_aws_credentials(
        profile: str,
        credentials: Dict[str, str],
        credentials_path: Optional[str] = None,
) -> bool:
    """
    Persist the temporary credentials into `profile` in the shared credentials
    file WITHOUT invoking the AWS CLI, so secret values never appear in a
    process argument list. The ENTIRE read-modify-write transaction runs under a
    same-directory advisory lock, so two cooperating writers can never lose an
    update: the second writer always reads the first writer's committed result
    before producing its own atomic replacement.

    Under the lock it: re-checks target-path safety; reads the latest file
    through a symlink-refusing, fstat-verified descriptor; merges ONLY the
    target profile (preserving every other profile/option and option-name case);
    writes a randomized same-directory 0600 temp file; flush + fsync; os.replace;
    and ensures the final file is 0600. On any failure it returns False, emits a
    concise payload-free error, removes only this call's temp file, and leaves
    the pre-existing file unchanged whenever the atomic replace has not occurred.
    Never logs credential values, STS values, MFA codes, file content, or paths.
    """
    # 1) profile name (rejects control chars / INI-section injection)
    if not _valid_profile_name(profile):
        logging.error("[configure_aws_credentials] Invalid or unsafe profile name.")
        return False

    # 2) credential mapping: non-empty secret strings + aware, unexpired expiration
    if not isinstance(credentials, dict):
        logging.error("[configure_aws_credentials] Invalid credential mapping.")
        return False
    secret_values = {}
    for key in _REQUIRED_SECRET_KEYS:
        value = credentials.get(key)
        if not isinstance(value, str) or not value:
            logging.error("[configure_aws_credentials] Missing or empty credential field.")
            return False
        secret_values[key] = value
    expiration = credentials.get("Expiration")
    if not _is_aware(expiration):
        logging.error("[configure_aws_credentials] Missing or invalid credential expiration.")
        return False
    if expiration <= datetime.now(timezone.utc):
        logging.error("[configure_aws_credentials] Refusing to persist already-expired credentials.")
        return False
    expiration_iso = expiration.astimezone(timezone.utc).isoformat()

    path = credentials_path or _default_credentials_path()
    directory = os.path.dirname(path) or "."

    # Parent directory must already exist (never create home paths implicitly).
    if not os.path.isdir(directory):
        logging.error("[configure_aws_credentials] Credentials parent directory does not exist.")
        return False

    # 3) Acquire the lock BEFORE loading the file, and hold it across the whole
    #    read-modify-write so a concurrent writer cannot start from stale content.
    lock_fd = _open_locked(directory)
    if lock_fd is None:
        logging.error("[configure_aws_credentials] Could not acquire a safe credentials lock.")
        return False

    tmp_fd = None
    tmp_path = None
    try:
        # 3a) Re-check target-path safety UNDER the lock.
        try:
            link_stat = os.lstat(path)
        except FileNotFoundError:
            link_stat = None
        except OSError as exc:
            logging.error(
                "[configure_aws_credentials] Could not inspect credentials path (%s).",
                type(exc).__name__,
            )
            return False
        existing = None
        if link_stat is not None:
            if stat.S_ISLNK(link_stat.st_mode):
                logging.error("[configure_aws_credentials] Refusing to write through a symlinked credentials file.")
                return False
            if not stat.S_ISREG(link_stat.st_mode):
                logging.error("[configure_aws_credentials] Credentials path is not a regular file.")
                return False
            # 3b) Read the LATEST content via the symlink-refusing verified fd.
            existing = _read_regular_file_text(path)
            if existing is None:
                logging.error("[configure_aws_credentials] Could not safely read the existing credentials file.")
                return False

        # 3c) Parse (preserving all sections/options + case) and merge target.
        parser = configparser.ConfigParser()
        parser.optionxform = str
        if existing is not None:
            try:
                parser.read_string(existing)
            except configparser.Error as exc:
                logging.error(
                    "[configure_aws_credentials] Could not parse existing credentials file (%s).",
                    type(exc).__name__,
                )
                return False

        if not parser.has_section(profile):
            parser.add_section(profile)
        parser.set(profile, "aws_access_key_id", secret_values["AccessKeyId"])
        parser.set(profile, "aws_secret_access_key", secret_values["SecretAccessKey"])
        parser.set(profile, "aws_session_token", secret_values["SessionToken"])
        parser.set(profile, EXPIRATION_METADATA_KEY, expiration_iso)

        # 3d) Atomic, 0600, fsync'd replace (still holding the lock).
        tmp_fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".aws_cluster_connect.", suffix=".tmp")
        os.fchmod(tmp_fd, 0o600)
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as out:
            tmp_fd = None  # ownership transferred to the file object
            parser.write(out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp_path, path)
        tmp_path = None  # replaced atomically; nothing to clean up
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # temp already had 0600; os.replace preserved it
        return True
    except OSError as exc:
        logging.error(
            "[configure_aws_credentials] Failed to persist credentials for profile '%s' (%s).",
            profile, type(exc).__name__,
        )
        return False
    finally:
        if tmp_fd is not None:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if tmp_path is not None and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        _close_locked(lock_fd)
