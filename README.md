# AWS EKS Connection Script

A modular Python solution for retrieving temporary AWS credentials (using **MFA** or **Switch Roles**) and automatically updating your local Kubernetes config to connect to an EKS cluster. It supports:

- **1Password-based MFA** retrieval
- **Role-based credential chaining** (`assume_role`)
- **Classic IAM user** credentials (`get_session_token`)

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Prerequisites](#prerequisites)
3. [AWS Configuration](#aws-configuration)
4. [How It Works](#how-it-works)
5. [Usage](#usage)
6. [Force Refresh](#force-refresh)
7. [Troubleshooting](#troubleshooting)
8. [Future Enhancements](#future-enhancements)

---

## Project Structure
```plaintext
script_name/
├── README.md             # This file
├── settings.py           # Constants (role/user max durations)
├── aws_config.py         # Reads/writes AWS config data (cluster_name, region, etc.)
├── credentials.py        # Handles STS calls for temporary credentials
├── mfa.py                # Fetches TOTP codes from 1Password
├── kube.py               # Connects to EKS via 'update-kubeconfig' (checks exit status)
├── errors.py             # Typed operational errors + fixed process exit codes
├── main.py               # Main entry point (CLI; fail-closed exits, no tracebacks)
├── test_cluster_connect.py   # Fake-only tests (op/STS/aws CLI faked)
├── requirements.txt          # Runtime deps (boto3)
├── requirements-dev.txt      # Test/lint deps (pytest, pyflakes)
└── .github/workflows/ci.yml  # CI: pyflakes + pytest
```

---

## AWS Configuration

- In ~/.aws/config, you need at least one profile with the following structure:
  ```ini
  [profile env]
  region = eu-west-1
  output = json
  cluster_name = env-cluster
  mfa_serial = arn:aws:iam::111111111111:mfa/JohnDoe
  ```
- If you’re using a role, you might have:
  ```ini
  [profile devops]
  region = eu-west-1
  output = json
  role_arn = arn:aws:iam::222222222222:role/devops
  source_profile = shared
  mfa_serial = arn:aws:iam::222222222222:mfa/JohnDoe
  ```
- In ~/.aws/credentials:
  ```ini
  [env]
  aws_access_key_id = AAAABBBBCCCCDDDDEEEE
  aws_secret_access_key = aVerySecretAccessKey
  
  [shared]
  aws_access_key_id = FFFFEEEEDDDDCCCCBBBB
  aws_secret_access_key = anotherSecretAccessKey
  ```
> **_NOTE:_**  The script will create or update [<profile>2auth] in the config/credentials to store temporary tokens.

## How It Works

- **Script Execution:** You run python main.py myenv, and the script derives the profile name (e.g., myenv2auth) to store temporary credentials
- **Check Validity (fail-closed):** cached credentials for `<profile>2auth` are reused ONLY when EVERY check passes — the three temporary credential fields are present in `~/.aws/credentials`, a non-secret **target fingerprint** stored in `~/.aws/config` matches the current identity target (profile, `role_arn`, `source_profile`, `mfa_serial`, region, `cluster_name`), the stored **credential expiration** is present and still in the future, `profile_timestamp` is present and numeric, and the duration bound holds. Any missing/malformed/mismatched value forces a refresh. A missing timestamp is treated as INVALID, never as newly valid.
- **Assume Role or Get Session Token:** If credentials are expired (or you use --force-refresh), the script retrieves a TOTP code from 1Password (e.g., AmazonMYENV) and calls STS to generate temporary credentials
- **Update Kubeconfig:** Finally, it updates ~/.kube/config so that kubectl commands work against the EKS cluster specified in the profile’s cluster_name

## Usage

- **From the script_name/ directory:**
  ```bash
  python main.py <environment>
  ```
- **For example:**
  ```bash
  python main.py env-dev
  ```
  
> **_NOTE:_** The script will parse env-dev, derive env as the base profile, check credentials for [env2auth], and if needed, get a TOTP code from 1Password (Amazon<ENV_NAME>)


## Force Refresh

- **Use the --force-refresh flag to ignore existing credentials:**
  ```bash 
  python main.py --force-refresh <env_name>-dev
  ```
> **_NOTE:_** Even if your tokens haven’t expired, the script will retrieve new ones


## Troubleshooting

### Invalid MFA One-Time Passcode
- Ensure the 1Password item name matches exactly what the script expects (e.g., `Amazon<ENV_NAME>`).
- Confirm `mfa_serial` in `~/.aws/config` belongs to the same user who owns the TOTP device.

---

### The Requested `DurationSeconds` Exceeds `MaxSessionDuration`
- Either lower `ROLE_MAX_DURATION` in `settings.py` or increase the role’s `MaxSessionDuration` in IAM.

---

### Cluster Not Found
- Verify the `cluster_name` in `~/.aws/config` under `[profile myenv]`.
- Ensure `myenv` is spelled correctly and references the correct AWS account and region.

---

### No MFA Token Retrieved
- Confirm that the 1Password CLI is installed and authenticated (`op signin`).
- Verify that the item name is correct (`op item get Amazon<ENV_NAME> --otp`).
- Use `op item list` to see the available items.
- If you configured `mfa_item`, confirm it names an existing item; otherwise the derived
  `Amazon<SOURCE_PROFILE_UPPER>` (e.g. `AmazonSHARED`) must exist.

---

### Old cluster/credentials kept being reused after a role change
- This is now prevented by the fingerprint check. If you still see stale behavior, remove
  `credential_fingerprint`/`credential_expiration`/`profile_timestamp` under
  `[profile <env>2auth]` in `~/.aws/config` (and the `[<env>2auth]` block in
  `~/.aws/credentials`) and re-run, or use `--force-refresh`.

---

### Configuration error before any AWS call
- The script validates `role_arn` (`:role/`) and `mfa_serial` (`:mfa/`) and rejects swapped,
  equal, malformed, or missing values, and a missing `source_profile` for role profiles.
  Fix the offending field in `~/.aws/config` and re-run.

---

### `update-kubeconfig` failed
- The script now exits non-zero (code 6) instead of reporting success. Check the AWS CLI
  output shown above the error, verify the profile has valid temporary credentials and the
  cluster/region are correct, then re-run (optionally with `--force-refresh`).

## Credential cache model (fail-closed)

Cache validity no longer trusts `profile_timestamp` alone. On every run the script
computes a non-secret **target fingerprint** — a SHA-256 over the version tag plus the
`<profile>2auth` name, `role_arn`, `source_profile`, `mfa_serial`, `region`, and
`cluster_name`. When new STS credentials are created, the script persists (via
`aws configure set`, into `[profile <profile>2auth]` in `~/.aws/config`):

- `credential_fingerprint` — the fingerprint above (non-secret);
- `credential_expiration` — the STS credential expiry (ISO-8601);
- `profile_timestamp` — the write time.

A later run reuses the cache only if the recomputed fingerprint matches, the expiration
is in the future, the timestamp is present and numeric, and all three temporary
credential fields exist in `~/.aws/credentials`. This closes the bug where old
`legendsprod` credentials were reused after the profile was pointed at a different role
(`legendbetprod`): the `role_arn` change alters the fingerprint, so the stale cache is
rejected and refreshed. None of the persisted metadata is secret.

## Explicit 1Password MFA item (`mfa_item`)

The role-based path derives the 1Password item as `Amazon<SOURCE_PROFILE_UPPER>` (for the
current setup this is `AmazonSHARED`, not `AmazonLEGENDBETPROD`). That derivation is kept
for backward compatibility, but you can pin the item explicitly in `~/.aws/config`:

```ini
[profile legendbetprod]
role_arn      = arn:aws:iam::…:role/legendbetprod
source_profile = shared
mfa_serial    = arn:aws:iam::…:mfa/you
region        = eu-west-1
cluster_name  = legendbet-prod
mfa_item      = AmazonSHARED
```

When `mfa_item` is present it is validated (a conservative identifier charset) and used
instead of the derivation. `op` is always invoked through a fixed argument vector
(`op item get <item> --otp`), never a shell.

## Configuration validation (before any AWS request)

Before contacting STS the script validates identity configuration and returns a concise
error (no AWS call, no traceback) when:

- `role_arn` is missing or does not contain `:role/`;
- `mfa_serial` is missing or does not contain `:mfa/`;
- the two are swapped (`:mfa/` in `role_arn`, or `:role/` in `mfa_serial`), equal, or
  otherwise malformed;
- `source_profile` is missing for a role-based profile.

## Exit codes (fail-closed, no tracebacks)

Every failure returns a non-zero process exit status with a concise, secret-free log line
(no keys, tokens, OTPs, credential contents, or raw provider stderr):

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | invalid/missing/malformed configuration |
| 3 | missing/empty MFA (OTP) token |
| 4 | STS `ClientError` (e.g. AccessDenied, invalid MFA) |
| 5 | failed to write temporary credentials |
| 6 | `aws eks update-kubeconfig` returned non-zero |
| 1 | other/unexpected failure |

`kube.py` explicitly checks the `aws eks update-kubeconfig` return status; a failed
update is never reported as success.

## Rollback and safe recovery

- To force a clean refresh regardless of the cache: `python main.py --force-refresh <env>`.
- If a target changed (role/account/cluster) and you want to discard the stale cache, remove
  the persisted metadata for the derived auth profile from `~/.aws/config`
  (`credential_fingerprint`, `credential_expiration`, `profile_timestamp` under
  `[profile <env>2auth]`) and its `[<env>2auth]` block in `~/.aws/credentials`, then re-run;
  the next run recreates them. A wrong or stale fingerprint/expiration simply triggers a
  refresh — it never connects with the old credentials.
- On any failure the script exits non-zero and leaves your shell without a false "connected"
  signal; fix the reported condition (config, MFA, STS, or update-kubeconfig) and re-run.

## Tests & CI

```bash
python -m pip install -r requirements-dev.txt
python -m pyflakes *.py
python -m pytest -q
```

Tests use fake `op`, fake STS/boto3, a fake `aws configure set`, and a fake
`aws eks update-kubeconfig` with synthetic `~/.aws` files in a temp dir — no real AWS,
Kubernetes, 1Password, or cloud calls, and they assert no secret/token leakage to logs.

