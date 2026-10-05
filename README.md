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
├── kube.py               # Connects to EKS via 'update-kubeconfig'
└── main.py               # Main entry point (CLI)
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
> **_NOTE:_**  The script stores the temporary credentials in the `<profile>2auth` profile of the shared AWS credentials file using a safe atomic local update. Secret values are never passed to `aws configure set` (or any command) as arguments.

## How It Works

- **Script Execution:** You run python main.py myenv, and the script derives the profile name (e.g., myenv2auth) to store temporary credentials
- **Check Validity:** The script reuses existing credentials only when the target profile's real STS expiration (persisted in the shared credentials file) is still valid, applying a short safety margin before the actual expiry
- **Assume Role or Get Session Token:** If credentials are expired (or you use --force-refresh), the script retrieves a TOTP code from 1Password (e.g., AmazonMYENV) and calls STS to generate temporary credentials
- **Update Kubeconfig:** Finally, it updates ~/.kube/config so that kubectl commands work against the EKS cluster specified in the profile’s cluster_name

## Isolated Kubeconfig Target & Bounded Waits

- **Kubeconfig target (backward compatible):**
  - With no isolated target (the `KUBECONFIG` environment variable is unset), the script keeps its
    legacy standalone behaviour: `aws eks update-kubeconfig` writes to its own default
    (`~/.kube/config`).
  - When exactly one isolated session file is supplied via `KUBECONFIG` (the same variable the
    DevOps Shell integration already sets — no competing mechanism), the write is pinned with
    `aws eks update-kubeconfig --kubeconfig <target>`, so only that file is touched and the global
    `~/.kube/config` is never modified.
  - A `KUBECONFIG` that is set but **unusable** — empty, multiple `:`-separated entries, a symlink,
    a non-regular existing file, or a missing parent directory — **fails closed before AWS is
    invoked**. The script never silently falls back to the global kubeconfig after an invalid
    isolated target.
  - The `aws` invocation is shell-free (fixed argument vector); its output is captured and never
    surfaced, so paths, endpoints, and account data are not leaked.
- **Bounded waits (no hidden retries):** every external wait is time-boxed so a hung endpoint fails
  fast and closed. STS calls use bounded botocore connect/read timeouts with retries disabled, and
  `aws eks update-kubeconfig` runs under a subprocess timeout. Timeout failures are concise and
  redacted. These are ceilings only — the script adds no retries, polling, background work, or
  credential caching (see `settings.py`: `AWS_CONNECT_TIMEOUT_SECONDS`, `AWS_READ_TIMEOUT_SECONDS`,
  `UPDATE_KUBECONFIG_TIMEOUT_SECONDS`).

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

### Reading a Temporary-Credential Failure Line
A failure to obtain temporary credentials is reported as one line naming the stage that failed:
```plaintext
[get_temporary_credentials] assume_role failed for profile 'env' (stage=sts_call, ClientError code=AccessDenied operation=AssumeRole http=403).
```
- `stage=source_credentials`: the source/base profile's credentials could not be resolved. The script did not create its own STS client, and its explicit AssumeRole/GetSessionToken call was not reached.
- `stage=sts_client`: the script's STS client could not be constructed. Its explicit AssumeRole/GetSessionToken call was not reached.
- `stage=sts_call`: the script's single explicit AssumeRole/GetSessionToken call failed. SDK retries are disabled for that client.

These guarantees cover only the script's own STS client and call. Resolving the source credentials is done by the AWS SDK's credential providers. Depending on how the source profile is configured, they can make their own network calls (for example, an assume-role, SSO or credential-process source), refresh credentials, or write their own caches, even when the line says `stage=source_credentials`.

For AWS service errors, `code` and `operation` are printed only when they are on a fixed allowlist of documented values. Any other value appears as `unrecognized`, and a missing or malformed value as `unavailable`. `http` appears only for a valid status code. Every other failure shows only the exception class name. The script never prints the exception message, raw response, request ID, request parameters (role ARN, MFA serial or code), or credential values.

When obtaining temporary credentials fails at any of these stages, the script exits 1 before it writes credentials to the shared credentials file and before it updates the kubeconfig. That covers only this step. If a later step fails, earlier steps may already have taken effect: for example, if `aws eks update-kubeconfig` fails after a successful refresh, the new temporary credentials have already been stored. The script does not retry or refresh automatically.

---

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
