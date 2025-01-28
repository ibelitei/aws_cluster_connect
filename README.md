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
> **_NOTE:_**  The script will create or update [<profile>2auth] in the config/credentials to store temporary tokens.

## How It Works

- **Script Execution:** You run python main.py myenv, and the script derives the profile name (e.g., myenv2auth) to store temporary credentials
- **Check Validity:** The script checks if existing credentials are still valid (based on a timestamp in ~/.aws/config)
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
