# AWS EKS Cluster Connection Script

## Overview
This script automates the process of connecting to AWS EKS clusters. It handles fetching temporary credentials using MFA, configuring AWS credentials, and updating the kubeconfig file.

## Prerequisites
- Python 3.x
- AWS CLI
- Boto3
- 1Password CLI (for MFA token retrieval)
- Properly set up AWS configuration and credentials files

## Installation

### MacOS and Linux
1. **Python 3.x**: Ensure Python 3.x is installed. Download from [python.org](https://www.python.org/downloads/).

2. **AWS CLI**: Install the AWS CLI as per the [AWS CLI User Guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html).

3. **Boto3**: Install Boto3 using `pip install boto3`.

4. **1Password CLI**: Install the 1Password CLI following the instructions on the [1Password CLI documentation](https://support.1password.com/command-line-getting-started/).

### Configuration
#### AWS Configuration
Configure your AWS CLI with the necessary profiles. The script expects the following formats:

- **/aws/config**:
  ```ini
  [profile <env_name>]
  region = <region>
  output = json
  cluster_name = <cluster_name>
  mfa_serial = <mfa_serial>

- **/aws/credentials**:
  ```ini
  [<env_name>]
  aws_access_key_id = <aws_access_key_id>
  aws_secret_access_key = <aws_secret_access_key>

Replace placeholders with your AWS details.

#### 1Password Configuration
The script retrieves MFA tokens using 1Password CLI. Ensure your credentials in 1Password start with `Amazon<env_name>`.

## Usage
Execute the script with the environment name as an argument:
```bash
python script_name.py my-environment
