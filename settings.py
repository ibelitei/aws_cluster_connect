# settings.py
"""
Holds common constants or settings for the AWS/EKS connection script.
"""

# Role sessions obtained via STS AssumeRole are capped to one hour. Requesting
# more than a role's MaxSessionDuration (AWS default 3600s) makes AssumeRole
# fail, which previously left credentials unrefreshed and forced repeated manual
# reconnects. 3600s is the safe maximum that works with a default-duration role.
ROLE_MAX_DURATION: int = 3600      # 1 hour for role-based profiles (AssumeRole)
USER_MAX_DURATION: int = 129600    # 36 hours for IAM user profiles (GetSessionToken)

# Bounded external waits. Every network/subprocess call the connector makes is
# time-boxed so a hung STS endpoint or a stuck 'aws' child fails fast and closed
# instead of blocking the operator indefinitely. These are hard ceilings, not
# retry budgets: the connector adds NO retries, polling, or background work.
AWS_CONNECT_TIMEOUT_SECONDS: int = 10        # botocore TCP connect timeout (STS)
AWS_READ_TIMEOUT_SECONDS: int = 30           # botocore read/response timeout (STS)
UPDATE_KUBECONFIG_TIMEOUT_SECONDS: int = 60  # 'aws eks update-kubeconfig' subprocess ceiling