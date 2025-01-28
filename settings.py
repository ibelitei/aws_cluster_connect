# settings.py
"""
Holds common constants or settings for the AWS/EKS connection script.
"""

ROLE_MAX_DURATION: int = 3600      # 1 hour for role-based profiles
USER_MAX_DURATION: int = 129600    # 36 hours for IAM user profiles