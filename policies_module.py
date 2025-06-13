import logging
from typing import List, Dict
import boto3
from botocore.exceptions import ClientError
from utils import paginate, get_logger

logger = get_logger()

def get_unused_iam_policies(session: boto3.Session) -> List[Dict]:
    """Identify unused customer-managed IAM policies (without Access Analyzer)."""
    iam = session.client('iam')
    unused_policies = []
    try:
        for page in paginate(iam, 'list_policies', Scope='Local'):
            for policy in page['Policies']:
                arn = policy['Arn']
                name = policy['PolicyName']
                logger.debug(f"Checking policy: {name} ({arn})")
                try:
                    entities = iam.list_entities_for_policy(PolicyArn=arn)
                    logger.debug(f"Policy {name} attached to users: {entities['PolicyUsers']}, groups: {entities['PolicyGroups']}, roles: {entities['PolicyRoles']}")
                    if not any([entities['PolicyUsers'], entities['PolicyGroups'], entities['PolicyRoles']]):
                        unused_policies.append({
                            'PolicyName': name,
                            'Arn': arn,
                            'CreateDate': policy['CreateDate'].isoformat() if hasattr(policy['CreateDate'], 'isoformat') else str(policy['CreateDate']),
                            'Description': policy.get('Description', 'No description available')
                        })
                except ClientError as e:
                    logger.warning(f"IAM policy entity check error for {arn}: {e}")
    except ClientError as e:
        logger.warning(f"IAM-policy collection error: {e}")
    logger.info(f"Checked {len(unused_policies)} unused customer-managed IAM policies.")
    return unused_policies
