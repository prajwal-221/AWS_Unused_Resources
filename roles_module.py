from typing import List, Dict, Tuple
import boto3
from botocore.exceptions import ClientError
import os
import datetime
from utils import get_logger

# Module-level logger
logger = get_logger()

TARGET_RESOURCE_TYPES = {'AWS::IAM::Role'}
# Add 'UnusedPermission' to include roles with unused permissions
UNUSED_FINDING_TYPES = {'UnusedIAMRole', 'UnusedPermission'}

def get_access_analyzer_findings(session: boto3.Session, analyzer_arn: str, region: str) -> List[Dict]:
    """Get Access Analyzer findings for unused IAM roles in a region."""
    access_analyzer = session.client('accessanalyzer', region_name=region)
    try:
        paginator = access_analyzer.get_paginator('list_findings_v2')
        findings = [f for page in paginator.paginate(
            analyzerArn=analyzer_arn,
            filter={'status': {'eq': ['ACTIVE']}}  # Include only active findings
        ) for f in page['findings']]
    except (access_analyzer.exceptions.ValidationException,
            access_analyzer.exceptions.ThrottlingException,
            access_analyzer.exceptions.AccessDeniedException,
            access_analyzer.exceptions.ResourceNotFoundException,
            Exception) as e:
        logger.error(f"Access Analyzer error in region {region}: {e}")
        return []

    # Log all finding types for debugging
    all_types = set(f.get('findingType') for f in findings)
    logger.debug(f"Finding types in {region}: {all_types}")

    # Filter findings to include unused IAM roles
    filtered = [
        f | {'region': region} for f in findings
        if f.get('findingType') in UNUSED_FINDING_TYPES and f.get('resourceType') in TARGET_RESOURCE_TYPES
    ]

    logger.info(f"{len(filtered)} unused findings in {region} after filtering.")
    return filtered

def summarize_iam_roles(findings: List[Dict]) -> List[Dict]:
    """Summarize IAM role findings from Access Analyzer."""
    return [
        {
            'resourceArn': f.get('resource', 'unknown'),
            'status': f.get('status', 'unknown'),
            'updatedAt': f.get('updatedAt').isoformat() if f.get('updatedAt') else 'unknown',
            'region': f.get('region', 'unknown'),
            'analyzerArn': f.get('analyzerArn', 'unknown')
        }
        for f in findings if f.get('resourceType') == 'AWS::IAM::Role'
    ]

def get_analyzer_name(session: boto3.Session, region: str) -> Tuple[str, str]:
    """Get the name and ARN of the first Access Analyzer in a region."""
    client = session.client('accessanalyzer', region_name=region)
    try:
        analyzers = client.list_analyzers()['analyzers']
        if not analyzers:
            logger.warning(f"No analyzer found in {region}. Skipping.")
            return None, None
        analyzer = analyzers[0]
        logger.debug(f"Using analyzer '{analyzer['name']}' in {region}.")
        return analyzer['name'], analyzer['arn']
    except ClientError as e:
        logger.error(f"Error fetching analyzer in {region}: {e}")
        return None, None

def summarize_findings(findings: List[Dict]) -> Dict:
    """Summarize all Access Analyzer findings for IAM roles."""
    iam_roles = summarize_iam_roles(findings)
    return {
        'iam_roles': iam_roles,
        'summary': {'total_iam_roles': len(iam_roles)}
    }

def print_summary(summary: Dict, output_file: str) -> None:
    """Print a summary of the scan results."""
    logger.info("\n================ AWS Unused Resources Scan Summary ================")
    logger.info(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"IAM Roles: {summary['summary']['total_iam_roles']} unused roles found")
    logger.info(f"Detailed results saved to: {os.path.abspath(output_file)}")
    logger.info("==================================================================\n")
