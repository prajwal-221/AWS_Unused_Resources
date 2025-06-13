import boto3
import json
import logging
import os
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError
from roles_module import summarize_iam_roles, get_access_analyzer_findings, get_analyzer_name, summarize_findings, print_summary
from policies_module import get_unused_iam_policies
from security_groups_module import get_unused_security_groups
from typing import NoReturn
from utils import get_logger

OUTPUT_FILE = 'access_analyzer_unused_resources.json'
LOG_FILE = 'access_analyzer_script.log'

logger = get_logger()

def main() -> NoReturn:
    """Main entry point for scanning unused AWS resources using Access Analyzer."""
    try:
        # Step 1: Check for AWS credentials before any other operation
        session = boto3.Session()
        credentials = session.get_credentials()
        if not credentials or not credentials.access_key or not credentials.secret_key:
            logger.error("No AWS credentials found. Use AWS_PROFILE or configure with aws configure.")
            print("No AWS credentials found. Use AWS_PROFILE or configure with aws configure.")
            exit(1)
        logger.info("AWS credentials found and loaded successfully.")
        if not session.region_name:
            raise NoRegionError()
        ec2 = session.client('ec2')
        regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        logger.info(f"Scanning {len(regions)} regions: {regions}")

        # Collect unused IAM roles
        all_findings = []
        regions_with_analyzer = []
        for region in regions:
            analyzer_name, analyzer_arn = get_analyzer_name(session, region)
            if analyzer_name and analyzer_arn:
                logger.info(f"Scanning region: {region} with analyzer '{analyzer_name}'...")
                findings = get_access_analyzer_findings(session, analyzer_arn, region)
                logger.info(f"  {len(findings)} unused findings in {region}")
                all_findings.extend(findings)
                regions_with_analyzer.append(region)
            else:
                logger.warning(f"No analyzer found in region {region}.")

        # Collect unused security groups
        unused_security_groups = get_unused_security_groups(session)
        logger.info(f"Total unused security groups found: {len(unused_security_groups)}")

        # Collect unused IAM policies
        unused_policies = get_unused_iam_policies(session)
        logger.info(f"Total unused IAM policies found: {len(unused_policies)}")

        if not regions_with_analyzer:
            logger.error("No Access Analyzer found in any region. Please create an analyzer in your AWS account.")
        elif not all_findings and not unused_security_groups and not unused_policies:
            logger.info("No unused resources found by Access Analyzer in any region.")
        else:
            summary = {
                'iam_roles': summarize_findings(all_findings),
                'security_groups': unused_security_groups,
                'iam_policies': unused_policies,
                'summary': {
                    'total_iam_roles': len(all_findings),
                    'total_security_groups': len(unused_security_groups),
                    'total_iam_policies': len(unused_policies)
                }
            }
            with open(OUTPUT_FILE, 'w') as f:
                json.dump(summary, f, indent=2)
            print_summary(summary, OUTPUT_FILE)
    except NoCredentialsError:
        logger.error("No AWS credentials found. Use AWS_PROFILE or configure with aws configure.")
    except NoRegionError:
        logger.error("No default region configured. Please set it in ~/.aws/config or export AWS_REGION.")
    except Exception as e:
        logger.exception(f"Unexpected error occurred: {e}")
    exit(0)

if __name__ == '__main__':
    main()
