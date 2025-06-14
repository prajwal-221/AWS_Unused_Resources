# AWS Unused Resources Analyzer

This project scans your AWS account for unused resources using AWS Access Analyzer and other AWS APIs. It helps you identify and clean up unused IAM roles, IAM policies, and EC2 security groups across all regions.

## Features
- Scans all AWS regions for unused IAM roles using Access Analyzer
- Identifies unused customer-managed IAM policies
- Detects unused EC2 security groups
- Outputs a summary and detailed results in JSON format
- Logs all actions and warnings for audit and troubleshooting

## Prerequisites
- Python 3.8 or higher (Python 3.9+ recommended)
- AWS credentials with sufficient permissions (Access Analyzer, IAM, EC2)
- AWS Access Analyzer enabled in at least one region
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) and [botocore](https://botocore.amazonaws.com/v1/documentation/api/latest/index.html) Python packages

## Setup
1. **Clone the repository or copy the script files to your working directory.**
2. **Install dependencies:**
   ```sh
   pip install boto3 botocore
   ```
3. **Configure your AWS credentials:**
   - Use `aws configure` to set up your credentials and default region, or
   - Set the `AWS_PROFILE` environment variable to use a named profile.

## Usage

You can run the analyzer using either `main.py` or `access_analyzer_unused_resources.py` (if present):

```sh
AWS_PROFILE=your_profile_name python3 main.py
```

- Replace `your_profile_name` with your AWS CLI profile name, or omit `AWS_PROFILE` if using the default profile.
- The script will scan all AWS regions and output results to `access_analyzer_unused_resources.json`.
- Logs are written to `access_analyzer_script.log`.

## Output
- **access_analyzer_unused_resources.json**: Contains a summary and details of unused IAM roles, policies, and security groups.
- **access_analyzer_script.log**: Contains detailed logs of the scan process.

## Notes
- Ensure you have Access Analyzer enabled in at least one region for IAM role analysis.
- The script requires permissions to list IAM roles, policies, security groups, and Access Analyzer findings.
- For large AWS accounts, the scan may take several minutes.

