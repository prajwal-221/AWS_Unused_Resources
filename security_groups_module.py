import logging
from typing import List, Dict
import boto3
from botocore.exceptions import ClientError, SSLError
from utils import paginate, get_logger

logger = get_logger()

def get_unused_security_groups(session: boto3.Session) -> List[Dict]:
    """Identify unused security groups across all regions (without Access Analyzer)."""
    ec2 = session.client('ec2')
    try:
        regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
    except ClientError as e:
        logger.error(f"Failed to get regions: {e}")
        return []

    unused_sgs = []
    for region in regions:
        try:
            reg_ec2 = session.client('ec2', region_name=region)
            used_sgs = set()
            all_sgs = set()

            # Collect used security groups
            def collect_used():
                try:
                    used_sgs.update(
                        s['GroupId']
                        for res in reg_ec2.describe_instances().get('Reservations', [])
                        for inst in res.get('Instances', [])
                        for s in inst.get('SecurityGroups', [])
                    )
                    used_sgs.update(
                        s['GroupId']
                        for ni in reg_ec2.describe_network_interfaces().get('NetworkInterfaces', [])
                        for s in ni.get('Groups', [])
                    )
                except ClientError as e:
                    logger.warning(f"EC2 describe error in {region}: {e}")
                try:
                    elb = session.client('elb', region_name=region)
                    used_sgs.update(
                        sg for lb in elb.describe_load_balancers()['LoadBalancerDescriptions']
                        for sg in lb.get('SecurityGroups', [])
                    )
                except ClientError:
                    pass
                try:
                    elbv2 = session.client('elbv2', region_name=region)
                    used_sgs.update(
                        sg for lb in elbv2.describe_load_balancers()['LoadBalancers']
                        for sg in lb.get('SecurityGroups', [])
                    )
                except ClientError:
                    pass
                try:
                    rds = session.client('rds', region_name=region)
                    used_sgs.update(
                        v['VpcSecurityGroupId']
                        for db in rds.describe_db_instances().get('DBInstances', [])
                        for v in db.get('VpcSecurityGroups', [])
                    )
                except (ClientError, SSLError) as e:
                    logger.warning(f"RDS describe error in {region}: {e}")
                try:
                    lam = session.client('lambda', region_name=region)
                    used_sgs.update(
                        sg for fn in lam.list_functions().get('Functions', [])
                        for sg in lam.get_function_configuration(FunctionName=fn['FunctionName']).get('VpcConfig', {}).get('SecurityGroupIds', [])
                    )
                except ClientError:
                    pass
                try:
                    eks = session.client('eks', region_name=region)
                    for page in paginate(eks, 'list_clusters'):
                        for cluster_name in page['clusters']:
                            cluster = eks.describe_cluster(name=cluster_name)['cluster']
                            used_sgs.update(cluster.get('resourcesVpcConfig', {}).get('securityGroupIds', []))
                            for ng_page in paginate(eks, 'list_nodegroups', clusterName=cluster_name):
                                for ng_name in ng_page['nodegroups']:
                                    nodegroup = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)['nodegroup']
                                    used_sgs.update(nodegroup.get('resources', {}).get('securityGroups', []))
                except ClientError as e:
                    logger.warning(f"EKS security group usage collection error in {region}: {e}")
            collect_used()

            # Collect unused
            try:
                for sg in reg_ec2.describe_security_groups()['SecurityGroups']:
                    gid = sg['GroupId']
                    all_sgs.add(gid)
                    # Skip default security groups
                    if sg.get('GroupName') == 'default':
                        logger.debug(f"Skipping default SG: {gid} in {region}")
                        continue
                    if gid in used_sgs:
                        logger.debug(f"Skipping SG: {gid} in {region}")
                        continue
                    entry = {
                        'GroupId': gid,
                        'GroupName': sg.get('GroupName'),
                        'VpcId': sg.get('VpcId'),
                        'Region': region
                    }
                    tags = {t['Key']: t['Value'] for t in sg.get('Tags', [])}
                    if 'aws:cloudformation:stack-name' in tags:
                        entry['Warning'] = 'Associated with CloudFormation stack'
                    unused_sgs.append(entry)
            except ClientError as e:
                logger.warning(f"Security group collection error in {region}: {e}")
            logger.info(f"Region {region}: {len(unused_sgs)} unused SGs, {len(used_sgs)} used SGs, {len(all_sgs)} total SGs.")
        except SSLError as ssl_err:
            logger.error(f"SSL error in region {region}: {ssl_err}. Skipping region.")
            continue
        except Exception as e:
            logger.error(f"Unexpected error in region {region}: {e}. Skipping region.")
            continue
    logger.info(f"Total unused security groups found: {len(unused_sgs)}")
    return unused_sgs
