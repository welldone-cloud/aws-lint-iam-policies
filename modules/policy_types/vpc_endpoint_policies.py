RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "ec2"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ec2_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    endpoints_paginator = ec2_client.get_paginator("describe_vpc_endpoints")

    # Iterate all VPC endpoints
    for endpoints_page in endpoints_paginator.paginate():
        for endpoint in endpoints_page["VpcEndpoints"]:
            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::EC2::VPCEndpoint",
                resource_name=endpoint["VpcEndpointId"],
                resource_arn="arn:aws:ec2:{}:{}:vpc-endpoint/{}".format(region, account_id, endpoint["VpcEndpointId"]),
                policy_document=endpoint["PolicyDocument"],
                policy_type="RESOURCE_POLICY",
            )
