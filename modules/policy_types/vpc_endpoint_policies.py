RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "ec2"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ec2_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    endpoints_paginator = ec2_client.get_paginator("describe_vpc_endpoints")
    services_with_vpc_endpoint_policy_support = set()

    # Iterate all VPC endpoints
    for endpoints_page in endpoints_paginator.paginate():
        for endpoint in endpoints_page["VpcEndpoints"]:

            # If there are VPC endpoints present, get the set of services that support custom VPC endpoint policies
            if not services_with_vpc_endpoint_policy_support:
                vpc_endpoint_services_paginator = ec2_client.get_paginator("describe_vpc_endpoint_services")
                for vpc_endpoint_services_page in vpc_endpoint_services_paginator.paginate():
                    for service_detail in vpc_endpoint_services_page["ServiceDetails"]:
                        if service_detail["VpcEndpointPolicySupported"]:
                            services_with_vpc_endpoint_policy_support.add(service_detail["ServiceName"])

            # Analyze the policy only if the underlying service supports custom VPC endpoint policies
            if endpoint["ServiceName"] in services_with_vpc_endpoint_policy_support:
                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::EC2::VPCEndpoint",
                    resource_name=endpoint["VpcEndpointId"],
                    resource_arn="arn:aws:ec2:{}:{}:vpc-endpoint/{}".format(
                        region, account_id, endpoint["VpcEndpointId"]
                    ),
                    policy_document=endpoint["PolicyDocument"],
                    policy_type="RESOURCE_POLICY",
                )
