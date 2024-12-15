RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "ec2"

# VPC endpoint types that currently do not offer policy support: GatewayLoadBalancer, Resource, ServiceNetwork
VPC_ENDPOINT_TYPES_WITH_POLICY_SUPPORT = ("Interface", "Gateway")


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ec2_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all VPC endpoint types
    for vpc_endpoint_type in VPC_ENDPOINT_TYPES_WITH_POLICY_SUPPORT:
        endpoints_paginator = ec2_client.get_paginator("describe_vpc_endpoints")

        # Iterate all VPC endpoints present
        for endpoints_page in endpoints_paginator.paginate(
            Filters=[
                {"Name": "vpc-endpoint-type", "Values": [vpc_endpoint_type]},
                {"Name": "vpc-endpoint-state", "Values": ["available", "pendingAcceptance", "pending"]},
            ]
        ):
            for endpoint in endpoints_page["VpcEndpoints"]:
                # Skip if no policy document is present or the service does not have endpoint policy support
                if "PolicyDocument" not in endpoint:
                    continue
                describe_vpc_endpoint_services_response = ec2_client.describe_vpc_endpoint_services(
                    ServiceNames=[endpoint["ServiceName"]],
                    Filters=[
                        {"Name": "service-type", "Values": [vpc_endpoint_type]},
                    ],
                )
                if not describe_vpc_endpoint_services_response["ServiceDetails"][0]["VpcEndpointPolicySupported"]:
                    continue

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
