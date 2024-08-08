RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "vpc-lattice"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    vpc_lattice_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    service_networks_paginator = vpc_lattice_client.get_paginator("list_service_networks")

    # Iterate all service networks
    try:
        for service_networks_page in service_networks_paginator.paginate():
            for service_network in service_networks_page["items"]:

                # Fetch the resource-based policy
                get_auth_policy_response = vpc_lattice_client.get_auth_policy(
                    resourceIdentifier=service_network["arn"]
                )

                # Skip if no policy is set
                if "policy" not in get_auth_policy_response:
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::VpcLattice::ServiceNetwork",
                    resource_name=service_network["name"],
                    resource_arn=service_network["arn"],
                    policy_document=get_auth_policy_response["policy"],
                    policy_type="RESOURCE_POLICY",
                )

    except vpc_lattice_client.exceptions.from_code("AccessDeniedException"):
        # Opt-in regions that don't support VPC Lattice unfortunately yield AccessDenied errors, making the
        # situation indistinguishable from an actual lack of permissions.
        pass
