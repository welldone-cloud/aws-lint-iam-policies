RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "vpc-lattice"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    vpc_lattice_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    services_paginator = vpc_lattice_client.get_paginator("list_services")

    # Iterate all services
    try:
        for services_page in services_paginator.paginate():
            for service in services_page["items"]:

                # Fetch the resource-based policy
                get_auth_policy_response = vpc_lattice_client.get_auth_policy(resourceIdentifier=service["arn"])

                # Skip if no policy is set
                if "policy" not in get_auth_policy_response:
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::VpcLattice::Service",
                    resource_name=service["name"],
                    resource_arn=service["arn"],
                    policy_document=get_auth_policy_response["policy"],
                    access_analyzer_type="RESOURCE_POLICY",
                )

    except vpc_lattice_client.exceptions.from_code("AccessDeniedException"):
        # Opt-in regions that don't support VPC Lattice unfortunately yield AccessDenied errors, making the
        # situation indistinguishable from an actual lack of permissions.
        pass
