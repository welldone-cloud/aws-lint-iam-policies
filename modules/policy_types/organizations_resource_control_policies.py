RUN_IN_REGION = "us-east-1"

SOURCE_SERVICE = "organizations"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    # Test whether RCPs are enabled and return if they are not
    organizations_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    rcps_enabled = False
    roots_paginator = organizations_client.get_paginator("list_roots")
    try:
        for roots_page in roots_paginator.paginate():
            for root_node in roots_page["Roots"]:
                for policy in root_node["PolicyTypes"]:
                    if policy["Type"] == "RESOURCE_CONTROL_POLICY" and policy["Status"] == "ENABLED":
                        rcps_enabled = True
                        break
        if not rcps_enabled:
            return

    except (
        organizations_client.exceptions.AccessDeniedException,
        organizations_client.exceptions.AWSOrganizationsNotInUseException,
    ):
        # Account is either not a management account or does not have Organizations enabled
        return

    # Iterate RCPs and forward to validation
    policy_paginator = organizations_client.get_paginator("list_policies")
    for policies_page in policy_paginator.paginate(Filter="RESOURCE_CONTROL_POLICY"):
        for policy in policies_page["Policies"]:
            if policy["AwsManaged"]:
                continue
            describe_policy_reponse = organizations_client.describe_policy(PolicyId=policy["Id"])
            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Organizations::Policy",
                resource_name=describe_policy_reponse["Policy"]["PolicySummary"]["Name"],
                resource_arn=describe_policy_reponse["Policy"]["PolicySummary"]["Arn"],
                policy_document=describe_policy_reponse["Policy"]["Content"],
                policy_type="RESOURCE_CONTROL_POLICY",
            )
