# Currently there exists only one OpsItemGroup ("default")
OPS_ITEM_GROUP_ARN_FORMAT = "arn:aws:ssm:{}:{}:opsitemgroup/default"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ssm_client = boto_session.client("ssm", config=boto_config, region_name=region)
    ops_item_group_arn = OPS_ITEM_GROUP_ARN_FORMAT.format(region, account_id)

    # Iterate resource policies of the OpsItemGroup resource
    policies_paginator = ssm_client.get_paginator("get_resource_policies")
    try:
        for policies_page in policies_paginator.paginate(ResourceArn=ops_item_group_arn):
            for policy in policies_page["Policies"]:

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    boto_session=boto_session,
                    resource_type="AWS::SSM::OpsItemGroup",
                    resource_name="default",
                    resource_arn=ops_item_group_arn,
                    policy_document=policy["Policy"],
                    policy_type="RESOURCE_POLICY",
                )

    except ssm_client.exceptions.from_code("AccessDeniedException"):
        # Regions that don't support this SSM feature unfortunately yield AccessDenied errors, making the
        # situation indistinguishable from an actual lack of permissions.
        pass
