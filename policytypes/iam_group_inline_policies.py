import json


def analyze(account_id, region, boto_session, boto_config, validation_function):
    iam_client = boto_session.client("iam", config=boto_config, region_name=region)
    groups_paginator = iam_client.get_paginator("list_groups")

    # Iterate all IAM groups
    for groups_page in groups_paginator.paginate():
        for group in groups_page["Groups"]:
            # Iterate all inline policies attached to a group
            policy_paginator = iam_client.get_paginator("list_group_policies")
            for policies_page in policy_paginator.paginate(GroupName=group["GroupName"]):
                for policy_name in policies_page["PolicyNames"]:
                    # Fetch the actual policy document
                    get_group_policy_response = iam_client.get_group_policy(
                        GroupName=group["GroupName"], PolicyName=policy_name
                    )

                    # Forward policy to validation
                    validation_function(
                        account_id=account_id,
                        region=region,
                        boto_session=boto_session,
                        resource_type="AWS::IAM::GroupPolicy",
                        resource_name=policy_name,
                        resource_arn=group["Arn"],
                        policy_document=json.dumps(get_group_policy_response["PolicyDocument"]),
                        policy_type="IDENTITY_POLICY",
                    )