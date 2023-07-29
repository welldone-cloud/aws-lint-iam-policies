import json


def analyze(account_id, region, boto_session, boto_config, validation_function):
    iam_client = boto_session.client("iam", config=boto_config, region_name=region)
    users_paginator = iam_client.get_paginator("list_users")

    # Iterate all IAM users
    for users_page in users_paginator.paginate():
        for user in users_page["Users"]:
            # Iterate all inline policies attached to a user
            policy_paginator = iam_client.get_paginator("list_user_policies")
            for policies_page in policy_paginator.paginate(UserName=user["UserName"]):
                for policy_name in policies_page["PolicyNames"]:
                    # Fetch the actual policy document
                    get_user_policy_response = iam_client.get_user_policy(
                        UserName=user["UserName"], PolicyName=policy_name
                    )

                    # Forward policy to validation
                    validation_function(
                        account_id=account_id,
                        region=region,
                        boto_session=boto_session,
                        resource_type="AWS::IAM::UserPolicy",
                        resource_name=policy_name,
                        resource_arn=user["Arn"],
                        policy_document=json.dumps(get_user_policy_response["PolicyDocument"]),
                        policy_type="IDENTITY_POLICY",
                    )
