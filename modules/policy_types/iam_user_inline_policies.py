import json


RUN_IN_REGION = "us-east-1"

SOURCE_SERVICE = "iam"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    iam_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
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

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::IAM::User",
                        resource_name="{}:{}".format(user["UserName"], policy_name),
                        resource_arn=user["Arn"],
                        policy_document=json.dumps(get_user_policy_response["PolicyDocument"]),
                        policy_type="IDENTITY_POLICY",
                    )
