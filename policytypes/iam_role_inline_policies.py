import json


SERVICE_LINKED_ROLE_PATH_PREFIX = "/aws-service-role/"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    iam_client = boto_session.client("iam", config=boto_config, region_name=region)
    roles_paginator = iam_client.get_paginator("list_roles")

    # Iterate all IAM roles
    for roles_page in roles_paginator.paginate():
        for role in roles_page["Roles"]:
            # Skip service-linked roles
            if role["Path"].startswith(SERVICE_LINKED_ROLE_PATH_PREFIX):
                continue

            # Iterate all inline policies attached to a role
            policy_paginator = iam_client.get_paginator("list_role_policies")
            for policies_page in policy_paginator.paginate(RoleName=role["RoleName"]):
                for policy_name in policies_page["PolicyNames"]:
                    # Fetch the actual policy document
                    get_role_policy_response = iam_client.get_role_policy(
                        RoleName=role["RoleName"], PolicyName=policy_name
                    )

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        boto_session=boto_session,
                        resource_type="AWS::IAM::RolePolicy",
                        resource_name=policy_name,
                        resource_arn=role["Arn"],
                        policy_document=json.dumps(get_role_policy_response["PolicyDocument"]),
                        policy_type="IDENTITY_POLICY",
                    )
