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

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::IAM::Role",
                resource_name=role["RoleName"],
                resource_arn=role["Arn"],
                policy_document=json.dumps(role["AssumeRolePolicyDocument"]),
                policy_type="RESOURCE_POLICY",
                policy_resource_type="AWS::IAM::AssumeRolePolicyDocument",
            )
