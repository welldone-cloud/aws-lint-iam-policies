import json


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    iam_client = boto_session.client("iam", config=boto_config, region_name=region)
    policies_paginator = iam_client.get_paginator("list_policies")

    # Iterate customer-managed IAM policies and forward to validation
    for policies_page in policies_paginator.paginate(Scope="Local", OnlyAttached=False):
        for policy in policies_page["Policies"]:
            get_policy_response = iam_client.get_policy_version(
                PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
            )
            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::IAM::ManagedPolicy",
                resource_name=policy["PolicyName"],
                resource_arn=policy["Arn"],
                policy_document=json.dumps(get_policy_response["PolicyVersion"]["Document"]),
                policy_type="IDENTITY_POLICY",
            )
