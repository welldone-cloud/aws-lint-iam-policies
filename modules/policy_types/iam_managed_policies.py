import json


RUN_IN_REGION = "us-east-1"

SOURCE_SERVICE = "iam"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    iam_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    policies_paginator = iam_client.get_paginator("list_policies")

    # Iterate customer-managed IAM policies
    for policies_page in policies_paginator.paginate(Scope="Local", OnlyAttached=False):
        for policy in policies_page["Policies"]:
            # Iterate all versions of the policy
            policy_versions_paginator = iam_client.get_paginator("list_policy_versions")
            for policy_versions_page in policy_versions_paginator.paginate(PolicyArn=policy["Arn"]):
                for policy_version in policy_versions_page["Versions"]:
                    # Fetch the actual policy document
                    get_policy_response = iam_client.get_policy_version(
                        PolicyArn=policy["Arn"], VersionId=policy_version["VersionId"]
                    )

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::IAM::ManagedPolicy",
                        resource_name="{}:{}".format(policy["PolicyName"], policy_version["VersionId"]),
                        resource_arn=policy["Arn"],
                        policy_document=json.dumps(get_policy_response["PolicyVersion"]["Document"]),
                        access_analyzer_type="IDENTITY_POLICY",
                    )
