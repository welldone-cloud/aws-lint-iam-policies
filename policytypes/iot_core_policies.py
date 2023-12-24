def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    iot_client = boto_session.client("iot", config=boto_config, region_name=region)
    policies_paginator = iot_client.get_paginator("list_policies")

    # Iterate all IoT core policies
    for policies_page in policies_paginator.paginate():
        for policy in policies_page["policies"]:
            # Fetch all policy versions
            list_policy_versions_response = iot_client.list_policy_versions(policyName=policy["policyName"])
            for policy_version in list_policy_versions_response["policyVersions"]:
                # Fetch the IAM policy of the policy version
                get_policy_version_response = iot_client.get_policy_version(
                    policyName=policy["policyName"],
                    policyVersionId=policy_version["versionId"],
                )

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    boto_session=boto_session,
                    resource_type="AWS::IoT::Policy",
                    resource_name="{}:{}".format(policy["policyName"], policy_version["versionId"]),
                    resource_arn=policy["policyArn"],
                    policy_document=get_policy_version_response["policyDocument"],
                    policy_type="IDENTITY_POLICY",
                )
