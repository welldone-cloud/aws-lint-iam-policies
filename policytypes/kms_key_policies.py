SOURCE_SERVICE = "kms"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    kms_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    keys_paginator = kms_client.get_paginator("list_keys")

    # Iterate all KMS keys
    for keys_page in keys_paginator.paginate():
        for key in keys_page["Keys"]:
            # Fetch key details
            describe_key_response = kms_client.describe_key(KeyId=key["KeyId"])

            # Skip AWS-managed keys
            if describe_key_response["KeyMetadata"]["KeyManager"] == "AWS":
                continue

            # Fetch the key policy
            get_key_policy_response = kms_client.get_key_policy(KeyId=key["KeyId"], PolicyName="default")

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::KMS::Key",
                resource_name=key["KeyId"],
                resource_arn=describe_key_response["KeyMetadata"]["Arn"],
                policy_document=get_key_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
