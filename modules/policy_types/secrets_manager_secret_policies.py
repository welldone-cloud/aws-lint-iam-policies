RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "secretsmanager"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    secrets_manager_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    secrets_paginator = secrets_manager_client.get_paginator("list_secrets")

    # Iterate all Secrets manager secrets
    for secrets_page in secrets_paginator.paginate():
        for secret in secrets_page["SecretList"]:
            # Fetch the policy of the secret
            get_resource_policy_response = secrets_manager_client.get_resource_policy(SecretId=secret["Name"])

            # Skip if the secret does not have a policy configured
            if "ResourcePolicy" not in get_resource_policy_response:
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::SecretsManager::Secret",
                resource_name=secret["Name"],
                resource_arn=secret["ARN"],
                policy_document=get_resource_policy_response["ResourcePolicy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
