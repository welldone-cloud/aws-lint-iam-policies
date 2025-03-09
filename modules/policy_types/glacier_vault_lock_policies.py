RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "glacier"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    glacier_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    vaults_paginator = glacier_client.get_paginator("list_vaults")

    # Iterate all vaults
    for vaults_page in vaults_paginator.paginate():
        for vault in vaults_page["VaultList"]:
            # Fetch the vault lock policy
            try:
                get_vault_lock_response = glacier_client.get_vault_lock(vaultName=vault["VaultName"])
            except glacier_client.exceptions.from_code("ResourceNotFoundException"):
                # Skip if there is no policy set
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::S3::GlacierVaultLock",
                resource_name=vault["VaultName"],
                resource_arn=vault["VaultARN"],
                policy_document=get_vault_lock_response["Policy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
