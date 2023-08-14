def analyze(account_id, region, boto_session, boto_config, validation_function):
    glacier_client = boto_session.client("glacier", config=boto_config, region_name=region)
    vaults_paginator = glacier_client.get_paginator("list_vaults")

    # Iterate all vaults
    for vaults_page in vaults_paginator.paginate():
        for vault in vaults_page["VaultList"]:
            # Fetch the resource policy
            try:
                get_vault_access_policy_response = glacier_client.get_vault_access_policy(vaultName=vault["VaultName"])
            except glacier_client.exceptions.from_code("ResourceNotFoundException"):
                # Skip if there is no policy set
                continue

            # Forward policy to validation
            validation_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::Glacier::ResourcePolicy",
                resource_name=vault["VaultName"],
                resource_arn=vault["VaultARN"],
                policy_document=get_vault_access_policy_response["policy"]["Policy"],
                policy_type="RESOURCE_POLICY",
            )
