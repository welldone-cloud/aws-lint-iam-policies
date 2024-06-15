SOURCE_SERVICE = "backup"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    backup_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    vaults_paginator = backup_client.get_paginator("list_backup_vaults")

    # Iterate all backup vaults
    for vaults_page in vaults_paginator.paginate():
        for backup_vault in vaults_page["BackupVaultList"]:
            # Fetch the backup vault policy
            try:
                get_backup_vault_access_policy_response = backup_client.get_backup_vault_access_policy(
                    BackupVaultName=backup_vault["BackupVaultName"]
                )
            except backup_client.exceptions.from_code("ResourceNotFoundException"):
                # This backup vault does not have a policy configured
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Backup::BackupVault",
                resource_name=backup_vault["BackupVaultName"],
                resource_arn=backup_vault["BackupVaultArn"],
                policy_document=get_backup_vault_access_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
