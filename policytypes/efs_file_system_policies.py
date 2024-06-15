SOURCE_SERVICE = "efs"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    efs_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    file_systems_paginator = efs_client.get_paginator("describe_file_systems")

    # Iterate all S3 object Lambda access points
    for file_systems_page in file_systems_paginator.paginate():
        for file_system in file_systems_page["FileSystems"]:
            # Fetch the file system policy
            try:
                describe_file_system_policy_response = efs_client.describe_file_system_policy(
                    FileSystemId=file_system["FileSystemId"]
                )
            except efs_client.exceptions.from_code("PolicyNotFound"):
                # This file system does not have a policy configured
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::EFS::FileSystem",
                resource_name=file_system["FileSystemId"],
                resource_arn=file_system["FileSystemArn"],
                policy_document=describe_file_system_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
