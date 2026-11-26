RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "s3files"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    s3_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    file_systems_paginator = s3_client.get_paginator("list_file_systems")

    # Iterate all S3 file systems
    for file_systems_page in file_systems_paginator.paginate():
        for file_system in file_systems_page["fileSystems"]:

            # Fetch the file system policy
            try:
                get_file_system_policy_response = s3_client.get_file_system_policy(
                    fileSystemId=file_system["fileSystemId"]
                )
            except s3_client.exceptions.from_code("ResourceNotFoundException"):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::S3Files::FileSystem",
                resource_name=file_system["name"],
                resource_arn=file_system["fileSystemArn"],
                policy_document=get_file_system_policy_response["policy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
