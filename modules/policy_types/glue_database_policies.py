RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "glue"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    glue_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    databases_paginator = glue_client.get_paginator("get_databases")

    # Iterate all databases
    for databases_page in databases_paginator.paginate():
        for database in databases_page["DatabaseList"]:
            database_arn = "arn:aws:glue:{}:{}:database/{}".format(region, account_id, database["Name"])

            # Fetch the resource policy
            try:
                get_resource_policy_response = glue_client.get_resource_policy(ResourceArn=database_arn)
            except glue_client.exceptions.from_code("EntityNotFoundException"):
                # Skip if there is no policy set
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Glue::Database",
                resource_name=database["Name"],
                resource_arn=database_arn,
                policy_document=get_resource_policy_response["PolicyInJson"],
                access_analyzer_type="RESOURCE_POLICY",
            )
