RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "dynamodb"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    dynamodb_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    tables_paginator = dynamodb_client.get_paginator("list_tables")

    # Iterate all tables
    for tables_page in tables_paginator.paginate():
        for table_name in tables_page["TableNames"]:
            describe_table_response = dynamodb_client.describe_table(TableName=table_name)

            # Fetch resource policy
            try:
                get_resource_policy_response = dynamodb_client.get_resource_policy(
                    ResourceArn=describe_table_response["Table"]["TableArn"]
                )
            except (
                dynamodb_client.exceptions.from_code("PolicyNotFoundException"),
                dynamodb_client.exceptions.from_code("ResourceNotFoundException"),
            ):
                # Skip if there is no policy set
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::DynamoDB::Table",
                resource_name=table_name,
                resource_arn=describe_table_response["Table"]["TableArn"],
                policy_document=get_resource_policy_response["Policy"],
                access_analyzer_type="RESOURCE_POLICY",
            )
