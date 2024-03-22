def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    dynamodb_client = boto_session.client("dynamodb", config=boto_config, region_name=region)
    tables_paginator = dynamodb_client.get_paginator("list_tables")

    # Iterate all tables
    for tables_page in tables_paginator.paginate():
        for table_name in tables_page["TableNames"]:
            describe_table_response = dynamodb_client.describe_table(TableName=table_name)

            # Skip if there is no stream ARN set
            if "LatestStreamArn" not in describe_table_response["Table"]:
                continue

            # Fetch resource policy
            try:
                get_resource_policy_response = dynamodb_client.get_resource_policy(
                    ResourceArn=describe_table_response["Table"]["LatestStreamArn"]
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
                boto_session=boto_session,
                resource_type="AWS::DynamoDB::TableStream",
                resource_name=describe_table_response["Table"]["LatestStreamArn"].split("/", maxsplit=1)[1],
                resource_arn=describe_table_response["Table"]["LatestStreamArn"],
                policy_document=get_resource_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
            )
