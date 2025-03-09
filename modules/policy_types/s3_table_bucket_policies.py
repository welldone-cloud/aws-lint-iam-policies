RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "s3tables"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    s3_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    table_buckets_paginator = s3_client.get_paginator("list_table_buckets")

    # Iterate all table buckets
    try:
        for table_bucket_page in table_buckets_paginator.paginate():
            for table_bucket in table_bucket_page["tableBuckets"]:

                # Fetch table bucket policy
                try:
                    get_table_bucket_policy_response = s3_client.get_table_bucket_policy(
                        tableBucketARN=table_bucket["arn"]
                    )
                except s3_client.exceptions.from_code("NotFoundException"):
                    # Skip if there is no policy set
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::S3Tables::TableBucket",
                    resource_name=table_bucket["name"],
                    resource_arn=table_bucket["arn"],
                    policy_document=get_table_bucket_policy_response["resourcePolicy"],
                    access_analyzer_type="RESOURCE_POLICY",
                )

    except s3_client.exceptions.from_code("UnauthorizedException"):
        # Occurs for regions where s3tables is not available
        return
