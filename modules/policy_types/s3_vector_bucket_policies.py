RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "s3vectors"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    s3_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    vector_buckets_paginator = s3_client.get_paginator("list_vector_buckets")

    # Iterate all vector buckets
    try:
        for vector_bucket_page in vector_buckets_paginator.paginate():
            for vector_bucket in vector_bucket_page["vectorBuckets"]:

                # Fetch the vector bucket policy
                try:
                    get_vector_bucket_policy_response = s3_client.get_vector_bucket_policy(
                        vectorBucketArn=vector_bucket["vectorBucketArn"]
                    )
                except s3_client.exceptions.from_code("NotFoundException"):
                    # Skip if there is no policy set
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::S3Vectors::VectorBucket",
                    resource_name=vector_bucket["vectorBucketName"],
                    resource_arn=vector_bucket["vectorBucketArn"],
                    policy_document=get_vector_bucket_policy_response["policy"],
                    access_analyzer_type="RESOURCE_POLICY",
                )

    except s3_client.exceptions.from_code("AccessDeniedException") as ex:
        # When S3 vector buckets are not available in a region, it will raise an AccessDenied exception. However,
        # the error message will be different compared to when a caller is actually lacking permissions. Ignore cases
        # where the feature is not available.
        if ex.response["Error"]["Message"].strip() == "Access Denied":
            return
        raise ex
