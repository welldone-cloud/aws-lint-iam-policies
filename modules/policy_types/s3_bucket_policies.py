RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "s3"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    s3_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    list_buckets_paginator = s3_client.get_paginator("list_buckets")

    # Iterate all buckets
    for buckets_page in list_buckets_paginator.paginate(BucketRegion=region):
        for bucket in buckets_page["Buckets"]:

            # Fetch bucket policy and skip those that do not have a bucket policy
            try:
                get_bucket_policy_response = s3_client.get_bucket_policy(Bucket=bucket["Name"])
                bucket_policy = get_bucket_policy_response["Policy"]
            except s3_client.exceptions.from_code("NoSuchBucketPolicy"):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::S3::Bucket",
                resource_name=bucket["Name"],
                resource_arn="arn:aws:s3:::{}".format(bucket["Name"]),
                policy_document=bucket_policy,
                policy_type="RESOURCE_POLICY",
            )
