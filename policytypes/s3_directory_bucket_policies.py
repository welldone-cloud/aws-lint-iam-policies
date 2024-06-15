SOURCE_SERVICE = "s3"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    s3_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    directory_buckets_paginator = s3_client.get_paginator("list_directory_buckets")

    # Iterate all directory buckets
    for directory_buckets_page in directory_buckets_paginator.paginate():
        for bucket in directory_buckets_page["Buckets"]:
            bucket_name = bucket["Name"]

            # Fetch bucket policy and skip those that do not have a bucket policy
            try:
                get_bucket_policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                bucket_policy = get_bucket_policy_response["Policy"]
            except s3_client.exceptions.from_code("NoSuchBucketPolicy"):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::S3Express::DirectoryBucket",
                resource_name=bucket_name,
                resource_arn="arn:aws:s3express:{}:{}:bucket/{}".format(region, account_id, bucket_name),
                policy_document=bucket_policy,
                policy_type="RESOURCE_POLICY",
                policy_resource_type="AWS::S3::Bucket",
            )
