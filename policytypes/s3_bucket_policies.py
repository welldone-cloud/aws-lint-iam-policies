S3_DEFAULT_LOCATION = "us-east-1"


def analyze(account_id, region, boto_session, boto_config, validation_function):
    s3_client = boto_session.client("s3", config=boto_config, region_name=region)
    list_buckets_response = s3_client.list_buckets()

    # Iterate all buckets
    for bucket in list_buckets_response["Buckets"]:
        bucket_name = bucket["Name"]

        # Skip those buckets that do not belong to the current region
        try:
            get_bucket_location_response = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_location = get_bucket_location_response["LocationConstraint"] or S3_DEFAULT_LOCATION
        except s3_client.exceptions.NoSuchBucket:
            continue
        if bucket_location != region:
            continue

        # Fetch bucket policy and skip those that do not have a bucket policy
        try:
            get_bucket_policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            bucket_policy = get_bucket_policy_response["Policy"]
        except s3_client.exceptions.from_code("NoSuchBucketPolicy"):
            continue

        # Forward policy to validation
        validation_function(
            account_id=account_id,
            region=region,
            boto_session=boto_session,
            resource_type="AWS::S3::BucketPolicy",
            resource_name=bucket_name,
            resource_arn="arn:aws:s3:::{}".format(bucket_name),
            policy_document=bucket_policy,
            policy_type="RESOURCE_POLICY",
            policy_resource_type="AWS::S3::Bucket",
        )
