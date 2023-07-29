def analyze(account_id, region, boto_session, boto_config, validation_function):
    s3_client = boto_session.client("s3control", config=boto_config, region_name=region)
    access_points_paginator = s3_client.get_paginator("list_access_points_for_object_lambda")

    # Iterate all S3 object Lambda access points
    for access_points_page in access_points_paginator.paginate(AccountId=account_id):
        for access_point in access_points_page["ObjectLambdaAccessPointList"]:
            # Fetch the access point policy
            try:
                get_access_point_policy_response = s3_client.get_access_point_policy_for_object_lambda(
                    AccountId=account_id, Name=access_point["Name"]
                )
            except s3_client.exceptions.from_code("NoSuchAccessPointPolicy"):
                # This access point does not have a policy configured
                continue

            # Forward policy to validation
            validation_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::S3ObjectLambda::AccessPointPolicy",
                resource_name=access_point["Name"],
                resource_arn=access_point["ObjectLambdaAccessPointArn"],
                policy_document=get_access_point_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
                policy_resource_type="AWS::S3ObjectLambda::AccessPoint",
            )
