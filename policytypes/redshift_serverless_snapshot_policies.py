def analyze(account_id, region, boto_session, boto_config, validation_function):
    redshift_client = boto_session.client("redshift-serverless", config=boto_config, region_name=region)
    list_snapshots_paginator = redshift_client.get_paginator("list_snapshots")

    # Iterate all Redshift serverless snapshots
    for snapshots_page in list_snapshots_paginator.paginate():
        for snapshot in snapshots_page["snapshots"]:
            # Fetch the snapshot policy
            try:
                get_resource_policy_response = redshift_client.get_resource_policy(resourceArn=snapshot["snapshotArn"])
            except redshift_client.exceptions.from_code("ResourceNotFoundException"):
                continue

            # Forward policy to validation
            validation_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::RedshiftServerless::Snapshot",
                resource_name=snapshot["snapshotName"],
                resource_arn=snapshot["snapshotArn"],
                policy_document=get_resource_policy_response["resourcePolicy"]["policy"],
                policy_type="RESOURCE_POLICY",
            )
