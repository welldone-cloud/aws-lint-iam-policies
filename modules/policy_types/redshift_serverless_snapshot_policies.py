RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "redshift-serverless"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    redshift_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    list_snapshots_paginator = redshift_client.get_paginator("list_snapshots")

    # Iterate all Redshift serverless snapshots
    try:
        for snapshots_page in list_snapshots_paginator.paginate():
            for snapshot in snapshots_page["snapshots"]:
                # Fetch the snapshot policy
                try:
                    get_resource_policy_response = redshift_client.get_resource_policy(
                        resourceArn=snapshot["snapshotArn"]
                    )
                except redshift_client.exceptions.from_code("ResourceNotFoundException"):
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::RedshiftServerless::Snapshot",
                    resource_name=snapshot["snapshotName"],
                    resource_arn=snapshot["snapshotArn"],
                    policy_document=get_resource_policy_response["resourcePolicy"]["policy"],
                    policy_type="RESOURCE_POLICY",
                )

    # Redshift serverless is not available in this region
    except redshift_client.exceptions.from_code("ValidationException"):
        pass
