SOURCE_SERVICE = "s3control"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    s3_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all access points (there is unfortunately no paginator available for this at the moment)
    call_params = {"AccountId": account_id}
    while True:
        list_access_points_response = s3_client.list_access_points(**call_params)
        for access_point in list_access_points_response["AccessPointList"]:
            # Fetch the access point policy
            try:
                get_access_point_policy_response = s3_client.get_access_point_policy(
                    AccountId=account_id, Name=access_point["Name"]
                )
            except s3_client.exceptions.from_code("NoSuchAccessPointPolicy"):
                # This access point does not have a policy configured
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::S3::AccessPoint",
                resource_name=access_point["Name"],
                resource_arn=access_point["AccessPointArn"],
                policy_document=get_access_point_policy_response["Policy"],
                policy_type="RESOURCE_POLICY",
                policy_resource_type="AWS::S3::AccessPoint",
            )

        try:
            call_params["NextToken"] = list_access_points_response["NextToken"]
        except KeyError:
            break
