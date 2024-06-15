SOURCE_SERVICE = "s3control"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    s3_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all multi-region access points (there is unfortunately no paginator available for this at the moment)
    call_params = {"AccountId": account_id}
    while True:
        list_multi_region_access_points_response = s3_client.list_multi_region_access_points(**call_params)
        for access_point in list_multi_region_access_points_response["AccessPoints"]:
            # Fetch the access point policy
            get_multi_region_access_point_policy_response = s3_client.get_multi_region_access_point_policy(
                AccountId=account_id, Name=access_point["Name"]
            )
            access_point_policy = get_multi_region_access_point_policy_response["Policy"]["Established"]["Policy"]

            # Skip validation if there is no access point policy set
            if not access_point_policy:
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::S3::MultiRegionAccessPoint",
                resource_name=access_point["Name"],
                resource_arn="arn:aws:s3::{}:accesspoint/{}".format(account_id, access_point["Alias"]),
                policy_document=access_point_policy,
                policy_type="RESOURCE_POLICY",
                policy_resource_type="AWS::S3::MultiRegionAccessPoint",
            )

        try:
            call_params["NextToken"] = list_multi_region_access_points_response["NextToken"]
        except KeyError:
            break
