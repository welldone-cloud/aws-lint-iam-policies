RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "s3outposts"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    s3_outposts_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    s3_control_client = boto_session.client("s3control", config=boto_config, region_name=region)

    # Iterate all Outposts with S3
    outposts_with_s3_paginator = s3_outposts_client.get_paginator("list_outposts_with_s3")
    for outposts_page in outposts_with_s3_paginator.paginate():
        for outpost in outposts_page["Outposts"]:

            # Iterate all buckets available on the Outpost (there is unfortunately no paginator available for this
            # at the moment)
            call_params_list_regional_buckets = {"AccountId": account_id, "OutpostId": outpost["OutpostId"]}
            while True:
                list_regional_buckets_response = s3_control_client.list_regional_buckets(
                    **call_params_list_regional_buckets
                )
                for bucket in list_regional_buckets_response["RegionalBucketList"]:

                    # Iterate all access points for the bucket (there is unfortunately no paginator available for
                    # this at the moment)
                    call_params_list_access_points = {"AccountId": account_id, "Bucket": bucket["BucketArn"]}
                    while True:
                        list_access_points_response = s3_control_client.list_access_points(
                            **call_params_list_access_points
                        )
                        for access_point in list_access_points_response["AccessPointList"]:

                            # Fetch the access point policy
                            try:
                                get_access_point_policy_response = s3_control_client.get_access_point_policy(
                                    AccountId=account_id, Name=access_point["AccessPointArn"]
                                )
                            except s3_control_client.exceptions.from_code("NoSuchAccessPointPolicy"):
                                # This access point does not have a policy configured
                                continue

                            policy_analysis_function(
                                account_id=account_id,
                                region=region,
                                source_service=SOURCE_SERVICE,
                                resource_type="AWS::S3Outposts::AccessPoint",
                                resource_name=access_point["Name"],
                                resource_arn=access_point["AccessPointArn"],
                                policy_document=get_access_point_policy_response["Policy"],
                                policy_type="RESOURCE_POLICY",
                            )

                        try:
                            call_params_list_access_points["NextToken"] = list_access_points_response["NextToken"]
                        except KeyError:
                            break

                try:
                    call_params_list_regional_buckets["NextToken"] = list_regional_buckets_response["NextToken"]
                except KeyError:
                    break
