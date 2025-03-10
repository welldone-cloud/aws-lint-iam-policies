RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "cloudtrail"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    cloudtrail_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all channels (there is unfortunately no paginator available for this at the moment)
    call_params = {}
    while True:
        list_channels_response = cloudtrail_client.list_channels(**call_params)
        for channel in list_channels_response["Channels"]:
            # Fetch the channel policy
            try:
                get_resource_policy_response = cloudtrail_client.get_resource_policy(ResourceArn=channel["ChannelArn"])
            except (
                cloudtrail_client.exceptions.from_code("ResourcePolicyNotFoundException"),
                cloudtrail_client.exceptions.from_code("ResourceTypeNotSupportedException"),
            ):
                # Skip if there is no policy set
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::CloudTrail::Channel",
                resource_name=channel["Name"],
                resource_arn=channel["ChannelArn"],
                policy_document=get_resource_policy_response["ResourcePolicy"],
                access_analyzer_type="RESOURCE_POLICY",
            )

        try:
            call_params["NextToken"] = list_channels_response["NextToken"]
        except KeyError:
            break
