RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "cloudtrail"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    cloudtrail_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all event data stores (there is unfortunately no paginator available for this at the moment)
    call_params = {}
    while True:
        try:
            list_event_data_stores_response = cloudtrail_client.list_event_data_stores(**call_params)
        except cloudtrail_client.exceptions.from_code("UnsupportedOperationException"):
            # This region does not support event data stores
            break

        for event_data_store in list_event_data_stores_response["EventDataStores"]:
            # Fetch the event data store policy
            try:
                get_resource_policy_response = cloudtrail_client.get_resource_policy(
                    ResourceArn=event_data_store["EventDataStoreArn"]
                )
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
                resource_type="AWS::CloudTrail::EventDataStore",
                resource_name=event_data_store["Name"],
                resource_arn=event_data_store["EventDataStoreArn"],
                policy_document=get_resource_policy_response["ResourcePolicy"],
                access_analyzer_type="RESOURCE_POLICY",
            )

        try:
            call_params["NextToken"] = list_event_data_stores_response["NextToken"]
        except KeyError:
            break
