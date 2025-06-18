RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "cloudtrail"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    cloudtrail_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all dashboards (there is unfortunately no paginator available for this at the moment)
    call_params = {"Type": "CUSTOM"}
    while True:
        list_dashboards_response = cloudtrail_client.list_dashboards(**call_params)
        for dashboard in list_dashboards_response["Dashboards"]:
            # Fetch the dashboard policy
            try:
                get_resource_policy_response = cloudtrail_client.get_resource_policy(
                    ResourceArn=dashboard["DashboardArn"]
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
                resource_type="AWS::CloudTrail::Dashboard",
                resource_name=dashboard["DashboardArn"].split("/")[-1],
                resource_arn=dashboard["DashboardArn"],
                policy_document=get_resource_policy_response["ResourcePolicy"],
                access_analyzer_type="RESOURCE_POLICY",
            )

        try:
            call_params["NextToken"] = list_dashboards_response["NextToken"]
        except KeyError:
            break
