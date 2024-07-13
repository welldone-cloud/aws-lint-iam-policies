import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "imagebuilder"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    image_builder_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all components (there is unfortunately no paginator available for this at the moment)
    call_params_list_components = {}
    while True:
        list_components_response = image_builder_client.list_components(**call_params_list_components)
        for component in list_components_response["componentVersionList"]:

            # Iterate all component build versions (there is unfortunately no paginator available for this at the moment)
            call_params_list_component_build_versions = {"componentVersionArn": component["arn"]}
            while True:
                list_component_build_versions_response = image_builder_client.list_component_build_versions(
                    **call_params_list_component_build_versions
                )
                for component_build_version in list_component_build_versions_response["componentSummaryList"]:
                    # Fetch the component policy
                    get_component_policy_response = image_builder_client.get_component_policy(
                        componentArn=component_build_version["arn"]
                    )

                    # Skip if policy is empty
                    if not json.loads(get_component_policy_response["policy"]):
                        continue

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::ImageBuilder::Component",
                        resource_name=component_build_version["name"],
                        resource_arn=component_build_version["arn"],
                        policy_document=get_component_policy_response["policy"],
                        policy_type="RESOURCE_POLICY",
                    )

                try:
                    call_params_list_component_build_versions["nextToken"] = list_component_build_versions_response[
                        "nextToken"
                    ]
                except KeyError:
                    break

        try:
            call_params_list_components["nextToken"] = list_components_response["nextToken"]
        except KeyError:
            break
