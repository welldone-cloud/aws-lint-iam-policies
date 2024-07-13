import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "imagebuilder"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    image_builder_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all images (there is unfortunately no paginator available for this at the moment)
    call_params_list_images = {"includeDeprecated": True}
    while True:
        list_images_response = image_builder_client.list_images(**call_params_list_images)
        for image in list_images_response["imageVersionList"]:

            # Iterate all image build versions (there is unfortunately no paginator available for this at the moment)
            call_params_list_image_build_versions = {"imageVersionArn": image["arn"]}
            while True:
                list_image_build_versions_response = image_builder_client.list_image_build_versions(
                    **call_params_list_image_build_versions
                )
                for image_build_version in list_image_build_versions_response["imageSummaryList"]:
                    # Fetch the image policy
                    get_image_policy_response = image_builder_client.get_image_policy(
                        imageArn=image_build_version["arn"]
                    )

                    # Skip if policy is empty
                    if not json.loads(get_image_policy_response["policy"]):
                        continue

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::ImageBuilder::Image",
                        resource_name=image_build_version["name"],
                        resource_arn=image_build_version["arn"],
                        policy_document=get_image_policy_response["policy"],
                        policy_type="RESOURCE_POLICY",
                    )

                try:
                    call_params_list_image_build_versions["nextToken"] = list_image_build_versions_response[
                        "nextToken"
                    ]
                except KeyError:
                    break

        try:
            call_params_list_images["nextToken"] = list_images_response["nextToken"]
        except KeyError:
            break
