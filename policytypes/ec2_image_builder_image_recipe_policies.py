import json


SOURCE_SERVICE = "imagebuilder"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    image_builder_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all image recipes (there is unfortunately no paginator available for this at the moment)
    call_params = {}
    while True:
        list_image_recipes_response = image_builder_client.list_image_recipes(**call_params)
        for image_recipe in list_image_recipes_response["imageRecipeSummaryList"]:

            # Fetch the image recipe policy
            get_image_recipe_policy_response = image_builder_client.get_image_recipe_policy(
                imageRecipeArn=image_recipe["arn"]
            )

            # Skip if policy is empty
            if not json.loads(get_image_recipe_policy_response["policy"]):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::ImageBuilder::ImageRecipe",
                resource_name=image_recipe["name"],
                resource_arn=image_recipe["arn"],
                policy_document=get_image_recipe_policy_response["policy"],
                policy_type="RESOURCE_POLICY",
            )

        try:
            call_params["nextToken"] = list_image_recipes_response["nextToken"]
        except KeyError:
            break
