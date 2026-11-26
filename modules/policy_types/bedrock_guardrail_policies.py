import json

RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "bedrock"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    bedrock_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    list_guardrails_paginator = bedrock_client.get_paginator("list_guardrails")

    # Iterate all guardrails
    try:
        for guardrails_page in list_guardrails_paginator.paginate():
            for guardrail in guardrails_page["guardrails"]:

                # Fetch the resource policy
                try:
                    get_resource_policy_response = bedrock_client.get_resource_policy(resourceArn=guardrail["arn"])
                except bedrock_client.exceptions.from_code("ResourceNotFoundException"):
                    continue

                # The API can return a string with an empty dict as the policy
                if not json.loads(get_resource_policy_response["resourcePolicy"]):
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::Bedrock::Guardrail",
                    resource_name=guardrail["name"],
                    resource_arn=guardrail["arn"],
                    policy_document=get_resource_policy_response["resourcePolicy"],
                    access_analyzer_type="RESOURCE_POLICY",
                )

    except bedrock_client.exceptions.from_code("AccessDeniedException") as ex:
        # Bedrock unfortunately returns AccessDeniedException when the service is not available in a region.
        # However, the error message is different from an actual lack of permissions.
        if "Your account is not authorized" not in ex.response["Error"].get("Message", ""):
            raise
