import json

RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "bedrock"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    bedrock_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Bedrock guardrail profiles cannot be listed directly at the moment. Instead, the Bedrock guardrails
    # need to be listed, from where references to guardrail profiles can be collected.
    guardrail_profile_arns = set()
    list_guardrails_paginator = bedrock_client.get_paginator("list_guardrails")
    try:
        for guardrails_page in list_guardrails_paginator.paginate():
            for guardrail in guardrails_page["guardrails"]:
                if "crossRegionDetails" in guardrail:
                    guardrail_profile_arns.add(guardrail["crossRegionDetails"]["guardrailProfileArn"])

        # Fetch the resource policy of each guardrail profile
        for guardrail_profile_arn in guardrail_profile_arns:
            try:
                get_resource_policy_response = bedrock_client.get_resource_policy(resourceArn=guardrail_profile_arn)
            except bedrock_client.exceptions.from_code("ResourceNotFoundException"):
                continue

            # Skip empty policies
            if not json.loads(get_resource_policy_response["resourcePolicy"]):
                continue

            policy_analysis_function(
                account_id=account_id,
                region=region,
                source_service=SOURCE_SERVICE,
                resource_type="AWS::Bedrock::GuardrailProfile",
                resource_name=guardrail_profile_arn.split("/")[-1],
                resource_arn=guardrail_profile_arn,
                policy_document=get_resource_policy_response["resourcePolicy"],
                access_analyzer_type="RESOURCE_POLICY",
            )

    except bedrock_client.exceptions.from_code("AccessDeniedException") as ex:
        # Bedrock can return AccessDeniedException when the service is not available in a region. The error message
        # allows to distinguish from an actual lack of permissions.
        if "Your account is not authorized" not in ex.response["Error"].get("Message", ""):
            raise
