RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "bedrock-agent"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    bedrock_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    knowledge_bases_paginator = bedrock_client.get_paginator("list_knowledge_bases")

    # Iterate all knowledge bases
    try:
        for knowledge_bases_page in knowledge_bases_paginator.paginate():
            for knowledge_base in knowledge_bases_page["knowledgeBaseSummaries"]:
                knowledge_base_arn = "arn:aws:bedrock:{}:{}:knowledge-base/{}".format(
                    region,
                    account_id,
                    knowledge_base["knowledgeBaseId"],
                )

                # Fetch the resource policy
                try:
                    get_resource_policy_response = bedrock_client.get_resource_policy(resourceArn=knowledge_base_arn)
                except (
                    bedrock_client.exceptions.from_code("ResourceNotFoundException"),
                    bedrock_client.exceptions.from_code("ValidationException"),
                ):
                    # There either is no policy or it's a type of knowledge base that doesn't support resource policies
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::Bedrock::KnowledgeBase",
                    resource_name=knowledge_base["name"],
                    resource_arn=knowledge_base_arn,
                    policy_document=get_resource_policy_response["policy"],
                    access_analyzer_type="RESOURCE_POLICY",
                )

    except bedrock_client.exceptions.from_code("InternalServerErrorException") as ex:
        # Bedrock can return this error in regions where the knowledge base service is not available
        if not ex.response["Error"].get("Message", "") == "Internal server error":
            raise
