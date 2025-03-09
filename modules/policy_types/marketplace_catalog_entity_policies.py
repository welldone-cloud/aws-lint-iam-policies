import json

ENTITY_TYPES = (
    "AmiProduct",
    "ContainerProduct",
    "DataProduct",
    "SaaSProduct",
    "ProcurementPolicy",
    "Experience",
    "Audience",
    "BrandingSettings",
    "Offer",
    "Seller",
    "ResaleAuthorization",
)

RUN_IN_REGION = "us-east-1"

SOURCE_SERVICE = "marketplace-catalog"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    marketplace_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    entities_paginator = marketplace_client.get_paginator("list_entities")

    # Iterate all Marketplace entities
    for entity_type in ENTITY_TYPES:
        for entities_page in entities_paginator.paginate(Catalog="AWSMarketplace", EntityType=entity_type):
            for entity in entities_page["EntitySummaryList"]:

                # Fetch the entity policy
                get_resource_policy_response = marketplace_client.get_resource_policy(ResourceArn=entity["EntityArn"])
                policy = get_resource_policy_response["Policy"]

                # Skip if policy is empty
                if not json.loads(policy):
                    continue

                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::Marketplace::Entity",
                    resource_name="{}/{}".format(entity["EntityType"], entity["Name"]),
                    resource_arn=entity["EntityArn"],
                    policy_document=policy,
                    access_analyzer_type="RESOURCE_POLICY",
                )
