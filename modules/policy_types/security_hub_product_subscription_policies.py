RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "securityhub"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    security_hub_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Collect all product subscriptions
    product_subscriptions = []
    enabled_products_paginator = security_hub_client.get_paginator("list_enabled_products_for_import")
    try:
        for enabled_products_page in enabled_products_paginator.paginate():
            for product in enabled_products_page["ProductSubscriptions"]:
                product_subscriptions.append(product.split(":product-subscription/")[1])

    # Skip if Security Hub is not enabled in this region
    except security_hub_client.exceptions.from_code("InvalidAccessException"):
        return

    # Skip if there are no product subscriptions
    if not product_subscriptions:
        return

    # Iterate all available product integrations
    describe_products_paginator = security_hub_client.get_paginator("describe_products")
    for describe_products_page in describe_products_paginator.paginate():
        for product in describe_products_page["Products"]:

            # Proceed if there is a subscription for this product
            if any(
                product["ProductArn"].endswith("product/{}".format(product_subscription))
                for product_subscription in product_subscriptions
            ):
                policy_analysis_function(
                    account_id=account_id,
                    region=region,
                    source_service=SOURCE_SERVICE,
                    resource_type="AWS::SecurityHub::ProductSubscription",
                    resource_name="{}/{}".format(product["CompanyName"], product["ProductName"]),
                    resource_arn=product["ProductArn"],
                    policy_document=product["ProductSubscriptionResourcePolicy"],
                    policy_type="RESOURCE_POLICY",
                )
