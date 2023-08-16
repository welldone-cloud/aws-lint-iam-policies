def analyze(account_id, region, boto_session, boto_config, validation_function):
    lex_client = boto_session.client("lexv2-models", config=boto_config, region_name=region)

    # Iterate all bots (there is unfortunately no paginator available for this at the moment)
    call_params = {}
    while True:
        list_bots_response = lex_client.list_bots(**call_params)
        for bot in list_bots_response["botSummaries"]:
            bot_arn = "arn:aws:lex:{}:{}:bot/{}".format(region, account_id, bot["botId"])

            # Fetch the bot policy
            try:
                describe_resource_policy_response = lex_client.describe_resource_policy(resourceArn=bot_arn)
            except lex_client.exceptions.from_code("ResourceNotFoundException"):
                # Skip if there is no policy set
                continue

            # Forward policy to validation
            validation_function(
                account_id=account_id,
                region=region,
                boto_session=boto_session,
                resource_type="AWS::Lex::Bot",
                resource_name=bot["botName"],
                resource_arn=bot_arn,
                policy_document=describe_resource_policy_response["policy"],
                policy_type="RESOURCE_POLICY",
            )

        try:
            call_params["nextToken"] = list_bots_response["nextToken"]
        except KeyError:
            break
