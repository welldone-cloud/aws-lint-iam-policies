RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "lexv2-models"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    lex_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all bots (there is unfortunately no paginator available for this at the moment)
    call_params_list_bots = {}
    while True:
        list_bots_response = lex_client.list_bots(**call_params_list_bots)
        for bot in list_bots_response["botSummaries"]:
            # Iterate all aliases of this bot (there is unfortunately no paginator available for this at the moment)
            call_params_list_bot_aliases = {"botId": bot["botId"]}
            while True:
                list_bot_aliases_response = lex_client.list_bot_aliases(**call_params_list_bot_aliases)
                for bot_alias in list_bot_aliases_response["botAliasSummaries"]:
                    bot_alias_arn = "arn:aws:lex:{}:{}:bot-alias/{}/{}".format(
                        region, account_id, bot["botId"], bot_alias["botAliasId"]
                    )

                    # Fetch the bot alias policy
                    try:
                        describe_resource_policy_response = lex_client.describe_resource_policy(
                            resourceArn=bot_alias_arn
                        )
                    except lex_client.exceptions.from_code("ResourceNotFoundException"):
                        # Skip if there is no policy set
                        continue

                    policy_analysis_function(
                        account_id=account_id,
                        region=region,
                        source_service=SOURCE_SERVICE,
                        resource_type="AWS::Lex::BotAlias",
                        resource_name=bot_alias["botAliasName"],
                        resource_arn=bot_alias_arn,
                        policy_document=describe_resource_policy_response["policy"],
                        policy_type="RESOURCE_POLICY",
                    )

                try:
                    call_params_list_bot_aliases["nextToken"] = list_bot_aliases_response["nextToken"]
                except KeyError:
                    break

        try:
            call_params_list_bots["nextToken"] = list_bots_response["nextToken"]
        except KeyError:
            break
