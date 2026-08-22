import json

RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "signin"


def uppercase_first_letter_of_keys(obj):
    if isinstance(obj, dict):
        return {key[0].upper() + key[1:]: uppercase_first_letter_of_keys(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [uppercase_first_letter_of_keys(item) for item in obj]
    else:
        return obj


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    signin_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)
    try:
        get_signin_policy_response = signin_client.get_resource_policy()
    except signin_client.exceptions.from_code("ResourceNotFoundException"):
        # There is no resource-based policy configured
        return

    policy_document = uppercase_first_letter_of_keys(get_signin_policy_response["signinResourceBasedPolicy"])
    policy_analysis_function(
        account_id=account_id,
        region=region,
        source_service=SOURCE_SERVICE,
        resource_type="AWS::SignIn::ResourcePolicy",
        resource_name="SignInResourceBasedPolicy",
        resource_arn="arn:aws:signin:{}:{}:ResourcePolicy".format(region, account_id),
        policy_document=json.dumps(policy_document),
        access_analyzer_type="RESOURCE_POLICY",
        disabled_finding_issue_codes=["INVALID_EFFECT"],
    )
