import modules.policy_types._ram_based_policies as ram_based_policies


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "ram"

RAM_RESOURCE_TYPE = "ec2:SecurityGroup"

CFN_RESOURCE_TYPE = "AWS::EC2::SecurityGroup"

ARN_TO_NAME_SPLIT_CHAR = "/"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    ram_based_policies.analyze(
        account_id,
        region,
        boto_session,
        boto_config,
        policy_analysis_function,
        RAM_RESOURCE_TYPE,
        CFN_RESOURCE_TYPE,
        ARN_TO_NAME_SPLIT_CHAR,
    )
