import json


RUN_IN_REGION = "ALL"

SOURCE_SERVICE = "sso-admin"


def analyze(account_id, region, boto_session, boto_config, policy_analysis_function):
    sso_client = boto_session.client(SOURCE_SERVICE, config=boto_config, region_name=region)

    # Iterate all SSO instances
    instances_paginator = sso_client.get_paginator("list_instances")
    for instances_page in instances_paginator.paginate():
        for instance in instances_page["Instances"]:

            # Skip if this instance lives in a different AWS account, which happens when having SSO set up in the
            # Organizations management account, but running this script in an Organizations member account.
            if instance["OwnerAccountId"] != account_id:
                continue

            # Iterate all applications of the instance
            applications_paginator = sso_client.get_paginator("list_applications")
            for applications_page in applications_paginator.paginate(InstanceArn=instance["InstanceArn"]):
                for application in applications_page["Applications"]:

                    # Skip if application is not associated with the account analyzed
                    if "ApplicationAccount" in application and application["ApplicationAccount"] != account_id:
                        continue

                    # Iterate all application authentication methods
                    try:
                        authentication_methods_paginator = sso_client.get_paginator(
                            "list_application_authentication_methods"
                        )
                        for authentication_methods_page in authentication_methods_paginator.paginate(
                            ApplicationArn=application["ApplicationArn"]
                        ):
                            for authentication_method in authentication_methods_page["AuthenticationMethods"]:

                                # Skip if the authentication method is not IAM
                                if authentication_method["AuthenticationMethodType"] != "IAM":
                                    continue

                                policy = json.dumps(
                                    authentication_method["AuthenticationMethod"]["Iam"]["ActorPolicy"]
                                )

                                policy_analysis_function(
                                    account_id=account_id,
                                    region=region,
                                    source_service=SOURCE_SERVICE,
                                    resource_type="AWS::SSO::Application",
                                    resource_name=application["Name"],
                                    resource_arn=application["ApplicationArn"],
                                    policy_document=policy,
                                    access_analyzer_type="RESOURCE_POLICY",
                                    disabled_finding_issue_codes=["MISSING_RESOURCE", "INVALID_ACTION"],
                                )

                    except sso_client.exceptions.from_code("ValidationException"):
                        # Skip if an application does not support authentication methods
                        continue
