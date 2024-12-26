import boto3
import botocore.exceptions
import fnmatch
import json
import os
import pathlib

from modules.account_analyzer import AccountAnalyzer


AWS_IAM_POLICY_ARN_READ_ONLY_ACCESS = "arn:aws:iam::aws:policy/ReadOnlyAccess"

FILE_PATH_REQUIRED_IAM_PERMISSIONS = os.path.join("resources", "permissions_scope_account.json")


class OrganizationAnalyzer:

    @staticmethod
    def _create_inline_session_policy(iam_client):
        # Get the actions that the AWS ReadOnlyAccess managed IAM policy currently allows
        get_policy_response = iam_client.get_policy(PolicyArn=AWS_IAM_POLICY_ARN_READ_ONLY_ACCESS)
        get_policy_version_response = iam_client.get_policy_version(
            PolicyArn=AWS_IAM_POLICY_ARN_READ_ONLY_ACCESS, VersionId=get_policy_response["Policy"]["DefaultVersionId"]
        )
        actions_allowed_by_aws_read_only = OrganizationAnalyzer._get_actions_allowed_by_iam_policy(
            get_policy_version_response["PolicyVersion"]["Document"]
        )

        # Get the actions that the script currently requires for account analysis
        policy_file_path = os.path.join(pathlib.Path(__file__).parent.parent, FILE_PATH_REQUIRED_IAM_PERMISSIONS)
        with open(policy_file_path) as policy_file:
            actions_required_by_script = OrganizationAnalyzer._get_actions_allowed_by_iam_policy(
                json.load(policy_file)
            )

        # Determine the actions that the AWS ReadOnlyAccess managed IAM policy currently does not allow but the script
        # currently requires
        actions_for_inline_session_policy = []
        for action_required in actions_required_by_script:
            add_action = True
            for action_allowed in actions_allowed_by_aws_read_only:
                if action_required.split(":")[0].lower() == action_allowed.split(":")[0].lower():
                    if fnmatch.fnmatch(action_required, action_allowed):
                        add_action = False
                        break
            if add_action:
                actions_for_inline_session_policy.append(action_required)

        # Construct inline session policy
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": actions_for_inline_session_policy, "Resource": "*"}],
            },
            separators=(",", ":"),
        )

    @staticmethod
    def _get_actions_allowed_by_iam_policy(policy):
        actions_allowed = []
        for statement in policy["Statement"]:
            if statement["Effect"] != "Allow":
                continue
            if isinstance(statement["Action"], list):
                actions_allowed.extend(statement["Action"])
            else:
                actions_allowed.append(statement["Action"])
        return actions_allowed

    def __init__(
        self,
        organization_description,
        member_accounts_role,
        boto_session,
        boto_config,
        result_collector,
        trusted_account_ids,
        exclude_policy_types,
        include_policy_types,
        exclude_regions,
        include_regions,
        exclude_accounts,
        include_accounts,
        exclude_ous,
        include_ous,
    ):
        self._organization_id = organization_description["Organization"]["Id"]
        self._management_account_id = organization_description["Organization"]["MasterAccountId"]
        self._member_accounts_role = member_accounts_role
        self._boto_session = boto_session
        self._boto_config = boto_config
        self._result_collector = result_collector
        self._trusted_account_ids = trusted_account_ids
        self._exclude_policy_types = exclude_policy_types
        self._include_policy_types = include_policy_types
        self._exclude_regions = exclude_regions
        self._include_regions = include_regions
        self._exclude_accounts = exclude_accounts
        self._include_accounts = include_accounts
        self._exclude_ous = exclude_ous
        self._include_ous = include_ous
        self._organizations_parents = {}

    def _get_organizations_parents(self, organizations_client, child_id):
        try:
            return self._organizations_parents[child_id]
        except KeyError:
            all_parents = []
            direct_parent = organizations_client.list_parents(ChildId=child_id)["Parents"][0]
            all_parents.append(direct_parent["Id"])
            if direct_parent["Type"] != "ROOT":
                all_parents.extend(self._get_organizations_parents(organizations_client, direct_parent["Id"]))
            self._organizations_parents[child_id] = all_parents
            return all_parents

    def analyze_organization(self):
        # We only require read-only access to Organizations member accounts, even if users provide a role that has
        # more permissions. When assuming the roles, we drop permissions to read-only access by using session
        # policies. As the AWS ReadOnlyAccess managed IAM policy often lags behind with new feature releases, we need
        # to determine the set of IAM permissions that is needed in addition to ReadOnlyAccess. This set is provided
        # as an inline session policy, while ReadOnlyAccess is provided as a managed session policy.
        iam_client = self._boto_session.client("iam", config=self._boto_config)
        try:
            inline_session_policy = OrganizationAnalyzer._create_inline_session_policy(iam_client)
        except botocore.exceptions.ClientError:
            print("Insufficient permissions to communicate with the AWS IAM service")
            return

        # Iterate all accounts of the Organization
        print(
            "Analyzing organization ID {} under management account ID {}".format(
                self._organization_id, self._management_account_id
            )
        )
        organizations_client = self._boto_session.client("organizations", config=self._boto_config)
        sts_client = self._boto_session.client(
            "sts",
            config=self._boto_config,
            endpoint_url="https://sts.{}.amazonaws.com".format(self._boto_session.region_name),
        )
        accounts_paginator = organizations_client.get_paginator("list_accounts")
        for accounts_page in accounts_paginator.paginate():
            for account in accounts_page["Accounts"]:
                account_id = account["Id"]

                # Skip accounts that should not be targeted because of include or exclude arguments
                if account_id in self._exclude_accounts:
                    continue
                if self._include_accounts and account_id not in self._include_accounts:
                    continue
                if self._exclude_ous or self._include_ous:
                    organizations_parents = self._get_organizations_parents(organizations_client, account_id)
                    if self._exclude_ous and any(ou in self._exclude_ous for ou in organizations_parents):
                        continue
                    if self._include_ous and all(ou not in self._include_ous for ou in organizations_parents):
                        continue

                # Skip accounts that are not active
                if account["Status"] != "ACTIVE":
                    self._result_collector.submit_error(
                        "Error for account ID {}: account status is not active".format(account_id)
                    )
                    continue

                # Assume the provided role in the account, except for when we are currently analyzing the management
                # account itself
                if account_id == self._management_account_id:
                    account_session = self._boto_session
                else:
                    try:
                        assume_role_response = sts_client.assume_role(
                            RoleArn="arn:aws:iam::{}:role/{}".format(account_id, self._member_accounts_role),
                            RoleSessionName=self._boto_config.user_agent_appid,
                            PolicyArns=[{"arn": AWS_IAM_POLICY_ARN_READ_ONLY_ACCESS}],
                            Policy=inline_session_policy,
                        )
                    except botocore.exceptions.ClientError:
                        self._result_collector.submit_error(
                            "Error for account ID {}: cannot assume specified member accounts role".format(account_id)
                        )
                        continue
                    account_session = boto3.Session(
                        aws_access_key_id=assume_role_response["Credentials"]["AccessKeyId"],
                        aws_secret_access_key=assume_role_response["Credentials"]["SecretAccessKey"],
                        aws_session_token=assume_role_response["Credentials"]["SessionToken"],
                        region_name=self._boto_session.region_name,
                    )

                # Run account analysis
                account_analyzer = AccountAnalyzer(
                    account_id,
                    account_session,
                    self._boto_config,
                    self._result_collector,
                    self._trusted_account_ids,
                    self._exclude_policy_types,
                    self._include_policy_types,
                    self._exclude_regions,
                    self._include_regions,
                )
                account_analyzer.analyze_account()
