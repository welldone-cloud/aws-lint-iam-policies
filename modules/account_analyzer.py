import botocore.exceptions
import concurrent.futures
import traceback

import modules.policy_types

from modules.policy_analyzer import PolicyAnalyzer
from modules.policy_types import *


class AccountAnalyzer:

    def __init__(
        self,
        account_id,
        boto_session,
        boto_config,
        result_collector,
        exclude_policy_types,
        include_policy_types,
        exclude_regions,
        include_regions,
    ):
        self._account_id = account_id
        self._boto_session = boto_session
        self._boto_config = boto_config
        self._result_collector = result_collector
        self._exclude_policy_types = exclude_policy_types
        self._include_policy_types = include_policy_types
        self._exclude_regions = exclude_regions
        self._include_regions = include_regions

    def analyze_account(self):
        # Get all regions enabled in the account
        ec2_client = self._boto_session.client("ec2", config=self._boto_config)
        try:
            describe_regions_response = ec2_client.describe_regions(AllRegions=False)
        except botocore.exceptions.ClientError:
            self._result_collector.submit_error(
                "Error for account ID {}: cannot read enabled regions, skipping account".format(self._account_id)
            )
            return
        enabled_regions = sorted([region["RegionName"] for region in describe_regions_response["Regions"]])

        # Iterate all policy types and enabled regions and trigger analysis for applicable combinations that are
        # also allowed by include and exclude arguments
        print("Analyzing account ID {}".format(self._account_id))
        policy_analyzer = PolicyAnalyzer(self._boto_session, self._boto_config, self._result_collector)
        futures = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for policy_type_name in PolicyAnalyzer.get_supported_policy_type_names():
                if policy_type_name in self._exclude_policy_types:
                    continue
                if self._include_policy_types and policy_type_name not in self._include_policy_types:
                    continue

                policy_type_implementation = getattr(modules.policy_types, policy_type_name)
                for region in enabled_regions:
                    if policy_type_implementation.RUN_IN_REGION not in ("ALL", region):
                        continue
                    if region in self._exclude_regions:
                        continue
                    if self._include_regions and region not in self._include_regions:
                        continue
                    future_params = {
                        "account_id": self._account_id,
                        "region": region,
                        "boto_session": self._boto_session,
                        "boto_config": self._boto_config,
                        "policy_analysis_function": policy_analyzer.analyze_policy,
                    }
                    future = executor.submit(policy_type_implementation.analyze, **future_params)
                    future_params["policy_type_name"] = policy_type_name
                    futures[future] = future_params

            # Show status and process any errors that occurred
            futures_completed = 0
            for future in concurrent.futures.as_completed(futures.keys()):
                futures_completed += 1
                print("{}%".format(int(futures_completed * 100 / len(futures))), end="\r")

                try:
                    future.result()
                except (botocore.exceptions.EndpointConnectionError, botocore.exceptions.ConnectTimeoutError):
                    # Ignore errors when an AWS service is not available in a certain region
                    pass
                except botocore.exceptions.ClientError as ex:
                    # Log expected errors such as a lack of permissions, regions/services denied by SCPs, etc.
                    self._result_collector.submit_error(
                        "Error for account ID {}, region {}, policy type {}: {} ({})".format(
                            self._account_id,
                            futures[future]["region"],
                            futures[future]["policy_type_name"],
                            ex.response["Error"]["Code"],
                            ex.response["Error"]["Message"],
                        )
                    )
                except Exception as ex:
                    # Log all remaining and unexpected errors and print stack trace details
                    msg = "Uncaught exception for account ID {}, region {}, policy type {}: {}. "
                    msg += "Please report this as an issue along with the stack trace information."
                    self._result_collector.submit_error(
                        msg.format(
                            self._account_id,
                            futures[future]["region"],
                            futures[future]["policy_type_name"],
                            ex.__class__.__name__,
                        )
                    )
                    print(traceback.format_exc())
