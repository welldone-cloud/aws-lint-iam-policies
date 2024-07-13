import datetime
import json
import os
import pathlib
import re
import string
import sys


RESULTS_DIRECTORY_NAME = "results"

TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"

VALID_FILE_NAME_CHARACTERS = string.ascii_letters + string.digits + "_+=,.@-"


class ResultCollector:

    def __init__(self, account_id, principal, scope, exclude_finding_issue_codes, include_finding_issue_codes):
        self._run_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(TIMESTAMP_FORMAT)
        self._exclude_finding_issue_codes = exclude_finding_issue_codes
        self._include_finding_issue_codes = include_finding_issue_codes

        # Prepare result collection JSON structure
        self._result_collection = {
            "_metadata": {
                "invocation": " ".join(sys.argv),
                "accountid": account_id,
                "principal": principal,
                "scope": scope,
                "run_timestamp": self._run_timestamp,
                "errors": [],
            },
            "results_grouped_by_account_id": {},
            "results_grouped_by_finding_category": {},
        }

        # Create results directory
        self._results_directory = os.path.join(pathlib.Path(__file__).parent.parent, RESULTS_DIRECTORY_NAME)
        try:
            os.mkdir(self._results_directory)
        except FileExistsError:
            pass

    def submit_error(self, msg):
        print(msg)
        self._result_collection["_metadata"]["errors"].append(msg.strip())

    def submit_result(self, policy_descriptor, finding_descriptor, disabled_finding_issue_codes):
        finding_issue_code = finding_descriptor["finding_issue_code"]

        # Skip if finding issue code should not be reported, either because set forth by the policy type implementation
        # or because of include or exclude arguments
        if finding_issue_code in disabled_finding_issue_codes:
            return
        if finding_issue_code in self._exclude_finding_issue_codes:
            return
        if self._include_finding_issue_codes and finding_issue_code not in self._include_finding_issue_codes:
            return

        result = {**policy_descriptor, **finding_descriptor}
        account_id = policy_descriptor["account_id"]
        finding_type = finding_descriptor["finding_type"]

        # Add to results_grouped_by_account_id
        try:
            self._result_collection["results_grouped_by_account_id"][account_id].append(result)
        except KeyError:
            self._result_collection["results_grouped_by_account_id"][account_id] = [result]

        # Add to results_grouped_by_finding_category
        try:
            self._result_collection["results_grouped_by_finding_category"][finding_type][finding_issue_code].append(
                result
            )
        except KeyError:
            if finding_type not in self._result_collection["results_grouped_by_finding_category"]:
                self._result_collection["results_grouped_by_finding_category"][finding_type] = {}
            self._result_collection["results_grouped_by_finding_category"][finding_type][finding_issue_code] = [result]

    def write_policy_dump_file(self, policy_descriptor, policy_document):
        # Ensure the policy dump directory exists
        policy_dump_directory = os.path.join(self._results_directory, "policy_dump_{}".format(self._run_timestamp))
        try:
            os.mkdir(policy_dump_directory)
        except FileExistsError:
            pass

        # Some AWS resources can have multiple policies attached or are allowed to have the same name, while using
        # different IDs. An index is thus put at the end of the file name to handle collisions.
        file_index = 0
        while True:
            policy_dump_file_name = "{}_{}_{}_{}_{}_{}.json".format(
                policy_descriptor["account_id"],
                policy_descriptor["region"],
                policy_descriptor["source_service"],
                policy_descriptor["resource_type"],
                policy_descriptor["resource_name"],
                file_index,
            )
            policy_dump_file_name = re.sub(
                "_+",
                "_",
                "".join(char if char in VALID_FILE_NAME_CHARACTERS else "_" for char in policy_dump_file_name),
            )
            policy_dump_file_path = os.path.join(policy_dump_directory, policy_dump_file_name)
            if os.path.isfile(policy_dump_file_path):
                file_index += 1
                continue
            break

        # Write policy document to file
        with open(policy_dump_file_path, "w") as out_file:
            json.dump(json.loads(policy_document), out_file, indent=2)
        return policy_dump_file_name

    def write_result_collection_file(self):
        result_collection_file = os.path.join(
            self._results_directory, "policy_linting_results_{}.json".format(self._run_timestamp)
        )
        with open(result_collection_file, "w") as out_file:
            json.dump(self._result_collection, out_file, indent=2)
