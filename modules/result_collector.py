import datetime
import json
import os
import pathlib
import re
import shutil
import string
import sys


RESULTS_DIRECTORY_NAME = "results"

RESULT_FILE_NAME = "results_{}.json"

POLICY_DUMP_DIRECTORY_NAME = "policy_dump_{}"

TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"

VALID_FILE_NAME_CHARACTERS = string.ascii_letters + string.digits + "_+=,.@-"


class ResultCollector:

    def __init__(
        self, account_id, principal, scope, exclude_finding_issue_codes, include_finding_issue_codes, result_name
    ):
        self._exclude_finding_issue_codes = exclude_finding_issue_codes
        self._include_finding_issue_codes = include_finding_issue_codes
        run_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(TIMESTAMP_FORMAT)
        result_name = result_name if result_name else run_timestamp

        # Ensure the results directory exists
        results_directory = os.path.join(pathlib.Path(__file__).parent.parent, RESULTS_DIRECTORY_NAME)
        try:
            os.mkdir(results_directory)
        except FileExistsError:
            pass

        # If a result file with the same name already exists, remove it
        self._result_file = os.path.join(results_directory, RESULT_FILE_NAME.format(result_name))
        try:
            os.remove(self._result_file)
        except FileNotFoundError:
            pass

        # Create the policy dump directory or replace it, if it already exists
        self._policy_dump_directory = os.path.join(results_directory, POLICY_DUMP_DIRECTORY_NAME.format(result_name))
        try:
            os.mkdir(self._policy_dump_directory)
        except FileExistsError:
            shutil.rmtree(self._policy_dump_directory)
            os.mkdir(self._policy_dump_directory)

        # Prepare the result collection JSON structure
        self._result_collection = {
            "_metadata": {
                "invocation": " ".join(sys.argv),
                "accountid": account_id,
                "principal": principal,
                "scope": scope,
                "run_timestamp": run_timestamp,
                "stats": {
                    "number_of_policies_analyzed": 0,
                    "number_of_results_collected": 0,
                },
                "errors": [],
            },
            "results": {},
        }

    def submit_error(self, msg):
        print(msg)
        self._result_collection["_metadata"]["errors"].append(msg.strip())

    def submit_policy(self, policy_descriptor, policy_document):
        self._result_collection["_metadata"]["stats"]["number_of_policies_analyzed"] += 1

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
            policy_dump_file = os.path.join(self._policy_dump_directory, policy_dump_file_name)
            if os.path.isfile(policy_dump_file):
                file_index += 1
                continue
            break

        # Write policy document to file
        with open(policy_dump_file, "w") as out_file:
            json.dump(json.loads(policy_document), out_file, indent=2)
        return policy_dump_file_name

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
        finding_type = finding_descriptor["finding_type"]
        self._result_collection["_metadata"]["stats"]["number_of_results_collected"] += 1

        # Add to results
        try:
            self._result_collection["results"][finding_type][finding_issue_code].append(result)
        except KeyError:
            if finding_type not in self._result_collection["results"]:
                self._result_collection["results"][finding_type] = {}
            self._result_collection["results"][finding_type][finding_issue_code] = [result]

    def write_result_file(self):
        with open(self._result_file, "w") as out_file:
            json.dump(self._result_collection, out_file, indent=2)
