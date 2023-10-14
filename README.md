# aws-lint-iam-policies

Runs IAM policy linting checks against either a single AWS account or all accounts of an AWS Organization. Reports on policies that violate security best practices or contain errors. Supports both identity-based and resource-based policies. See the accompanying blog post 
[here](https://medium.com/@michael.kirchner/linting-aws-iam-policies-e76b95859c93).

The actual linting is performed by the [AWS IAM Access Analyzer policy validation feature](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html), which is mostly known for showing recommendations when manually editing IAM policies on the AWS Console UI:

![](./doc/access_analyzer_console.png)

The linting checks are created and maintained by AWS and are described closer [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html).



## Usage

Make sure you have AWS credentials configured for your targeted environment. This can either be done using [environment 
variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html) or by specifying a [named 
profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) in the optional `--profile` 
argument.

* If your are using `--scope ACCOUNT`, you require at least [these permissions](doc/permissions_scope_account.json). 

* If you are using `--scope ORGANIZATION`, you must use credentials that belong to the Organizations management account and have at least [these permissions](doc/permissions_scope_organization.json) (take care to adapt the IAM role name). The Organizations member accounts need to have an IAM role configured that can be assumed from the Organizations management account. In many cases, there is the default `OrganizationAccountAccessRole` available. If you are instead using custom roles within the Organizations member accounts, they require at least [these permissions](doc/permissions_scope_account.json). 



#### Example invocations:

```bash
pip install -r requirements.txt

python aws_lint_iam_policies.py --scope ACCOUNT

python aws_lint_iam_policies.py --scope ORGANIZATION --member-accounts-role OrganizationAccountAccessRole

python aws_lint_iam_policies.py --scope ORGANIZATION --member-accounts-role OrganizationAccountAccessRole --exclude-accounts 112233445566,998877665544 --exclude-ous ou-lodr-r0rbg49t --exclude-policy-types lambda_function_policies
```



## Supported policy types
The following IAM policy types are analyzed. A list of all AWS services that currently offer support for resource-based policies can be found [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html).

* ACM private CA policies
* API Gateway REST API policies
* Backup vault policies
* CloudTrail channel policies
* CloudWatch Logs destination policies
* CloudWatch Logs resource policies
* CodeArtifact domain policies
* CodeArtifact repository policies
* CodeBuild build project policies
* CodeBuild report group policies
* ECR private registry policies
* ECR private repository policies
* ECR public repository policies
* EFS file system policies
* Elemental MediaStore container policies
* EventBridge event bus policies
* EventBridge schema registry policies
* Glacier vault lock policies
* Glacier vault resource policies
* Glue data catalog policies
* IAM group inline policies
* IAM managed policies
* IAM role inline policies
* IAM role trust policies
* IAM user inline policies
* KMS key policies
* Lambda function policies
* Lambda layer policies
* Lex bot alias policies
* Lex bot policies
* Migration Hub Refactor Spaces environment policies
* OpenSearch domain policies
* Organizations delegation policies
* Organizations service control policies
* Redshift serverless snapshot policies
* Rekognition custom labels project policies
* S3 access point policies
* S3 bucket policies
* S3 multi-region access point policies
* S3 object Lambda access point policies
* Secrets manager secret policies
* SES authorization policies
* SNS topic policies
* SQS queue policies
* SSM Incident Manager contact policies
* SSM Incident Manager response plan policies
* VPC endpoint policies



## Example output file

Results are written to a JSON output file. Findings are grouped once by account ID and once by finding category. This means that one specific finding is present twice in the result file.

```json
{
  "_metadata": {
    "invocation": "aws_lint_iam_policies.py --scope ACCOUNT",
    "principal": "arn:aws:iam::123456789012:user/user1",
    "run_timestamp": "20230729093927",
    "scope": "ACCOUNT",
    "errors": [],
    "account_id": "123456789012"
  },
  "results_grouped_by_account_id": {
    "123456789012": [
      {
        "account_id": "123456789012",
        "region": "us-east-1",
        "resource_type": "AWS::IAM::UserPolicy",
        "resource_name": "inlinepolicy",
        "resource_arn": "arn:aws:iam::123456789012:user/user1",
        "policy_type": "IDENTITY_POLICY",
        "finding_type": "SECURITY_WARNING",
        "finding_issue_code": "PASS_ROLE_WITH_STAR_IN_RESOURCE",
        "finding_description": "Using the iam:PassRole action with wildcards (*) in the resource can be overly permissive because it allows iam:PassRole permissions on multiple resources. We recommend that you specify resource ARNs or add the iam:PassedToService condition key to your statement.",
        "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#access-analyzer-reference-policy-checks-security-warning-pass-role-with-star-in-resource"
      },
      {
        "account_id": "123456789012",
        "region": "eu-central-1",
        "resource_type": "AWS::SQS::QueuePolicy",
        "resource_name": "queue1",
        "resource_arn": "arn:aws:sqs:eu-central-1:123456789012:queue1",
        "policy_type": "RESOURCE_POLICY",
        "finding_type": "WARNING",
        "finding_issue_code": "MISSING_VERSION",
        "finding_description": "We recommend that you specify the Version element to help you with debugging permission issues.",
        "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#access-analyzer-reference-policy-checks-general-warning-missing-version"
      }
    ]
  },
  "results_grouped_by_finding_category": {
    "SECURITY_WARNING": {
      "PASS_ROLE_WITH_STAR_IN_RESOURCE": [
        {
          "account_id": "123456789012",
          "region": "us-east-1",
          "resource_type": "AWS::IAM::UserPolicy",
          "resource_name": "inlinepolicy",
          "resource_arn": "arn:aws:iam::123456789012:user/user1",
          "policy_type": "IDENTITY_POLICY",
          "finding_type": "SECURITY_WARNING",
          "finding_issue_code": "PASS_ROLE_WITH_STAR_IN_RESOURCE",
          "finding_description": "Using the iam:PassRole action with wildcards (*) in the resource can be overly permissive because it allows iam:PassRole permissions on multiple resources. We recommend that you specify resource ARNs or add the iam:PassedToService condition key to your statement.",
          "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#access-analyzer-reference-policy-checks-security-warning-pass-role-with-star-in-resource"
        }
      ]
    },
    "WARNING": {
      "MISSING_VERSION": [
        {
          "account_id": "123456789012",
          "region": "eu-central-1",
          "resource_type": "AWS::SQS::QueuePolicy",
          "resource_name": "queue1",
          "resource_arn": "arn:aws:sqs:eu-central-1:123456789012:queue1",
          "policy_type": "RESOURCE_POLICY",
          "finding_type": "WARNING",
          "finding_issue_code": "MISSING_VERSION",
          "finding_description": "We recommend that you specify the Version element to help you with debugging permission issues.",
          "finding_link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#access-analyzer-reference-policy-checks-general-warning-missing-version"
        }
      ]
    }
  }
}
```



## Notes

* To speed up execution of the script, run it within an AWS region (e.g., on EC2 or CloudShell) instead of your local machine. Network latency between AWS regions is usually lower than your machine connecting to each region via the Internet.

* The provided minimum IAM permissions exceed the policy size limit for IAM user inline policies (2048 characters). Consider using managed policies or roles instead, which have higher policy size limits.

* Analysis of a policy via AWS IAM Access Analyzer is conducted in the same AWS account and region where the policy is stored. This means that your policy information is not transferred to another region that you are not already using.

* Using a delegated administrator account for AWS Organizations is not supported at the moment.

* The script can only lint policies that are using the AWS IAM policy language. It is not capable of linting other policy languages, such as Cedar policies (as used in AWS Verified Access and AWS Verified Permissions, for example).



## Related projects

If this script does not quite fulfill your needs, consider looking at the following projects that offer similar functionality:
* https://github.com/duo-labs/parliament
* https://github.com/sjakthol/aws-access-analyzer-validator
* https://github.com/salesforce/cloudsplaining
