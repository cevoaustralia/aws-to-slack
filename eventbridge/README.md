# AWS-to-Slack

[![npm](https://img.shields.io/npm/v/aws-to-slack.svg)](https://www.npmjs.com/package/aws-to-slack)
[![license](https://img.shields.io/github/license/arabold/aws-to-slack.svg)](https://github.com/arabold/aws-to-slack/blob/master/LICENSE)


This document is specific to Cloudformation Stacks that reside under *eventbridge* directory. This stack deploys the following components with certain parameters that are configurable.

## Template Parameters
  1. DeployAllWSConfigComplianceChangesRule (Boolean). Controls creation of Eventbridge rule to detect all Compliance Changes. Default = true.
  2. DeployAWSConfigNonComplianceAlertRule: Controls creation of Eventbridge rule to only when resources become non-Compliant. Default = true. 
  3. Controls creation of Eventbridge rule to detect Failures of Remediation Actions. Default = true.
  4. ManagementAccountId. Mandatory Parameter for AWS Account ID where you manage the StackSet. The Lambda Function that Subscribes to the SNS topic is also created in this account. Steps to deploy lambda are described in next Section.
  5. RemediationTopicName. SNS Topic.


## Resources Created
1. Eventbridge Rule: DetectAWSConfigNonComplianceChanges</th>
2. Eventbridge Rule:DetectAllAWSConfigComplianceChanges</th>
3. Eventbridge Rule:DetectConfigRemediationFailures</th>
4. IAM Role: EventbridgeAllowPublishToSNS</th>
5. ConfigRemediationTopic & ConfigRemediationTopicPOlicy</th>



## HOw to Deploy: 
1. Go to your Management/Audit/Security AWS account from where you wish to deploy the SNS Topic, Eventbridge Rules and required IAM role.
2. Grab the Cloudformation template under eventbridge directory, and deploy it as StackSet. Specify the required, described above.



## Try!
Ready to try the latest version for yourself? Installation into your own AWS environment is simple - just launch event-bridge-cfn.yaml in Cloudformation COnsole.


## Contributing

You want to contribute? That's awesome! 🎉

