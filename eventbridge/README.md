# AWS-to-Slack

[![npm](https://img.shields.io/npm/v/aws-to-slack.svg)](https://www.npmjs.com/package/aws-to-slack)
[![license](https://img.shields.io/github/license/arabold/aws-to-slack.svg)](https://github.com/arabold/aws-to-slack/blob/master/LICENSE)


This document is specific to Cloudformation Stacks that reside under *eventbridge* directory. As of now, this stack only creates rules for AWS Config related events.

This stack deploys the following components with certain parameters that are configurable.

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



## How to Deploy: 
Please Refer to Step 2.2 Deploy SNS Topic and EventBridge rules in the member account in the README under root directory of the project. 

## Try in Single Account:
Ready to try the latest version for yourself? Installation into your own AWS environment is simple - just launch event-bridge-cfn.yaml in Cloudformation Console. For that, please do not deploy as StackSet.


## Contributing

If you want to leverage EventBridge to receive notifications, here is what you will need to do.
1. Update the event-bridge-cfn.yaml to add the relevant Rule.
2. Update the scr\parsers to include the parser to parse the relevant field sent in Eventbridge message payload, for consumption of Slack API.
3. Update the Parsers list in src\index.js to include your parser.
