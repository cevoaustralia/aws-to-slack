# AWS-to-Slack

[![npm](https://img.shields.io/npm/v/aws-to-slack.svg)](https://www.npmjs.com/package/aws-to-slack)
[![license](https://img.shields.io/github/license/arabold/aws-to-slack.svg)](https://github.com/arabold/aws-to-slack/blob/master/LICENSE)


This document is specific to Cloudformation Stacks that reside under *eventbridge* directory. This stack deploys the following components with certain parameters that are confirgurable

<table>
   <tr>
      <th>Eventbridge Rule: DetectAWSConfigNonComplianceChanges</th>
      <th>Eventbridge Rule:DetectAllAWSConfigComplianceChanges</th>
      <th>Eventbridge Rule:DetectConfigRemediationFailures</th>
      <th>IAM Role: EventbridgeAllowPublishToSNS</th>
      <th>ConfigRemediationTopic & ConfigRemediationTopicPOlicy</th>
   </tr>
   <tr>
      <td width="50%">Placeholder test</td>
      <td width="50%">Placeholder test</td>
   </tr>
</table>


## Deployment Pre-requisites.
1. Slack incoming webhook configured to forward incoming messages to Slack channel.
2. A Slack Channel which receives notifications from Step 1.


## Creating SNS Topic, Eventbridge Rules, and required Roles.
1. Go to your Management/Audit/Security AWS account from where you wish to deploy the SNS Topic, Eventbridge Rules and required IAM role.
2. Grab the Cloudformation template under eventbridge directory, and deploy it as StackSet. This template requires parameters below:
  i. DeployAWSConfigComplianceChangesRule (Boolean). Controls creation of Eventbridge rule to detect Compliance Changes. Default = true.
  ii. Controls creation of Eventbridge rule to detect Failures of Remediation Actions. Default = true.
  iii. ManagementAccountId. Mandatory Parameter for AWS Account ID where you manage the StackSet. The Lambda Function that Subscribes to the SNS topic is also created in this account. Steps to deploy lambda are described in next Section.
  iv. RemediationTopicName. SNS Topic.


## Try!
Ready to try the latest version for yourself? Installation into your own AWS environment is simple - just launch event-bridge-cfn.yaml in Cloudformation COnsole.


## Contributing

You want to contribute? That's awesome! 🎉

