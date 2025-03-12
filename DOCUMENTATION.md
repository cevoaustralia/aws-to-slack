# AWS-to-Slack Integration

## Introduction
AWS-to-Slack is a serverless solution that enables real-time forwarding of AWS service notifications and alerts to Slack channels. It uses AWS Lambda to process events from various AWS services and forwards them to Slack using webhooks, making it an essential tool for DevOps teams who want to stay informed about their AWS infrastructure events.

## Features
- Supports multiple AWS services including:
  - Auto-Scaling Events
  - AWS Health Notifications
  - AWS Batch
  - CloudFormation
  - CodeBuild
  - CodeCommit
  - CodeDeploy
  - CodePipeline
  - ECS
  - GuardDuty
  - Inspector
  - RDS Events
  - Security Hub
  - SES (Simple Email Service)
- Customizable message formatting
- Serverless architecture using AWS Lambda
- Easy deployment using AWS CloudFormation
- Support for multiple deployments
- EventBridge (CloudWatch Events) integration
- Multi-account setup support with centralized notifications

## Architecture
The solution implements a hub-and-spoke architecture for multi-account event processing:

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   Account A      │    │   Account B      │    │   Account C      │
│  (Member)        │    │  (Member)        │    │  (Member)        │
│                  │    │                  │    │                  │
│  EventBridge ────┼────▶ SNS Topic    ◄───┼────  EventBridge    │
└────────┬─────────┘    └────────┬─────────┘    └──────────────────┘
         │                       │
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────────┐
│           Central Account                    │
│           (Audit/Management)                 │
│                                             │
│    ┌─────────────┐         ┌────────────┐  │
│    │   Lambda    │         │   Slack    │  │
│    │   Function  ├─────────▶  Channel   │  │
│    └─────────────┘         └────────────┘  │
└─────────────────────────────────────────────┘
```

The solution uses the following AWS services:
- AWS Lambda - For event processing and Slack message formatting
- Amazon EventBridge - For routing AWS service events
- Amazon SNS - For cross-account message delivery
- IAM - For security and access control
- CloudFormation - For infrastructure deployment

## Deployment Guide

### Prerequisites
1. Access to multiple AWS accounts (member accounts and central account)
2. A Slack workspace where you have permissions to create apps
3. Node.js and npm (for development)
4. AWS CLI (for deployment)

### Step 1: Slack Configuration
1. Go to https://api.slack.com/apps/
2. Click "Create New App"
3. Select "From scratch"
4. Choose an App Name and select your Workspace
5. Navigate to "Incoming Webhooks" and activate them
6. Click "Add New Webhook to Workspace"
7. Select the channel where you want to receive notifications
8. Copy the Webhook URL for use in the AWS configuration

### Step 2: Central Account (Audit/Management) Deployment
1. Clone the repository:
   ```bash
   git clone [repository-url]
   cd aws-to-slack
   ```

2. Deploy the Lambda function in the central account:
   ```bash
   # Set AWS_PROFILE to your central account profile
   export AWS_PROFILE=central-account
   npm run deploy
   ```

3. During deployment, provide:
   - The Slack Webhook URL obtained in Step 1
   - The desired AWS region
   - The SNS topic name
   - KMS key details (if using encryption)

4. Note the SNS topic ARN from the deployment output

### Step 3: Member Account Configuration
1. Deploy EventBridge rules in each member account:
   ```bash
   cd eventbridge
   # Set AWS_PROFILE to your member account profile
   export AWS_PROFILE=member-account
   aws cloudformation deploy \
     --template-file event-bridge-cfn.yaml \
     --stack-name aws-to-slack-events \
     --parameter-overrides \
       CentralAccountId=<CENTRAL_ACCOUNT_ID> \
       SnsTopicArn=<SNS_TOPIC_ARN>
   ```

2. Repeat for each member account where you want to collect events

### Step 4: Event Configuration
1. In each member account:
   - Navigate to the AWS Management Console
   - Go to EventBridge (CloudWatch Events)
   - Create rules for the AWS services you want to monitor
   - Set the target as the SNS topic created during deployment

## Development
- The main event processing logic is in `src/index.js`
- Event definitions and parsing are handled in `src/eventdef.js`
- Service-specific parsers are in the `parsers/` directory
- Use `npm test` to run the test suite

## Security Considerations
- Always use IAM roles with least privilege
- Consider encrypting sensitive data using KMS
- Regularly rotate Slack webhook URLs
- Monitor Lambda function execution logs
- Ensure proper cross-account IAM permissions
- Use STS for temporary credentials when needed

## Troubleshooting
1. Check CloudWatch Logs for Lambda execution logs
2. Verify EventBridge rules are properly configured
3. Ensure IAM roles have proper permissions
4. Validate Slack webhook URL is correct and active
5. Check SNS delivery status and permissions
6. Verify cross-account trust relationships

## References
1. [AWS Lambda Documentation](https://docs.aws.amazon.com/lambda/)
2. [Slack API Documentation](https://api.slack.com/docs)
3. [AWS EventBridge Documentation](https://docs.aws.amazon.com/eventbridge/)
4. [AWS CloudFormation User Guide](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/)
5. [AWS Organizations Documentation](https://docs.aws.amazon.com/organizations/)
6. [Cross-Account IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html)

## Contributing
Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## License
This project is licensed under the MIT License - see the LICENSE file for details.