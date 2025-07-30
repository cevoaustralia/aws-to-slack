exports.matches = event =>
    _.includes(event.message, "Config Rules Re-evaluation Status") || 
    _.includes(event.message, "Config Remediation Execution Status");     

exports.parse = event => {
   // Extract the specified fields
   const message = event.message;
   console.log("MESSAGE >>>>>>", message)

   detailType = _.get(message, "detail-type");

   configRuleName = _.get(message.detail, "configRuleName");
   resourceType = _.get(message.detail, "resourceType");
   resourceId = _.get(message.detail, "resourceId");
   awsAccountId = _.get(message, "account");
   awsRegion = _.get(message, "region");
   status = _.get(message.detail, "status");
   remediationType = _.get(message.detail, "remediationType");
   failureReason = _.get(message.detail, "failureReason");
   remediationTargetResourceType = _.get(message.detail, "remediationTargetResourceType");
   automationExecutionId = _.get(message.detail, "automationExecutionId");
   messageType = _.get(message.detail, "messageType");
   notificationCreationTime = _.get(message.detail, "notificationCreationTime");

   const consoleLink = `https://${awsRegion}.console.aws.amazon.com/config/home?region=${awsRegion}#/rules/details?configRuleName=${configRuleName}`;

   // Create Slack message with color based on status
   const COLORS = require("../../eventdef").COLORS;
   const text_color = (status === 'SUCCESS') ? COLORS.ok : COLORS.critical;

   const slackMessage = {
       attachments: [
           {
               color: text_color,
               blocks: [
                   {
                       type: "header",
                       text: {
                           type: "plain_text",
                           text: `${detailType}`
                       }
                   },
                   {
                       type: "section",
                       fields: [
                           {
                               type: "mrkdwn",
                               text: `*Config Rule:*\n${configRuleName}`
                           },
                           {
                               type: "mrkdwn",
                               text: `*Execution Status:*\n${status === 'SUCCESS' ? 
                                   ':large_green_circle:'  : ':red_circle:' }${status}`
                           },
                           {
                               type: "mrkdwn",
                               text: `*Remediation Type:*\n${remediationType}`
                           },
                           {
                               type: "mrkdwn",
                               text: `*Remediation Target Resource Type:*\n${remediationTargetResourceType}`
                           },
                           {
                               type: "mrkdwn",
                               text: `*Automation Execution Id:*\n${automationExecutionId}`
                           },
                           {
                               type: "mrkdwn",
                               text: `*Message Type:*\n${messageType}`
                           },
                           {
                               type: "mrkdwn",
                               text: `*Notification Creation Time:*\n${notificationCreationTime}`
                           }
                       ]
                   },
                   {
                       type: "section",
                       fields: [
                           {
                               type: "mrkdwn",
                               text: `*Resource Type:*\n${resourceType}`
                           },
                           {
                               type: "mrkdwn",
                               text: `*ResourceId:*\n${resourceId}`
                           },
                           {
                               type: "mrkdwn",
                               text: `*Region:*\n${awsRegion}`
                           },
                           {
                               type: "mrkdwn",
                               text: `*AWS Account:*\n${awsAccountId}`
                           }
                       ]
                   },
                   {
                       type: "actions",
                       elements: [
                           {
                               type: "button",
                               text: {
                                   type: "plain_text",
                                   text: "View in AWS Console"
                               },
                               url: `${consoleLink}`,
                               style: "primary"
                           }
                       ]
                   }
               ]
           }
       ]
   };

   return slackMessage;
};