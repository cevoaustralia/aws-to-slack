//
// AWS Config event parser
//
exports.matches = event =>
    _.includes(event.message, "Config Rules Compliance Change");                               

    exports.parse = event => {
                
                // Extract the specified fields using optional chaining
                const message = event.message;
                configRuleName = _.get(message.detail, "configRuleName");
                detailType = _.get(message, "detail-type");
                resourceType = _.get(message.detail, "resourceType");
                resourceId = _.get(message.detail, "resourceId");
                awsAccountId = _.get(message, "account");
                awsRegion = _.get(message, "region");
                complianceType = _.get(message.detail.newEvaluationResult, "complianceType");
                configRuleInvokedTime = _.get(message.detail.newEvaluationResult, "configRuleInvokedTime");
                resultRecordedTime = _.get(message.detail.newEvaluationResult, "resultRecordedTime");
                const consoleLink = `https://${awsRegion}.console.aws.amazon.com/config/home?region=${awsRegion}#/rules/details?configRuleName=${configRuleName}`;
                
                // Create Slack message with color based on compliance status
                const COLORS = require("../../eventdef").COLORS;
                const text_color = (complianceType === 'COMPLIANT') ? COLORS.ok : COLORS.critical;
                
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
                                            text: `*Compliance Status:*\n${complianceType === 'COMPLIANT' ? 
                                                ':large_green_circle:' : ':red_circle:'}${complianceType}`                                            
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
                                    type: "section",
                                    fields: [
                                        {
                                            type: "mrkdwn",
                                            text: `*Config Rule Invoked at:*\n${configRuleInvokedTime}`
                                        },
                                        {   
                                            type: "mrkdwn",
                                            text: `*Config Rule Result Recorded at:*\n${resultRecordedTime}`
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

                //return event.attachmentWithDefaults(slackMessage);
                return slackMessage;
};
