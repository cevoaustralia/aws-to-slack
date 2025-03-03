//
// AWS Config event parser
//
exports.matches = event =>
    _.includes(event.message, "Config Rules Compliance Change");                               

    exports.parse = event => {
                
                // Extract the specified fields using optional chaining
                const message = event.message;

                console.log("MESSAGE IS >>>>>>>>>>>>>>>>: ", message)

                configRuleName = _.get(message.detail, "configRuleName");
                console.log("CONFIG RULE NAME : ", configRuleName)

                resourceType = _.get(message, "resourceType");
                awsAccountId = _.get(message, "account");
                awsRegion = _.get(message, "region");
                complianceType = _.get(message.detail.newEvaluationResult, "complianceType");
                
          
                // Create Slack message with color based on compliance status
                //const color = complianceType === 'COMPLIANT' ? '#36a64f' : '#ff0000';
                const COLORS = require("../../eventdef").COLORS;
                const text_color = (complianceType === 'COMPLIANT') ? COLORS.ok : COLORS.critical;

                console.log("COLORS IS >>>>>>>>>>>>>>>>: ", text_color)
                
                const slackMessage = {
                    attachments: [
                        {
                            color: text_color,
                            blocks: [
                                {
                                    type: "header",
                                    text: {
                                        type: "plain_text",
                                        text: "AWS Config Rule Compliance Change"
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
                                            text: `*Compliance Status:*\n${complianceType}`,
                                            color: `${text_color}`
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
                                            text: `*Region:*\n${awsRegion}`
                                        }
                                    ]
                                },
                                {
                                    type: "section",
                                    fields: [
                                        {
                                            type: "mrkdwn",
                                            text: `*AWS Account:*\n${awsAccountId}`
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
