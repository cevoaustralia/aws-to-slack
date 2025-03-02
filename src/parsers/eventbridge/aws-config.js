//
// AWS Config event parser
//
exports.matches = event =>
    _.has(event.message, "config");

exports.parse = event => {
    const accountId = event.get("accountId");
    const region = event.get("awsRegion");
    const configItem = event.get("Message");
    const resourceType = configItem.resourceType;
    const resourceId = configItem.resourceId;
    const resourceName = configItem.resourceName || resourceId;
    const configurationItemStatus = configItem.configurationItemStatus;
    
    const signInLink = `https://${accountId}.signin.aws.amazon.com/console/config?region=${region}`;
    const consoleLink = event.consoleUrl(`/config/home?region=${region}`);

    const text = `AWS Config detected a ${configurationItemStatus} change for resource ${resourceType}`;

    return event.attachmentWithDefaults({
        author_name: `AWS Config (${region} - ${accountId})`,
        author_link: signInLink,
        title: `${resourceName} - ${configurationItemStatus}`,
        title_link: consoleLink,
        text,
        fallback: text,
        color: event.COLORS.warning,
        fields: [{
            title: "Resource Type",
            value: resourceType,
            short: true
        }, {
            title: "Status",
            value: configurationItemStatus,
            short: true
        }, {
            title: "Resource ID",
            value: resourceId,
            short: true
        }]
    });
};