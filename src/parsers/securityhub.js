//
// AWS GuardDuty event parser
//
exports.matches = event =>
	event.getSource() === "securityhub"
	|| _.get(event.message, "detail.service.serviceName") === "securityhub";

exports.parse = event => {
	const detail = event.get("detail");

	//const id = _.get(detail, "id");
	const title = _.get(detail, "title");
	const description = _.get(detail, "description");
	const createdAt = new Date(_.get(detail, "UpdatedAt"));
	const severity = _.get(detail, "severity");
	const criticality = _.get(detail, "Criticality");

	const accountId = _.get(detail, "AwsAccountId");

	const fields = [];

	fields.push({
		title: "Description",
		value: description,
		short: false
	});

	fields.push({
		title: "Account",
		value: accountId,
		short: true
	});

	fields.push({
		title: "Region",
		value: region,
		short: true
	});

	fields.push({
		title: "Type",
		value: type,
		short: true
	});

	fields.push({
		title: "Severity",
		value: severity,
		short: true
	});

	fields.push({
		title: threatName,
		value: threatListName,
		short: true
	});

	// if (resourceType === "Instance") {
	//
	//
	// }
	// else {
	console.log(`Unknown GuardDuty resourceType '${resourceType}'`);

	fields.push({
		title: "Unknown Resource Type (" + resourceType + ")",
		value: JSON.stringify(_.get(event, "resource"), null, 2),
		short: false
	});
	// }

	let color = event.COLORS.neutral; //low severity below 50
	if (criticality > 50) { //medium seveirty between 50 and 80
		color = event.COLORS.warning;
	}
	if (criticality > 80) { //high sevirity above 80
		color = event.COLORS.critical;
	}

	return event.attachmentWithDefaults({
		author_name: "Amazon SecurityHub",
		fallback: `${title} ${description}`,
		color: color,
		title: title,
		fields: fields,
		mrkdwn_in: ["title", "text"],
		ts: createdAt,
	});
};
