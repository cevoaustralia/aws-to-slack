//
// AWS GuardDuty event parser
//
exports.matches = event =>
	event.getSource() === "guardduty" && event.getDetailType() === "AWS API Call via CloudTrail"

exports.parse = event => {
	const detail = event.get("detail");

	let title = _.get(detail, "title");
	let description = _.get(detail, "description");
	const createdAt = new Date(_.get(detail, "time"));
	let accountId = _.get(detail, "accountId");
	let region = _.get(detail, "region");
	let color = event.COLORS.neutral; //low severity below 4
	const fields = [];

	const eventName = _.get(detail, "eventName")

	let actionedBy = _.get(detail, "userIdentity.principalId")
	accountId = _.get(detail, "recipientAccountId");
	region = _.get(detail, "awsRegion");
	title = "Findings Archived"
	description = `Findings Archived by ${actionedBy}`
	color = event.COLORS.ok;

	if (eventName === "UnarchiveFindings") {
		title = "Findings Unarchived"
		description = `Findings Unarchived by ${actionedBy}`
		color = event.COLORS.warning;
	}

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
		title: "Actioned by",
		value: actionedBy,
		short: false
	});

	const findings = _.get(detail, "requestParameters.findingIds");

	for (const finding of findings) {
		fields.push({
			title: "Finding ID",
			value: finding,
			short: false
		});
	}


	return event.attachmentWithDefaults({
		author_name: "Amazon GuardDuty",
		fallback: `${title} ${description}`,
		color: color,
		title: title,
		fields: fields,
		mrkdwn_in: ["title", "text"],
		ts: createdAt,
	});
};
