//
// AWS GuardDuty event parser
//
exports.matches = event =>
	event.getSource() === "guardduty" && event.getDetailType() === "AWS API Call via CloudTrail";

exports.parse = event => {
	const detail = event.get("detail");

	const createdAt = new Date(_.get(detail, "time"));
	const fields = [];

	const eventName = _.get(detail, "eventName");
	const actionedBy = _.get(detail, "userIdentity.principalId");
	const accountId = _.get(detail, "recipientAccountId");
	const region = _.get(detail, "awsRegion");

	let title = "GuardDuty Configuration change";
	let description = `Actioned by ${actionedBy}`;
	let color = event.COLORS.ok;

	if (eventName === "ArchiveFindings" || eventName === "UnarchiveFindings") {

		title = "Findings Archived";
		description = `Findings Archived by ${actionedBy}`;
		color = event.COLORS.ok;

		if (eventName === "UnarchiveFindings") {
			title = "Findings Unarchived";
			description = `Findings Unarchived by ${actionedBy}`;
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
	} else if (eventName === "UpdateOrganizationConfiguration" || eventName === "UpdateDetector") {

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

		fields.push({
			title: "Event",
			value: eventName,
			short: true
		});

		const features = _.get(detail, "requestParameters.features");

		for (const feature of features) {

			fields.push({
				title: _.get(feature, "name"),
				value: _.get(feature, "status"),
				short: true
			});

			const additionalConfiguration = _.get(feature, "additionalConfiguration");

			if (additionalConfiguration) {
				for (const item of additionalConfiguration) {
					fields.push({
						title: _.get(item, "name"),
						value: _.get(item, "status"),
						short: true
					});
				}
			}
		}

	}
	else {
		console.log(`Unknown GuardDuty Event '${eventName}'`);

		fields.push({
			title: `Unknown Event Type (${eventName})`,
			value: JSON.stringify(_.get(detail, "requestParameters"), null, 2),
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
