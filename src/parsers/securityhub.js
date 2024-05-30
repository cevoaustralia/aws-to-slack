const SUPPRESS_ACCOUNT_TYPES = false;

//
// AWS SecurityHub event parser
//
exports.matches = (event) =>
	event.getSource() === "securityhub" ||
	_.get(event.message, "detail.service.serviceName") === "securityhub";

exports.parse = (event) => {
	console.log(`Event ${JSON.stringify(event, null, 2)}`);

	const detail = event.get("detail");
	console.log(`Detail ${JSON.stringify(detail, null, 2)}`);

	const finding = _.get(detail, "findings")[0];
	console.log(`Finding ${JSON.stringify(finding, null, 2)}`);

	const id = _.get(finding, "Id");
	const generatorId = _.get(finding, "GeneratorId");
	const title = _.get(finding, "Title");
	const description = _.get(finding, "Description");
	const createdAt = new Date(_.get(finding, "CreatedAt"));
	const updatedAt = new Date(_.get(finding, "UpdatedAt"));
	const firstSeen = new Date(_.get(finding, "FirstObservedAt"));
	const lastSeen = new Date(_.get(finding, "LastObservedAt"));
	const complianceStatus = _.get(finding, "Compliance.Status");
	const severity = _.get(finding, "Severity.Normalized");
	const severityLabel = _.get(finding, "Severity.Label");
	const criticality = _.get(finding, "Criticality");

	const accountId = _.get(finding, "AwsAccountId");
	const resources = _.get(finding, "Resources");
	const recomendationText = _.get(finding, "Remediation.Recommendation.Text");
	const recomendationLink = _.get(finding, "Remediation.Recommendation.Url");

	const fields = [];

	fields.push({
		title: "Description",
		value: description,
		short: false,
	});

	fields.push({
		title: "Account",
		value: accountId,
		short: true,
	});

	// fields.push({
	// 	title: "Region",
	// 	value: region,
	// 	short: true
	// });
	//
	// fields.push({
	// 	title: "Type",
	// 	value: type,
	// 	short: true
	// });

	fields.push({
		title: "Severity",
		value: severityLabel,
		short: true,
	});

	fields.push({
		title: "First Seen",
		value: firstSeen,
		short: true,
	});

	fields.push({
		title: "Last Seen",
		value: lastSeen,
		short: true,
	});

	fields.push({
		title: "Recommendation",
		value: `${recomendationLink} - ${recomendationText}`,
	});

	if (resources) {
		const resourceType = _.get(resources[0], "Type");
		const resourceId = _.get(resources[0], "Id");

		if (SUPPRESS_ACCOUNT_TYPES) {
			if ("AwsAccount" === resourceType) {
				return true;
			}
		}

		fields.push({
			title: "Affected Resource",
			value: `${resourceType} - ${resourceId}`,
			short: false,
		});
	}

	let color = event.COLORS.neutral; //low severity below 50
	if (severity > 39) {
		//medium severity between 50 and 80
		color = event.COLORS.warning;
	}
	if (severity > 80) {
		//high severity above 80
		color = event.COLORS.critical;
	}

	return event.attachmentWithDefaults({
		author_name: "Amazon SecurityHub",
		fallback: `${title} ${description}`,
		color,
		title,
		fields,
		mrkdwn_in: ["title", "text"],
		ts: createdAt,
	});
};
