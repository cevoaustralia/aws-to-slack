//
// AWS GuardDuty event parser
//
exports.matches = event =>
	event.getSource() === "guardduty" && event.getDetailType().startsWith("GuardDuty Runtime Protection")

exports.parse = event => {
	const detail = event.get("detail");

	let title = event.getDetailType();
	let description = "";
	const fields = [];
	const createdAt = new Date(_.get(event, "message.time"));
	let accountId = _.get(event, "message.account");
	let region = _.get(event, "message.region");

	let color = event.COLORS.ok;
	if (event.getDetailType().indexOf("Unhealthy") !== -1) {
		color = event.COLORS.critical;
	}

	let resource = _.get(detail, "resourceDetails");

	let previousStatus = _.get(detail, "previousStatus");
	let currentStatus = _.get(detail, "currentStatus");
	let issue = _.get(detail, "issue");

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

	let resourceType = _.get(resource, "resourceType");

	fields.push({
		title: "Resource Type",
		value: resourceType,
		short: true
	});

	if (resourceType === "EKS") {
		let eksCluster = _.get(resource, "eksClusterDetails");

		fields.push({
			title: "Cluster",
			value: _.get(eksCluster, "clusterName"),
			short: true
		});

		let addonVersion = _.get(eksCluster, "addonDetails.addonVersion");
		let addonStatus = _.get(eksCluster, "addonDetails.addonStatus");

		fields.push({
			title: "AddOn",
			value: `${addonVersion} - ${addonStatus}`,
			short: true
		});
	}
	else if (resourceType === "EC2") {
		let ec2Instance = _.get(resource, "ec2InstanceDetails");
		let instanceId = _.get(ec2Instance, "instanceId");
		let instanceType = _.get(ec2Instance, "instanceType");
		let clusterArn = _.get(ec2Instance, "clusterArn");
		let agentVersion= _.get(ec2Instance, "agentDetails.version");
		let managementType= _.get(ec2Instance, "managementType");

		fields.push({
			title: "Instance",
			value: instanceId,
			short: true
		});
		fields.push({
			title: "Instance Type",
			value: instanceType,
			short: true
		});
		fields.push({
			title: "ClusterArn",
			value: clusterArn,
			short: false
		});
		fields.push({
			title: "Agent Version",
			value: agentVersion,
			short: true
		});
		fields.push({
			title: "Management Type",
			value: managementType,
			short: true
		});
	}
	else {
		console.log(`Unknown GuardDuty resourceType '${resourceType}'`);

		fields.push({
			title: `Unknown Resource Type (${resourceType})`,
			value: JSON.stringify(resource, null, 2),
			short: false
		});
	}


	if (issue) {
		fields.push({
			title: "Issue",
			value: issue,
			short: false
		})
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