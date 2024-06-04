//
// AWS GuardDuty event parser
//
exports.matches = event =>
	event.getSource() === "guardduty" && _.startsWith(event.getDetailType(), "GuardDuty Runtime Protection");

exports.parse = event => {
	const detail = event.get("detail");

	const title = event.getDetailType();
	const description = "";
	const fields = [];
	const createdAt = new Date(_.get(event, "message.time"));
	const accountId = _.get(event, "message.account");
	const region = _.get(event, "message.region");

	let color = event.COLORS.ok;
	if (_.includes(event.getDetailType(), "Unhealthy")) {
		color = event.COLORS.critical;
	}

	const resource = _.get(detail, "resourceDetails");

	// const previousStatus = _.get(detail, "previousStatus");
	// const currentStatus = _.get(detail, "currentStatus");
	const issue = _.get(detail, "issue");

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

	const resourceType = _.get(resource, "resourceType");

	fields.push({
		title: "Resource Type",
		value: resourceType,
		short: true
	});

	if (resourceType === "EKS") {
		const eksCluster = _.get(resource, "eksClusterDetails");

		fields.push({
			title: "Cluster",
			value: _.get(eksCluster, "clusterName"),
			short: true
		});

		const addonVersion = _.get(eksCluster, "addonDetails.addonVersion");
		const addonStatus = _.get(eksCluster, "addonDetails.addonStatus");

		fields.push({
			title: "AddOn",
			value: `${addonVersion} - ${addonStatus}`,
			short: true
		});
	}
	else if (resourceType === "EC2") {
		const ec2Instance = _.get(resource, "ec2InstanceDetails");
		const instanceId = _.get(ec2Instance, "instanceId");
		const instanceType = _.get(ec2Instance, "instanceType");
		const clusterArn = _.get(ec2Instance, "clusterArn");
		const agentVersion= _.get(ec2Instance, "agentDetails.version");
		const managementType= _.get(ec2Instance, "managementType");

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
	else if (resourceType === "ECS") {
		const ecsClusterDetails = _.get(resource, "ecsClusterDetails");
		const clusterName = _.get(ecsClusterDetails, "clusterName");
		const fargateDetails= _.get(ecsClusterDetails, "fargateDetails");
		const issues= _.get(fargateDetails, "issues");
		const managementType= _.get(fargateDetails, "managementType");

		fields.push({
			title: "Cluster Name",
			value: clusterName,
			short: true
		});
		fields.push({
			title: "Issue",
			value: issues,
			short: false
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