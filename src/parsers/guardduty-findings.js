//
// AWS GuardDuty event parser
//
exports.matches = event =>
	event.getSource() === "guardduty" && event.getDetailType() === "GuardDuty Finding";

exports.parse = event => {
	const detail = event.get("detail");

	const title = _.get(detail, "title");
	const description = _.get(detail, "description");
	const createdAt = new Date(_.get(detail, "time"));
	const accountId = _.get(detail, "accountId");
	const region = _.get(detail, "region");
	let color = event.COLORS.neutral; //low severity below 4
	const fields = [];

	//const id = _.get(detail, "id");
	const severity = _.get(detail, "severity");
	//const partition = _.get(event, "partition");
	//const arn = _.get(event, "arn");
	const type = _.get(detail, "type");

	const threatName = _.get(detail, "service.additionalInfo.threatName");
	const threatListName = _.get(detail, "service.additionalInfo.threatListName");

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

	const actionType = _.get(detail, "service.action.actionType");
	const eventFirstSeen = _.get(detail, "service.eventFirstSeen");
	const eventLastSeen = _.get(detail, "service.eventLastSeen");
	//const archived = _.get(event, "service.archived");
	const count = _.get(detail, "service.count");

	if (actionType === "PORT_PROBE") {

		const port = _.get(detail, "service.action.portProbeAction.portProbeDetails[0].localPortDetails.port");
		const portName = _.get(detail, "service.action.portProbeAction.portProbeDetails[0].localPortDetails.portName");

		const ipAddressV4 = _.get(detail, "service.action.portProbeAction.portProbeDetails[0].remoteIpDetails.ipAddressV4");
		const isp = _.get(detail, "service.action.portProbeAction.portProbeDetails[0].remoteIpDetails.organization.isp");
		const org = _.get(detail, "service.action.portProbeAction.portProbeDetails[0].remoteIpDetails.organization.org");

		const blocked = _.get(detail, "service.action.portProbeAction.blocked");

		fields.push({
			title: "Port probe details",
			value: `port ${port} - ${portName}`,
			short: true
		});

		fields.push({
			title: "Remote probe origin",
			value: `${ipAddressV4}\n${isp} - ${org}`,
			short: true
		});

		fields.push({
			title: "Blocked",
			value: `${blocked}`,
			short: true
		});
	}
	else if (actionType === "AWS_API_CALL") {

		const api = _.get(detail, "service.action.awsApiCallAction.api");
		const serviceName = _.get(detail, "service.action.awsApiCallAction.serviceName");

		const ipAddressV4 = _.get(detail, "service.action.awsApiCallAction.remoteIpDetails.ipAddressV4");
		const isp = _.get(detail, "service.action.awsApiCallAction.remoteIpDetails.organization.isp");
		const org = _.get(detail, "service.action.awsApiCallAction.remoteIpDetails.organization.org");

		const country = _.get(detail, "service.action.awsApiCallAction.remoteIpDetails.country.countryName");
		const city = _.get(detail, "service.action.awsApiCallAction.remoteIpDetails.city.cityName");

		fields.push({
			title: "Service",
			value: `${serviceName} - ${api}`,
			short: true
		});

		fields.push({
			title: "API origin",
			value: `${ipAddressV4}\n${isp} - ${org}`,
			short: true
		});

		fields.push({
			title: "Location",
			value: `${country} - ${city}`,
			short: true
		});
	}
	else if (actionType === "NETWORK_CONNECTION") {

		const detectedAction = _.get(detail, "service.action.networkConnectionAction");

		const connectionDirection = _.get(detectedAction, "connectionDirection");
		const protocol = _.get(detectedAction, "protocol");
		// const blocked = _.get(detectedAction, "blocked");

		const ipAddressV4 = _.get(detectedAction, "remoteIpDetails.ipAddressV4");
		const isp = _.get(detectedAction, "remoteIpDetails.organization.isp");
		const org = _.get(detectedAction, "remoteIpDetails.organization.org");

		const country = _.get(detectedAction, "remoteIpDetails.country.countryName");
		const city = _.get(detectedAction, "remoteIpDetails.city.cityName");

		// const remotePort = _.get(detectedAction, "remotePortDetails.port");
		// const remotePortName = _.get(detectedAction, "remotePortDetails.portName");

		const localIpAddress = _.get(detectedAction, "localIpDetails.ipAddressV4");
		const localPort = _.get(detectedAction, "localPortDetails.port");
		// const localPortName = _.get(detectedAction, "localPortDetails.portName");


		fields.push({
			title: "Connection",
			value: `${connectionDirection} on ${localIpAddress} (${protocol}:${localPort})`,
			short: false
		});

		fields.push({
			title: "API origin",
			value: `${ipAddressV4}\n${isp} - ${org}`,
			short: true
		});

		fields.push({
			title: "Location",
			value: `${country} - ${city}`,
			short: true
		});
	}
	else if (actionType === "KUBERNETES_API_CALL") {

		const detectedAction = _.get(detail, "service.action.kubernetesApiCallAction");

		const ipAddressV4 = _.get(detectedAction, "remoteIpDetails.ipAddressV4");
		const isp = _.get(detectedAction, "remoteIpDetails.organization.isp");
		const org = _.get(detectedAction, "remoteIpDetails.organization.org");

		const country = _.get(detectedAction, "remoteIpDetails.country.countryName");
		const city = _.get(detectedAction, "remoteIpDetails.city.cityName");

		const verb = _.get(detectedAction, "verb");
		const requestUri = _.get(detectedAction, "requestUri");

		fields.push({
			title: "Kubernetes API call",
			value: `${verb} on ${requestUri}`,
			short: false
		});

		fields.push({
			title: "API origin",
			value: `${ipAddressV4}\n${isp} - ${org}`,
			short: true
		});

		fields.push({
			title: "Location",
			value: `${country} - ${city}`,
			short: true
		});

	}
	else {
		console.log(`Unknown GuardDuty actionType '${actionType}'`);

		fields.push({
			title: `Unknown Action Type (${actionType})`,
			value: JSON.stringify(_.get(detail, "service.action"), null, 2),
			short: false
		});
	}

	if (count > 1) {
		fields.push({
			title: "First Event Time",
			value: eventFirstSeen,
			short: true
		});

		fields.push({
			title: "Last Event Time",
			value: eventLastSeen,
			short: true
		});

		fields.push({
			title: "Event count",
			value: count,
			short: false
		});
	}

	const resourceType = _.get(detail, "resource.resourceType");

	fields.push({
		title: "Resource Type",
		value: resourceType,
		short: true
	});

	if (resourceType === "Instance") {

		const instanceDetails = _.get(detail, "resource.instanceDetails");

		const instanceId = _.get(instanceDetails, "instanceId");
		const instanceType = _.get(instanceDetails, "instanceType");

		fields.push({
			title: "Instance ID",
			value: instanceId,
			short: true
		});

		fields.push({
			title: "Instance Type",
			value: instanceType,
			short: true
		});

		const tags = _.get(instanceDetails, "tags");

		for (let i = 0; i < tags.length; i++) {
			const key = tags[i].key;
			const value = tags[i].value;

			fields.push({
				title: key,
				value: value,
				short: true
			});
		}
	}
	else if (resourceType === "AccessKey") {

		const accessKeyDetails = _.get(detail, "resource.accessKeyDetails");

		const accessKeyId = _.get(accessKeyDetails, "accessKeyId");
		const principalId = _.get(accessKeyDetails, "principalId");
		const userType = _.get(accessKeyDetails, "userType");
		const userName = _.get(accessKeyDetails, "userName");

		fields.push({
			title: "AccessKeyId",
			value: accessKeyId,
			short: true
		});
		fields.push({
			title: "PrincipalId",
			value: principalId,
			short: true
		});
		fields.push({
			title: "User Type",
			value: userType,
			short: true
		});
		fields.push({
			title: "User Name",
			value: userName,
			short: true
		});

	}
	else if (resourceType === "EKSCluster") {
		const cluster = _.get(detail, "resource.eksClusterDetails");

		const name = _.get(cluster, "name");
		const arn = _.get(cluster, "arn");
		// const createdAt = _.get(cluster, "createdAt");
		const vpcId = _.get(cluster, "vpcId");
		const status = _.get(cluster, "status");

		fields.push({
			title: "Cluster",
			value: `${name} (${arn}) - ${status}`,
			short: false
		});

		fields.push({
			title: "VPC",
			value: `${vpcId}`,
			short: true
		});

		const kubernetesDetails = _.get(detail, "resource.kubernetesDetails");
		const workloadDetails = _.get(kubernetesDetails, "kubernetesWorkloadDetails");
		fields.push({
			title: "Workload",
			value: workloadDetails,
			short: true
		});
		const userDetails = _.get(kubernetesDetails, "kubernetesUserDetails");

		const username= _.get(userDetails, "username");
		const uid = _.get(userDetails, "uid");
		const groups = _.get(userDetails, "groups");
		const sessionName = _.get(userDetails, "sessionName");

		fields.push({
			title: "User",
			value: `${username}/${sessionName} (${uid})`,
			short: true
		});

		fields.push({
			title: "Groups",
			value: `${groups}`,
			short: true
		});

		const tags = _.get(cluster, "tags");

		for (let i = 0; i < tags.length; i++) {
			const key = tags[i].key;
			const value = tags[i].value;

			fields.push({
				title: key,
				value: value,
				short: true
			});
		}
	}
	else {
		console.log(`Unknown GuardDuty resourceType '${resourceType}'`);

		fields.push({
			title: "Unknown Resource Type (" + resourceType + ")",
			value: JSON.stringify(_.get(detail, "resource"), null, 2),
			short: false
		});
	}

	if (severity > 4) { //medium seveirty between 4 and 7
		color = event.COLORS.warning;
	}
	if (severity > 7) { //high sevirity above 7
		color = event.COLORS.critical;
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
