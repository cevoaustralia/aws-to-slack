//
// AWS CloudFormation event parser
//
exports.matches = event =>
	event.getSource() === "cloudformation";

exports.parse = event => {
	console.log(`Event ${JSON.stringify(event, null, 2)}`);

	const message = event.message;

	const version = _.get(message, "version");
	const id = _.get(message, "id");
	const source = _.get(message, "source");
	const account = _.get(message, "account");
	const time = _.get(message, "time");
	const region = _.get(message, "region");

	const detail = _.get(message, "detail");

	const userIdentity = _.get(detail, "userIdentity");
	const userPrincipal = _.get(userIdentity, "principalId");
	const userName = _.get(userIdentity, "userName");

	const eventTime = _.get(detail, "eventTime");
	const eventName = _.get(detail, "eventName");
	const awsRegion = _.get(detail, "awsRegion");
	const userAgent = _.get(detail, "userAgent");
	const errorCode = _.get(detail, "errorCode");
	const errorMessage = _.get(detail, "errorMessage");

	const requestParameters = _.get(detail, "requestParameters");

	const fields = [];

	fields.push({
		title: "Id",
		value: `${id}`,
		short: false
	});

	fields.push({
		title: "Event Name",
		value: `${eventName} (${awsRegion})`,
		short: true
	});

	fields.push({
		title: "Source",
		value: userAgent,
		short: true
	});

	fields.push({
		title: "Invoked by",
		value: userName || userPrincipal,
		short: true
	});

	if (requestParameters) {
		for (var name in requestParameters) {
			const value = requestParameters[name];

			fields.push({
				title: name,
				value: value,
				short: true
			});
		}
	}

	if (errorMessage) {
		fields.push({
			title: errorCode,
			value: errorMessage,
			short: false
		});
	}

	let stackName = `Unknown`;

	if (requestParameters) {
		stackName = _.get(requestParameters, "stackName");
	}

	const title = `${eventName}`;

	return event.attachmentWithDefaults({
		author_name: "AWS CloudFormation",
		title: title,
		// title_link: consoleLink,
		fallback: `${stackName}: ${title}`,
		// color: color,
		ts: new Date(time),
		fields: fields
	});
};

const COLORS = require("../eventdef").COLORS;
// Status codes from <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-describing-stacks.html#w2ab1c15c15c17c11>
const statusMappings = {
	"CREATE_COMPLETE": {
		"title": "Stack creation complete",
		"color": COLORS.ok,
	},
	"CREATE_IN_PROGRESS": {
		"title": "Stack creation in progress",
		"color": COLORS.accent,
	},
	"CREATE_FAILED": {
		"title": "Stack creation failed",
		"color": COLORS.critical,
	},
	"DELETE_COMPLETE": {
		"title": "Stack deletion complete",
		"color": COLORS.ok,
	},
	"DELETE_FAILED": {
		"title": "Stack deletion failed",
		"color": COLORS.critical,
	},
	"DELETE_IN_PROGRESS": {
		"title": "Stack deletion in progress",
		"color": COLORS.accent,
	},
	"REVIEW_IN_PROGRESS": {
		"title": "Stack review in progress",
		"color": COLORS.accent,
	},
	"ROLLBACK_COMPLETE": {
		"title": "Stack rollback complete",
		"color": COLORS.warning,
	},
	"ROLLBACK_FAILED": {
		"title": "Stack rollback failed",
		"color": COLORS.critical,
	},
	"ROLLBACK_IN_PROGRESS": {
		"title": "Stack rollback in progress",
		"color": COLORS.warning,
	},
	"UPDATE_COMPLETE": {
		"title": "Stack update complete",
		"color": COLORS.ok,
	},
	"UPDATE_COMPLETE_CLEANUP_IN_PROGRESS": {
		"title": "Stack update complete, cleanup in progress",
		"color": COLORS.accent,
	},
	"UPDATE_IN_PROGRESS": {
		"title": "Stack update in progress",
		"color": COLORS.accent,
	},
	"UPDATE_ROLLBACK_COMPLETE": {
		"title": "Stack update rollback complete",
		"color": COLORS.warning,
	},
	"UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS": {
		"title": "Stack update rollback complete, cleanup in progress",
		"color": COLORS.warning,
	},
	"UPDATE_ROLLBACK_FAILED": {
		"title": "Stack update rollback failed",
		"color": COLORS.critical,
	},
	"UPDATE_ROLLBACK_IN_PROGRESS": {
		"title": "Stack update rollback in progress",
		"color": COLORS.warning,
	},
};
