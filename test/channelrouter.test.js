/* eslint-disable */

const EventDef = require('../src/eventdef');
const ChannelRouter = require('../src/router');

const handler = new ChannelRouter();

beforeAll(async () => {
	handler.channelConfig = [
		{ key: new RegExp(".*-securityhub-.*"), channel: "test-securityhub-channel" },
		{ key: new RegExp(".*-guardduty-.*"), channel: "test-guardduty-channel" },
		{ key: new RegExp(".*-foobar-.*"), channel: "test-foobar-channel" },
		{ key: new RegExp("123456789012-.*-.*"), channel: "test-123456789012-channel" },
	];
})


test(`ChannelRouter resolves no match`, async () => {
	const testArn = "arn:aws:glue:eu-west-1:else:table/d1/t1:suffix";
	const event = {
		test1: "test89",
		source: "something",
		test8: 7,
		region: "us-west-2",
		resources: [ testArn ]
	};
	const result = new EventDef(event);

	const channel = handler.resolveChannel(result)

	expect(channel).toEqual([null])
});


test(`ChannelRouter resolves source to channel`, async () => {
	const testArn = "arn:aws:glue:eu-west-1:123456789012:table/d1/t1:suffix";
	const event = {
		test1: "test89",
		source: "foobar",
		test8: 7,
		region: "us-west-2",
		resources: [ testArn ]
	};
	const result = new EventDef(event);

	const channel = handler.resolveChannel(result)

	expect(channel).toEqual(["test-foobar-channel", "test-123456789012-channel"])
});


test(`ChannelRouter resolves account to channel`, async () => {
	const testArn = "arn:aws:glue:eu-west-1:123456789012:table/d1/t1:suffix";
	const event = {
		test1: "test89",
		source: "barbaz",
		test8: 7,
		region: "us-west-2",
		resources: [ testArn ]
	};
	const result = new EventDef(event);

	const channel = handler.resolveChannel(result)

	expect(channel).toEqual(["test-123456789012-channel"])
});

test(`ChannelRouter resolves from actual payload`, async () => {
	const event = {
		"Records": [
			{
				"EventSource": "aws:sns",
				"EventVersion": "1.0",
				"EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack:6635ff10-c98f-455b-90f7-9b8386082633",
				"Sns": {
					"Type": "Notification",
					"MessageId": "db0f2d8a-dabf-53a0-92de-73595e93e71b",
					"TopicArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack",
					"Subject": null,
					"Message": "{\"version\":\"0\",\"id\":\"4eaf90cc-a2e2-06ab-1ac1-f464a1aa7412\",\"detail-type\":\"GuardDuty Runtime Protection Healthy\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-05-31T07:53:14Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"accountId\":\"CHILD-EXAMPLE\",\"resourceDetails\":{\"resourceType\":\"EC2\",\"ec2InstanceDetails\":{\"instanceId\":\"i-0e5f6345341fd7144\",\"instanceType\":\"t3.medium\",\"clusterArn\":\"arn:aws:eks:ap-southeast-2:EXAMPLE:cluster/eks-demo\",\"agentDetails\":{\"version\":\"v1.6.1\"},\"managementType\":\"MANUAL\"}},\"previousStatus\":\"Unhealthy\",\"currentStatus\":\"Healthy\",\"issue\":\"\",\"lastUpdatedAt\":1717141247000}}",
					"Timestamp": "2024-05-31T07:53:16.192Z",
					"SignatureVersion": "1",
					"Signature": "EXAMPLE",
					"SigningCertUrl": "EXAMPLE",
					"UnsubscribeUrl": "EXAMPLE",
					"MessageAttributes": {}
				}
			}
		]
	}

	const result = new EventDef(event);

	handler.addRoute(".*-guard.*", "testme")
	handler.addRoute(".*-guard.*", "testme")
	handler.addRoute(".*-guard.*", "testme")

	const channel = handler.resolveChannel(result)

	expect(channel).toEqual(["test-guardduty-channel", "testme"])
});


test(`ChannelRouter removes duplicate channel names`, async () => {
	const event = {
		"Records": [
			{
				"EventSource": "aws:sns",
				"EventVersion": "1.0",
				"EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack:6635ff10-c98f-455b-90f7-9b8386082633",
				"Sns": {
					"Type": "Notification",
					"MessageId": "db0f2d8a-dabf-53a0-92de-73595e93e71b",
					"TopicArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack",
					"Subject": null,
					"Message": "{\"version\":\"0\",\"id\":\"4eaf90cc-a2e2-06ab-1ac1-f464a1aa7412\",\"detail-type\":\"GuardDuty Runtime Protection Healthy\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-05-31T07:53:14Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"accountId\":\"CHILD-EXAMPLE\",\"resourceDetails\":{\"resourceType\":\"EC2\",\"ec2InstanceDetails\":{\"instanceId\":\"i-0e5f6345341fd7144\",\"instanceType\":\"t3.medium\",\"clusterArn\":\"arn:aws:eks:ap-southeast-2:EXAMPLE:cluster/eks-demo\",\"agentDetails\":{\"version\":\"v1.6.1\"},\"managementType\":\"MANUAL\"}},\"previousStatus\":\"Unhealthy\",\"currentStatus\":\"Healthy\",\"issue\":\"\",\"lastUpdatedAt\":1717141247000}}",
					"Timestamp": "2024-05-31T07:53:16.192Z",
					"SignatureVersion": "1",
					"Signature": "EXAMPLE",
					"SigningCertUrl": "EXAMPLE",
					"UnsubscribeUrl": "EXAMPLE",
					"MessageAttributes": {}
				}
			}
		]
	}

	const result = new EventDef(event);

	handler.addRoute(".*-guard.*", "testme")
	handler.addRoute(".*-guard.*", "testme")
	handler.addRoute(".*-guard.*", "testme")

	const channel = handler.resolveChannel(result)

	expect(channel).toEqual(["test-guardduty-channel", "testme"])
});