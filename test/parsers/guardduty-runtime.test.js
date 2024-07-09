/* eslint-disable */

// The generic parser is intended to match anything that DOES NOT match another parser.
// Update these examples below if they happen to match your custom parser format.

const findingsMock = require("./_parser_mock").named("guardduty-findings");
const runtimeMock = require("./_parser_mock").named("guardduty-runtime");

const simpleSnsPacket = {
	Records: [{
			"EventSource": "aws:sns",
			"EventVersion": "1.0",
			"EventSubscriptionArn": `arn:aws:sns:region:account-id:topicname:subscriptionid`,
			"Sns": {
				"Type": "Notification",
				"TopicArn": `arn:aws:sns:region:account-id:topicname`,
				"Subject": "TestInvoke",
				"MessageId": "sample-message",
				"Message": "{\"version\":\"0\",\"id\":\"c030d66e-ccae-00a7-b7ec-f233d4182986\",\"detail-type\":\"GuardDuty Finding\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-05-28T17:55:11Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"schemaVersion\":\"2.0\",\"accountId\":\"CHILD-EXAMPLE\",\"region\":\"ap-southeast-2\",\"partition\":\"aws\",\"id\":\"EXAMPLE\",\"arn\":\"arn:aws:guardduty:ap-southeast-2:EXAMPLE:detector/findingg\",\"type\":\"Discovery:Kubernetes/MaliciousIPCaller\",\"resource\":{\"resourceType\":\"EKSCluster\",\"eksClusterDetails\":{\"name\":\"eks-demo\",\"arn\":\"arn:aws:eks:ap-southeast-2:EXAMPLE:cluster/eks-demo\",\"createdAt\":1.716854656938E9,\"vpcId\":\"vpc-testvpc\",\"status\":\"ACTIVE\",\"tags\":[{\"key\":\"Blueprint\",\"value\":\"eks-demo\"}]},\"kubernetesDetails\":{\"kubernetesWorkloadDetails\":null,\"kubernetesUserDetails\":{\"username\":\"system:anonymous\",\"uid\":null,\"groups\":[\"system:unauthenticated\"],\"sessionName\":[]}}},\"service\":{\"serviceName\":\"guardduty\",\"detectorId\":\"EXAMPLE\",\"action\":{\"actionType\":\"KUBERNETES_API_CALL\",\"kubernetesApiCallAction\":{\"requestUri\":\"/version\",\"verb\":\"get\",\"sourceIPs\":[\"167.94.145.97\"],\"userAgent\":\"Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)\",\"remoteIpDetails\":{\"ipAddressV4\":\"167.94.145.97\",\"organization\":{\"asn\":\"398705\",\"asnOrg\":\"CENSYS-ARIN-02\",\"isp\":\"Censys-arin-02\",\"org\":\"Censys-arin-02\"},\"country\":{\"countryName\":\"United States\"},\"city\":{\"cityName\":\"\"},\"geoLocation\":{\"lat\":37.751,\"lon\":-97.822}},\"statusCode\":200}},\"resourceRole\":\"TARGET\",\"additionalInfo\":{\"threatListName\":\"ProofPoint\",\"value\":\"{\\\"threatListName\\\":\\\"ProofPoint\\\"}\",\"type\":\"default\"},\"evidence\":{\"threatIntelligenceDetails\":[{\"threatListName\":\"ProofPoint\",\"threatNames\":[]}]},\"eventFirstSeen\":\"2024-05-28T17:50:48.681Z\",\"eventLastSeen\":\"2024-05-28T17:50:48.681Z\",\"archived\":false,\"count\":1},\"severity\":5,\"createdAt\":\"2024-05-28T17:51:52.721Z\",\"updatedAt\":\"2024-05-28T17:51:52.721Z\",\"title\":\"A Kubernetes API commonly used in Discovery tactics invoked from a known malicious IP address.\",\"description\":\"A Kubernetes API commonly used in Discovery tactics was invoked on cluster eks-demo from known malicious IP address 167.94.145.97.\"}}",
				"Timestamp": "2024-05-28T17:55:12.020Z",
				"SignatureVersion": "1",
				"Signature": "EXAMPLE",
				"SigningCertUrl": "EXAMPLE",
				"UnsubscribeUrl": "EXAMPLE",
				"MessageAttributes": {}
			}
		}
	]
};


findingsMock.matchesEvent(simpleSnsPacket);

findingsMock.matchesEventWithDetail(simpleSnsPacket, {
	"author_name": "Amazon GuardDuty",
	"color": "warning",
	"fallback": "A Kubernetes API commonly used in Discovery tactics invoked from a known malicious IP address. A Kubernetes API commonly used in Discovery tactics was invoked on cluster eks-demo from known malicious IP address 167.94.145.97.",
	"title": "A Kubernetes API commonly used in Discovery tactics invoked from a known malicious IP address."
});


const unhealthyRuntimeProtection = {
	Records: [
		{
			"EventSource": "aws:sns",
			"EventVersion": "1.0",
			"EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack:6635ff10-c98f-455b-90f7-9b8386082633",
			"Sns": {
				"Type": "Notification",
				"MessageId": "fb4becf1-f88c-5ff5-b12d-b2226236905b",
				"TopicArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack",
				"Subject": null,
				"Message": "{\"version\":\"0\",\"id\":\"a2f5f101-a7a3-47b3-2287-e2a83135cf7a\",\"detail-type\":\"GuardDuty Runtime Protection Unhealthy\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-05-31T09:29:28Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"accountId\":\"CHILD-EXAMPLE\",\"resourceDetails\":{\"resourceType\":\"EKS\",\"eksClusterDetails\":{\"clusterName\":\"eks-demo\",\"availableNodes\":-1,\"desiredNodes\":-1,\"addonDetails\":{\"addonVersion\":\"v1.6.1-eksbuild.1\",\"addonStatus\":\"DELETED\"}}},\"previousStatus\":\"Healthy\",\"currentStatus\":\"Unhealthy\",\"issue\":\"\",\"lastUpdatedAt\":1717147358760000}}",
				"Timestamp": "2024-05-31T09:29:30.100Z",
				"SignatureVersion": "1",
				"Signature": "EXAMPLE",
				"SigningCertUrl": "EXAMPLE",
				"UnsubscribeUrl": "EXAMPLE",
				"MessageAttributes": {}
			}
		}
	]
}

runtimeMock.matchesEvent(unhealthyRuntimeProtection);

runtimeMock.matchesEventWithDetail(unhealthyRuntimeProtection, {
	"author_name": "Amazon GuardDuty",
	"color": "danger",
	"fallback": "GuardDuty Runtime Protection Unhealthy ",
	"title": "GuardDuty Runtime Protection Unhealthy"
});

const healthyRuntimeProtection = {
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
				"Message": "{\"version\":\"0\",\"id\":\"4eaf90cc-a2e2-06ab-1ac1-f464a1aa7412\",\"detail-type\":\"GuardDuty Runtime Protection Healthy\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-05-31T07:53:14Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"accountId\":\"CHILD-:"wEXAMPLE\",\"resourceDetails\":{\"resourceType\":\"EC2\",\"ec2InstanceDetails\":{\"instanceId\":\"i-0e5f6345341fd7144\",\"instanceType\":\"t3.medium\",\"clusterArn\":\"arn:aws:eks:ap-southeast-2:EXAMPLE:cluster/eks-demo\",\"agentDetails\":{\"version\":\"v1.6.1\"},\"managementType\":\"MANUAL\"}},\"previousStatus\":\"Unhealthy\",\"currentStatus\":\"Healthy\",\"issue\":\"\",\"lastUpdatedAt\":1717141247000}}",
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


runtimeMock.matchesEvent(healthyRuntimeProtection);

runtimeMock.matchesEventWithDetail(healthyRuntimeProtection, {
	"author_name": "Amazon GuardDuty",
	"color": "good",
	"fallback": "GuardDuty Runtime Protection Healthy ",
	"title": "GuardDuty Runtime Protection Healthy",
	"fields": [
		{
			"short": true,
			"title": "Account",
			"value": "CHILD-EXAMPLE",
		},
		{
			"short": true,
			"title": "Region",
			"value": "ap-southeast-2",
		},
		{
			"short": true,
			"title": "Resource Type",
			"value": "EC2",
		},
		{
			"short": true,
			"title": "Instance",
			"value": "i-0e5f6345341fd7144",
		},
		{
			"short": true,
			"title": "Instance Type",
			"value": "t3.medium",
		},
		{
			"short": false,
			"title": "ClusterArn",
			"value": "arn:aws:eks:ap-southeast-2:EXAMPLE:cluster/eks-demo",
		},
		{
			"short": true,
			"title": "Agent Version",
			"value": "v1.6.1",
		},
		{
			"short": true,
			"title": "Management Type",
			"value": "MANUAL",
		},
	]
});

const healthyECSGuardDuty = {
	"Records": [
		{
			"EventSource": "aws:sns",
			"EventVersion": "1.0",
			"EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack:6635ff10-c98f-455b-90f7-9b8386082633",
			"Sns": {
				"Type": "Notification",
				"MessageId": "b07dddbc-90ef-59d9-8a06-83643fa2dbc1",
				"TopicArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack",
				"Subject": null,
				"Message": "{\"version\":\"0\",\"id\":\"a0b44948-7c77-790e-b927-481427f6a97b\",\"detail-type\":\"GuardDuty Runtime Protection Healthy\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-06-04T05:58:35Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"accountId\":\"CHILD-EXAMPLE\",\"resourceDetails\":{\"resourceType\":\"ECS\",\"ecsClusterDetails\":{\"clusterName\":\"buildkite-deploy-dev-Cluster-1O47RNJPQMRI6-EcsCluster-RPPZMvAnkFJP\",\"fargateDetails\":{\"issues\":[],\"managementType\":\"AUTO_MANAGED\"},\"containerInstanceDetails\":{\"coveredContainerInstances\":0,\"compatibleContainerInstances\":0}}},\"previousStatus\":\"Unhealthy\",\"currentStatus\":\"Healthy\",\"issue\":\"\",\"lastUpdatedAt\":1717480351457}}",
				"Timestamp": "2024-06-04T05:58:37.795Z",
				"SignatureVersion": "1",
				"Signature": "EXAMPLE",
				"SigningCertUrl": "EXAMPLE",
				"UnsubscribeUrl": "EXAMPLE",
				"MessageAttributes": {}
			}
		}
	]
}

runtimeMock.matchesEvent(healthyECSGuardDuty);

runtimeMock.matchesEventWithDetail(healthyECSGuardDuty, {
	"author_name": "Amazon GuardDuty",
	"color": "good",
	"fallback": "GuardDuty Runtime Protection Healthy ",
	"title": "GuardDuty Runtime Protection Healthy",
	"fields": [
		{
			"short": true,
			"title": "Account",
			"value": "CHILD-EXAMPLE",
		},
		{
			"short": true,
			"title": "Region",
			"value": "ap-southeast-2",
		},
		{
			"short": true,
			"title": "Resource Type",
			"value": "ECS",
		},
		{
			"short": true,
			"title": "Cluster Name",
			"value": "buildkite-deploy-dev-Cluster-1O47RNJPQMRI6-EcsCluster-RPPZMvAnkFJP",
		},
		{
			"short": true,
			"title": "Management Type",
			"value": "AUTO_MANAGED",
		},
	]
});


const unhealthyECSEvent = {
	"Records": [
		{
			"EventSource": "aws:sns",
			"EventVersion": "1.0",
			"EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack:6635ff10-c98f-455b-90f7-9b8386082633",
			"Sns": {
				"Type": "Notification",
				"MessageId": "daa6ae66-99d9-5e51-853f-f0b1e003cbfa",
				"TopicArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack",
				"Subject": null,
				"Message": "{\"version\":\"0\",\"id\":\"7e706286-0e00-7515-f2be-0793fd3092d9\",\"detail-type\":\"GuardDuty Runtime Protection Unhealthy\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-06-03T07:58:16Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"accountId\":\"CHILD-EXAMPLE\",\"resourceDetails\":{\"resourceType\":\"ECS\",\"ecsClusterDetails\":{\"clusterName\":\"buildkite-deploy-dev-Cluster-1O47RNJPQMRI6-EcsCluster-RPPZMvAnkFJP\",\"fargateDetails\":{\"issues\":[\"Others : Unidentified issue(s), for task(s) in TaskDefinition 'buildkite:17' . Refer documentation\"],\"managementType\":\"AUTO_MANAGED\"},\"containerInstanceDetails\":{\"coveredContainerInstances\":0,\"compatibleContainerInstances\":0}}},\"previousStatus\":\"Healthy\",\"currentStatus\":\"Unhealthy\",\"issue\":\"\",\"lastUpdatedAt\":1717401173897}}",
				"Timestamp": "2024-06-03T07:58:18.667Z",
				"SignatureVersion": "1",
				"Signature": "EXAMPLE",
				"SigningCertUrl": "EXAMPLE",
				"UnsubscribeUrl": "EXAMPLE",
				"MessageAttributes": {}
			}
		}
	]
}


runtimeMock.matchesEvent(unhealthyECSEvent);

runtimeMock.matchesEventWithDetail(unhealthyECSEvent, {
	"author_name": "Amazon GuardDuty",
	"color": "danger",
	"fallback": "GuardDuty Runtime Protection Unhealthy ",
	"title": "GuardDuty Runtime Protection Unhealthy",
	"fields": [
		{
			"short": true,
			"title": "Account",
			"value": "CHILD-EXAMPLE",
		},
		{
			"short": true,
			"title": "Region",
			"value": "ap-southeast-2",
		},
		{
			"short": true,
			"title": "Resource Type",
			"value": "ECS",
		},
		{
			"short": true,
			"title": "Cluster Name",
			"value": "buildkite-deploy-dev-Cluster-1O47RNJPQMRI6-EcsCluster-RPPZMvAnkFJP",
		},
		{
			"short": false,
			"title": "Issue",
			"value": "Others : Unidentified issue(s), for task(s) in TaskDefinition 'buildkite:17' . Refer documentation",
		},
		{
			"short": true,
			"title": "Management Type",
			"value": "AUTO_MANAGED",
		},
	]
});
