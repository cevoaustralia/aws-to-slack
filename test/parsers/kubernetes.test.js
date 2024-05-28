/* eslint-disable */

// The generic parser is intended to match anything that DOES NOT match another parser.
// Update these examples below if they happen to match your custom parser format.

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
				"Message": "{\"version\":\"0\",\"id\":\"c030d66e-ccae-00a7-b7ec-f233d4182986\",\"detail-type\":\"GuardDuty Finding\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-05-28T17:55:11Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"schemaVersion\":\"2.0\",\"accountId\":\"EXAMPLE\",\"region\":\"ap-southeast-2\",\"partition\":\"aws\",\"id\":\"EXAMPLE\",\"arn\":\"arn:aws:guardduty:ap-southeast-2:EXAMPLE:detector/findingg\",\"type\":\"Discovery:Kubernetes/MaliciousIPCaller\",\"resource\":{\"resourceType\":\"EKSCluster\",\"eksClusterDetails\":{\"name\":\"eks-demo\",\"arn\":\"arn:aws:eks:ap-southeast-2:EXAMPLE:cluster/eks-demo\",\"createdAt\":1.716854656938E9,\"vpcId\":\"vpc-testvpc\",\"status\":\"ACTIVE\",\"tags\":[{\"key\":\"Blueprint\",\"value\":\"eks-demo\"}]},\"kubernetesDetails\":{\"kubernetesWorkloadDetails\":null,\"kubernetesUserDetails\":{\"username\":\"system:anonymous\",\"uid\":null,\"groups\":[\"system:unauthenticated\"],\"sessionName\":[]}}},\"service\":{\"serviceName\":\"guardduty\",\"detectorId\":\"EXAMPLE\",\"action\":{\"actionType\":\"KUBERNETES_API_CALL\",\"kubernetesApiCallAction\":{\"requestUri\":\"/version\",\"verb\":\"get\",\"sourceIPs\":[\"167.94.145.97\"],\"userAgent\":\"Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)\",\"remoteIpDetails\":{\"ipAddressV4\":\"167.94.145.97\",\"organization\":{\"asn\":\"398705\",\"asnOrg\":\"CENSYS-ARIN-02\",\"isp\":\"Censys-arin-02\",\"org\":\"Censys-arin-02\"},\"country\":{\"countryName\":\"United States\"},\"city\":{\"cityName\":\"\"},\"geoLocation\":{\"lat\":37.751,\"lon\":-97.822}},\"statusCode\":200}},\"resourceRole\":\"TARGET\",\"additionalInfo\":{\"threatListName\":\"ProofPoint\",\"value\":\"{\\\"threatListName\\\":\\\"ProofPoint\\\"}\",\"type\":\"default\"},\"evidence\":{\"threatIntelligenceDetails\":[{\"threatListName\":\"ProofPoint\",\"threatNames\":[]}]},\"eventFirstSeen\":\"2024-05-28T17:50:48.681Z\",\"eventLastSeen\":\"2024-05-28T17:50:48.681Z\",\"archived\":false,\"count\":1},\"severity\":5,\"createdAt\":\"2024-05-28T17:51:52.721Z\",\"updatedAt\":\"2024-05-28T17:51:52.721Z\",\"title\":\"A Kubernetes API commonly used in Discovery tactics invoked from a known malicious IP address.\",\"description\":\"A Kubernetes API commonly used in Discovery tactics was invoked on cluster eks-demo from known malicious IP address 167.94.145.97.\"}}",
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


const mock = require("./_parser_mock").named("guardduty");
mock.matchesEvent(simpleSnsPacket);

mock.matchesEventWithDetail(simpleSnsPacket, {
	"author_name": "Amazon GuardDuty",
	"color": "warning",
	"fallback": "A Kubernetes API commonly used in Discovery tactics invoked from a known malicious IP address. A Kubernetes API commonly used in Discovery tactics was invoked on cluster eks-demo from known malicious IP address 167.94.145.97.",
	"title": "A Kubernetes API commonly used in Discovery tactics invoked from a known malicious IP address."
});
