/* eslint-disable */

// The generic parser is intended to match anything that DOES NOT match another parser.
// Update these examples below if they happen to match your custom parser format.

const mockFindings = require("./_parser_mock").named("guardduty-findings");
const mockApiCall = require("./_parser_mock").named("guardduty-apicall");

const simpleSnsPacket = {
	Records: [{
		"EventVersion": "1.0",
		"EventSubscriptionArn": `arn:aws:sns:region:account-id:topicname:subscriptionid`,
		"EventSource": "aws:sns",
		"Sns": {
			"SignatureVersion": "1",
			"Timestamp": "1970-01-01T00:00:00.000Z",
			"Signature": "EXAMPLE",
			"SigningCertUrl": "EXAMPLE",
			"MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
			"Message": "{\"version\":\"0\",\"id\":\"4565c69d-00e7-e740-2b17-234d\",\"detail-type\":\"GuardDuty Finding\",\"source\":\"aws.guardduty\",\"account\":\"12345678\",\"time\":\"2019-02-21T06:07:17Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"schemaVersion\":\"2.0\",\"accountId\":\"845345345\",\"region\":\"ap-southeast-2\",\"partition\":\"aws\",\"id\":\"345rf3ff\",\"arn\":\"arn:aws:guardduty:ap-southeast-2:123456778:detector/f0b004e2d3c8a11f786fa8faec50b19a/finding/18b48550bee9b37e3953983474f0f59d\",\"type\":\"Recon:EC2/PortProbeUnprotectedPort\",\"resource\":{\"resourceType\":\"Instance\",\"instanceDetails\":{\"instanceId\":\"i-blart\",\"instanceType\":\"t2.micro\",\"launchTime\":\"2019-02-20T11:00:56Z\",\"platform\":null,\"productCodes\":[],\"iamInstanceProfile\":null,\"networkInterfaces\":[{\"ipv6Addresses\":[],\"networkInterfaceId\":\"eni-0af858c8afc15a077\",\"privateDnsName\":\"ip-172-31-8-176.ap-southeast-2.compute.internal\",\"privateIpAddress\":\"172.31.8.176\",\"privateIpAddresses\":[{\"privateDnsName\":\"ip-172-31-8-176.ap-southeast-2.compute.internal\",\"privateIpAddress\":\"172.31.8.176\"}],\"subnetId\":\"subnet-453454534\",\"vpcId\":\"vpc-453454534\",\"securityGroups\":[{\"groupName\":\"default\",\"groupId\":\"sg-453454534\"}],\"publicDnsName\":\"ec2-52-64-107-188.ap-southeast-2.compute.amazonaws.com\",\"publicIp\":\"52.64.107.188\"}],\"tags\":[{\"key\":\"OwnerContact\",\"value\":\"test@example.com\"}],\"instanceState\":\"running\",\"availabilityZone\":\"ap-southeast-2b\",\"imageId\":\"ami-02fd0b06f06d93dfc\",\"imageDescription\":\"Amazon Linux AMI 2018.03.0.20181129 x86_64 HVM gp2\"}},\"service\":{\"serviceName\":\"guardduty\",\"detectorId\":\"f0b004e2d3c8a11f786fa8faec50b19a\",\"action\":{\"actionType\":\"PORT_PROBE\",\"portProbeAction\":{\"portProbeDetails\":[{\"localPortDetails\":{\"port\":22,\"portName\":\"SSH\"},\"remoteIpDetails\":{\"ipAddressV4\":\"122.2.223.242\",\"organization\":{\"asn\":\"9299\",\"asnOrg\":\"Philippine Long Distance Telephone Company\",\"isp\":\"Philippine Long Distance Telephone\",\"org\":\"Philippine Long Distance Telephone\"},\"country\":{\"countryName\":\"Philippines\"},\"city\":{\"cityName\":\"Dolores\"},\"geoLocation\":{\"lat\":14.5703,\"lon\":121.1472}}}],\"blocked\":false}},\"resourceRole\":\"TARGET\",\"additionalInfo\":{\"threatName\":\"Scanner\",\"threatListName\":\"ProofPoint\"},\"eventFirstSeen\":\"2019-02-20T11:13:58Z\",\"eventLastSeen\":\"2019-02-21T05:51:10Z\",\"archived\":false,\"count\":49},\"severity\":2,\"createdAt\":\"2019-02-20T11:19:09.523Z\",\"updatedAt\":\"2019-02-21T06:00:14.003Z\",\"title\":\"Unprotected port on EC2 instance i-blart is being probed.\",\"description\":\"EC2 instance has an unprotected port which is being probed by a known malicious host.\"}}",
			"MessageAttributes": {
				"Test": {
					"Type": "String",
					"Value": "TestString"
				},
				"TestBinary": {
					"Type": "Binary",
					"Value": "TestBinary"
				}
			},
			"Type": "Notification",
			"UnsubscribeUrl": "EXAMPLE",
			"TopicArn": `arn:aws:sns:region:account-id:topicname`,
			"Subject": "TestInvoke"
		}
	}]
};


mockFindings.matchesEvent(simpleSnsPacket);

mockFindings.matchesEventWithDetail(simpleSnsPacket, {
	"author_name": "Amazon GuardDuty",
	"color": "#A8A8A8",
	"fallback":"Unprotected port on EC2 instance i-blart is being probed. EC2 instance has an unprotected port which is being probed by a known malicious host.",
	"title": "Unprotected port on EC2 instance i-blart is being probed.",
});


const archivePacket = {
    "Records": [
        {
            "EventSource": "aws:sns",
            "EventVersion": "1.0",
            "EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:Guard-Duty-Alert:be9ea46c-59bb-4fb4-b1ae-edd53e1a6ef4",
            "Sns": {
                "Type": "Notification",
                "MessageId": "451c28e7-2709-512f-a683-74e21001f05a",
                "TopicArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:Guard-Duty-Alert",
                "Subject": null,
                "Message": "{\"version\":\"0\",\"id\":\"bd3b1ef2-d3ff-8558-350f-46c45c95124c\",\"detail-type\":\"AWS API Call via CloudTrail\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2022-12-03T11:36:31Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"eventVersion\":\"1.08\",\"userIdentity\":{\"type\":\"AssumedRole\",\"principalId\":\"EXAMPLE:example@test.com\",\"arn\":\"arn:aws:sts::EXAMPLE:assumed-role/AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f/example@test.com\",\"accountId\":\"EXAMPLE\",\"accessKeyId\":\"ASIAUDN2TOUFFAG5HLW7\",\"sessionContext\":{\"sessionIssuer\":{\"type\":\"Role\",\"principalId\":\"EXAMPLE\",\"arn\":\"arn:aws:iam::EXAMPLE:role/aws-reserved/sso.amazonaws.com/ap-southeast-2/AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f\",\"accountId\":\"EXAMPLE\",\"userName\":\"AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f\"},\"webIdFederationData\":{},\"attributes\":{\"creationDate\":\"2022-12-03T11:35:36Z\",\"mfaAuthenticated\":\"false\"}}},\"eventTime\":\"2022-12-03T11:36:31Z\",\"eventSource\":\"guardduty.amazonaws.com\",\"eventName\":\"ArchiveFindings\",\"awsRegion\":\"ap-southeast-2\",\"sourceIPAddress\":\"202.91.207.179\",\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\",\"requestParameters\":{\"findingIds\":[\"56c262cb80b3afa1cc47fa0020e93b32\"],\"detectorId\":\"8eb0051b873e9d57e7abc9481954d0b8\"},\"responseElements\":null,\"requestID\":\"1f58d79c-f990-4948-bdf0-99219c88f6d1\",\"eventID\":\"6c9e7ce6-6558-4f86-8e32-def7502d7fd5\",\"readOnly\":false,\"eventType\":\"AwsApiCall\",\"managementEvent\":true,\"recipientAccountId\":\"EXAMPLE\",\"eventCategory\":\"Management\"}}",
                "Timestamp": "2022-12-03T11:36:40.995Z",
                "SignatureVersion": "1",
				"Signature": "EXAMPLE",
				"SigningCertUrl": "EXAMPLE",
				"UnsubscribeUrl": "EXAMPLE",
                "MessageAttributes": {}
            }
        }
    ]
}
mockApiCall.matchesEvent(archivePacket);

mockApiCall.matchesEventWithDetail(archivePacket, {
	"author_name": "Amazon GuardDuty",
	"color": "good",
	"fallback":"Findings Archived Findings Archived by EXAMPLE:example@test.com",
	"title": "Findings Archived",
	"fields": [
		{
			"short": true,
			"title": "Account",
			"value": "EXAMPLE",
		},
		{
			"short": true,
			"title": "Region",
			"value": "ap-southeast-2",
		},
		{
			"short": false,
			"title": "Actioned by",
			"value": "EXAMPLE:example@test.com",
		},
		{
			"short": false,
			"title": "Finding ID",
			"value": "56c262cb80b3afa1cc47fa0020e93b32",
		},
	]
});

const archiveMultiPacket = {
    "Records": [
        {
            "EventSource": "aws:sns",
            "EventVersion": "1.0",
            "EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:Guard-Duty-Alert:be9ea46c-59bb-4fb4-b1ae-edd53e1a6ef4",
            "Sns": {
                "Type": "Notification",
                "MessageId": "39b5f364-e86e-589f-954f-af61df726211",
                "TopicArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:Guard-Duty-Alert",
                "Subject": null,
                "Message": "{\"version\":\"0\",\"id\":\"d7f20cbf-35da-2ab9-2af9-f57c33528b95\",\"detail-type\":\"AWS API Call via CloudTrail\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2022-12-03T11:36:39Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"eventVersion\":\"1.08\",\"userIdentity\":{\"type\":\"AssumedRole\",\"principalId\":\"EXAMPLE:example@test.com\",\"arn\":\"arn:aws:sts::EXAMPLE:assumed-role/AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f/example@test.com\",\"accountId\":\"EXAMPLE\",\"accessKeyId\":\"ASIAUDN2TOUFFAG5HLW7\",\"sessionContext\":{\"sessionIssuer\":{\"type\":\"Role\",\"principalId\":\"EXAMPLE\",\"arn\":\"arn:aws:iam::EXAMPLE:role/aws-reserved/sso.amazonaws.com/ap-southeast-2/AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f\",\"accountId\":\"EXAMPLE\",\"userName\":\"AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f\"},\"webIdFederationData\":{},\"attributes\":{\"creationDate\":\"2022-12-03T11:35:36Z\",\"mfaAuthenticated\":\"false\"}}},\"eventTime\":\"2022-12-03T11:36:39Z\",\"eventSource\":\"guardduty.amazonaws.com\",\"eventName\":\"ArchiveFindings\",\"awsRegion\":\"ap-southeast-2\",\"sourceIPAddress\":\"202.91.207.179\",\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\",\"requestParameters\":{\"findingIds\":[\"9ec25610d073e0d88a29da315da6f340\",\"26c24811191298114594f30b05a7b2b9\",\"6ac235608add1b18bd0a3150de6f567f\"],\"detectorId\":\"8eb0051b873e9d57e7abc9481954d0b8\"},\"responseElements\":null,\"requestID\":\"ad9a8364-b84d-43ae-81e1-dd0bcbbbe26f\",\"eventID\":\"c46a291b-4ad2-48ef-b032-73ad615abc02\",\"readOnly\":false,\"eventType\":\"AwsApiCall\",\"managementEvent\":true,\"recipientAccountId\":\"EXAMPLE\",\"eventCategory\":\"Management\"}}",
                "Timestamp": "2022-12-03T11:37:00.206Z",
                "SignatureVersion": "1",
				"Signature": "EXAMPLE",
				"SigningCertUrl": "EXAMPLE",
                "UnsubscribeUrl": "EXAMPLE",
                "MessageAttributes": {}
            }
        }
    ]
}
mockApiCall.matchesEvent(archiveMultiPacket);

mockApiCall.matchesEventWithDetail(archiveMultiPacket, {
	"author_name": "Amazon GuardDuty",
	"color": "good",
	"fallback":"Findings Archived Findings Archived by EXAMPLE:example@test.com",
	"title": "Findings Archived",
	"fields": [
		{
			"short": true,
			"title": "Account",
			"value": "EXAMPLE",
		},
		{
			"short": true,
			"title": "Region",
			"value": "ap-southeast-2",
		},
		{
			"short": false,
			"title": "Actioned by",
			"value": "EXAMPLE:example@test.com",
		},
		{
			"short": false,
			"title": "Finding ID",
			"value": "9ec25610d073e0d88a29da315da6f340",
		},
		{
			"short": false,
			"title": "Finding ID",
			"value": "26c24811191298114594f30b05a7b2b9",
		},
		{
			"short": false,
			"title": "Finding ID",
			"value": "6ac235608add1b18bd0a3150de6f567f",
		},
	]
});

const enableRuntimeMonitoring = {
	"Records": [
		{
			"EventSource": "aws:sns",
			"EventVersion": "1.0",
			"EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack:6635ff10-c98f-455b-90f7-9b8386082633",
			"Sns": {
				"Type": "Notification",
				"MessageId": "4380762d-d1b6-5c38-866f-28f538451b54",
				"TopicArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack",
				"Subject": null,
				"Message": "{\"version\":\"0\",\"id\":\"042fdeb8-49d7-83dd-089e-17db86cbe678\",\"detail-type\":\"AWS API Call via CloudTrail\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-06-04T10:08:39Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"eventVersion\":\"1.09\",\"userIdentity\":{\"type\":\"AssumedRole\",\"principalId\":\"EXAMPLE:test@example.com\",\"arn\":\"arn:aws:sts::EXAMPLE:assumed-role/AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f/test@example.com\",\"accountId\":\"EXAMPLE\",\"accessKeyId\":\"ASIAUDN2TOUFK5IM6BNH\",\"sessionContext\":{\"sessionIssuer\":{\"type\":\"Role\",\"principalId\":\"EXAMPLE\",\"arn\":\"arn:aws:iam::EXAMPLE:role/aws-reserved/sso.amazonaws.com/ap-southeast-2/AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f\",\"accountId\":\"EXAMPLE\",\"userName\":\"AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f\"},\"attributes\":{\"creationDate\":\"2024-06-04T09:39:17Z\",\"mfaAuthenticated\":\"false\"}}},\"eventTime\":\"2024-06-04T10:08:39Z\",\"eventSource\":\"guardduty.amazonaws.com\",\"eventName\":\"UpdateDetector\",\"awsRegion\":\"ap-southeast-2\",\"sourceIPAddress\":\"194.193.53.174\",\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36\",\"requestParameters\":{\"features\":[{\"name\":\"RUNTIME_MONITORING\",\"status\":\"ENABLED\",\"additionalConfiguration\":[{\"name\":\"EKS_ADDON_MANAGEMENT\",\"status\":\"ENABLED\"},{\"name\":\"ECS_FARGATE_AGENT_MANAGEMENT\",\"status\":\"ENABLED\"},{\"name\":\"EC2_AGENT_MANAGEMENT\",\"status\":\"ENABLED\"}]}],\"detectorId\":\"8eb0051b873e9d57e7abc9481954d0b8\",\"enable\":true},\"responseElements\":null,\"requestID\":\"9f4ba10c-02f4-4941-ba35-da488caffa9b\",\"eventID\":\"24cc3fd8-bea9-407e-a5d0-a1150ed0ca4b\",\"readOnly\":false,\"eventType\":\"AwsApiCall\",\"managementEvent\":true,\"recipientAccountId\":\"EXAMPLE\",\"eventCategory\":\"Management\"}}",
				"Timestamp": "2024-06-04T10:08:51.184Z",
				"SignatureVersion": "1",
				"Signature": "EXAMPLE",
				"SigningCertUrl": "EXAMPLE",
				"UnsubscribeUrl": "EXAMPLE",
				"MessageAttributes": {}
			}
		}
	]
}

mockApiCall.matchesEvent(enableRuntimeMonitoring);

mockApiCall.matchesEventWithDetail(enableRuntimeMonitoring, {
	"author_name": "Amazon GuardDuty",
	"color": "good",
	"fallback": "GuardDuty Configuration change Actioned by EXAMPLE:test@example.com",
	"title": "GuardDuty Configuration change",
	"fields": [
		{
			"short": true,
			"title": "Account",
			"value": "EXAMPLE",
		},
		{
			"short": true,
			"title": "Region",
			"value": "ap-southeast-2",
		},
		 {
		   "short": false,
		   "title": "Actioned by",
		   "value": "EXAMPLE:test@example.com",
		 },
		 {
		   "short": true,
		   "title": "Event",
		   "value": "UpdateDetector",
		 },
		 {
		   "short": true,
		   "title": "RUNTIME_MONITORING",
		   "value": "ENABLED",
		 },
		 {
		   "short": true,
		   "title": "EKS_ADDON_MANAGEMENT",
		   "value": "ENABLED",
		 },
		 {
		   "short": true,
		   "title": "ECS_FARGATE_AGENT_MANAGEMENT",
		   "value": "ENABLED",
		 },
		 {
		   "short": true,
		   "title": "EC2_AGENT_MANAGEMENT",
		   "value": "ENABLED",
		 },
	]
});

const enableFeaturePacket = {
	"Records": [
	{
		"EventSource": "aws:sns",
		"EventVersion": "1.0",
		"EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack:6635ff10-c98f-455b-90f7-9b8386082633",
		"Sns": {
			"Type": "Notification",
			"MessageId": "46b8b01e-b9c0-5248-ad4b-eec653860ccf",
			"TopicArn": "arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack",
			"Subject": null,
			"Message": "{\"version\":\"0\",\"id\":\"692bb73f-d65f-b36a-ef99-38e1fa8f4f4a\",\"detail-type\":\"AWS API Call via CloudTrail\",\"source\":\"aws.guardduty\",\"account\":\"EXAMPLE\",\"time\":\"2024-06-04T10:09:49Z\",\"region\":\"ap-southeast-2\",\"resources\":[],\"detail\":{\"eventVersion\":\"1.09\",\"userIdentity\":{\"type\":\"AssumedRole\",\"principalId\":\"EXAMPLE:test@example.com\",\"arn\":\"arn:aws:sts::EXAMPLE:assumed-role/AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f/test@example.com\",\"accountId\":\"EXAMPLE\",\"accessKeyId\":\"ASIAUDN2TOUFK5IM6BNH\",\"sessionContext\":{\"sessionIssuer\":{\"type\":\"Role\",\"principalId\":\"EXAMPLE\",\"arn\":\"arn:aws:iam::EXAMPLE:role/aws-reserved/sso.amazonaws.com/ap-southeast-2/AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f\",\"accountId\":\"EXAMPLE\",\"userName\":\"AWSReservedSSO_AWSAdministratorAccess_6e6225578768610f\"},\"attributes\":{\"creationDate\":\"2024-06-04T09:39:17Z\",\"mfaAuthenticated\":\"false\"}}},\"eventTime\":\"2024-06-04T10:09:49Z\",\"eventSource\":\"guardduty.amazonaws.com\",\"eventName\":\"UpdateDetector\",\"awsRegion\":\"ap-southeast-2\",\"sourceIPAddress\":\"194.193.53.174\",\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36\",\"requestParameters\":{\"features\":[{\"name\":\"LAMBDA_NETWORK_LOGS\",\"status\":\"ENABLED\"}],\"detectorId\":\"8eb0051b873e9d57e7abc9481954d0b8\",\"enable\":true},\"responseElements\":null,\"requestID\":\"a60f2482-2410-4ea1-894a-11b27427fe36\",\"eventID\":\"58cd082c-5a4d-4e77-99e2-b526633bcdd8\",\"readOnly\":false,\"eventType\":\"AwsApiCall\",\"managementEvent\":true,\"recipientAccountId\":\"EXAMPLE\",\"eventCategory\":\"Management\"}}",
			"Timestamp": "2024-06-04T10:10:14.810Z",
			"SignatureVersion": "1",
			"Signature": "UXl0Ebk/PKb74LRK/06kwVJ/qGQWj7oa/CBeOxMTwTHft1Qmt8gEC25Db5rk4CyRoTeedjokm1VUYnHO66iKlY1fQ0w2zlM0STQOU+Fev32io3yFnbMYlLPEYvxt8F3HjyUO2qUpnsfsE/h7NgRKPmNQEMsqMTCdlnyvrZ8UmNBmXfRtmU/rabW16Rt0AOP/Xq3TBJHm1irE3qKNsX8cz048ewrG53wBeuJI7icstkLZdUIZqQXBIypjm1BTP5zIC7+l++mhOIy0OfuXJ3kDhCuxZowK283XkSHRC/MfjCroOUdlAg6NH0MH8QoHHM+q3XCWwDbivqewaTVJ6SCNLg==",
			"SigningCertUrl": "https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-60eadc530605d63b8e62a523676ef735.pem",
			"UnsubscribeUrl": "https://sns.ap-southeast-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:ap-southeast-2:EXAMPLE:aws-to-slack:6635ff10-c98f-455b-90f7-9b8386082633",
			"MessageAttributes": {}
		}
	}
]}

mockApiCall.matchesEvent(enableFeaturePacket);

mockApiCall.matchesEventWithDetail(enableFeaturePacket, {
	"author_name": "Amazon GuardDuty",
	"color": "good",
	"fallback": "GuardDuty Configuration change Actioned by EXAMPLE:test@example.com",
	"title": "GuardDuty Configuration change",
	"fields": [
		{
			"short": true,
			"title": "Account",
			"value": "EXAMPLE",
		},
		{
			"short": true,
			"title": "Region",
			"value": "ap-southeast-2",
		},
		{
			"short": false,
			"title": "Actioned by",
			"value": "EXAMPLE:test@example.com",
		},
		{
			"short": true,
			"title": "Event",
			"value": "UpdateDetector",
		},
		{
			"short": true,
			"title": "LAMBDA_NETWORK_LOGS",
			"value": "ENABLED",
		},
	]
});