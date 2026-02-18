/*
 * Configuration of identification for account, user, environment, and checks
 */
var config = {
    /*
     * Cloud Insight API URL
     * US: api.cloudinsight.alertlogic.com
     * UK: api.cloudinsight.alertlogic.co.uk
     */
    "api_url": "api.cloudinsight.alertlogic.com",

    /*
     * Supported Regions for AWS Lambda
     */
    "supported": [
        'us-east-1',
        'us-east-2',
        'us-west-1',
        'us-west-2',
        'eu-west-1',
        'eu-west-2',
        'eu-west-3',
        'eu-central-1',
        'ap-northeast-1',
        'ap-northeast-2',
        'ap-southeast-1',
        'ap-southeast-2',
        'ap-south-1',
        'ca-central-1',
        'sa-east-1' 
    ],

    /*
     * Cloud Insight Check Configurations
     */
    "checks": {
        /*
         * Check names must match file names in checks/*.js
         */
        "sg": {
            "name": "sg",
            "enabled": false,
            "mode": ["configurationItem", "snapshotEvent"],
            "configuration": {
                "resourceTypes": [
                    "AWS::EC2::SecurityGroup"
                ],
                "approved_ports": [
                    3389,
                    22
                ]
            },
            "vulnerability": {
                id: "custom-001",
                name: "Security Group Ingress Rules Policy Violation",
                description: "Security groups were found to have rules that allow access to ports not officially approved by the security department.",
                remediation: "Restrict security group ingress rules to only include approved port ranges.",
                resolution: "Restrict security group ingress rules to only include approved port ranges. To restrict access to a approved port ranges, set the 'Port Range' field to a range/ranges approved by the security department. Be sure to delete unapproved rules after creating rules that follow official policy.",
                risk: "High",
                scope: "security group",
                ccss_score: "5.4",
                resolution_type:"Reconfigure Security Groups",
                reference:"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
                pci_concern:"N/A",
                ccss_vector: "N/A",
                evidence: "{sg_configuration,0}",
                type : "application/json"
            }
        },
        "namingConvention": {
            "name": "namingConvention",
            "enabled": false,
            "mode": ["configurationItem", "snapshotEvent"],
            "configuration": {
                /*
                * Your callback will only be called when message are received for the following AWS resource types
                */
                "resourceTypes": ["AWS::EC2::Subnet", "AWS::EC2::SecurityGroup", "AWS::EC2::Instance"],
                "conventions": [
                    {
                        "resourceTypes": [
                            "AWS::EC2::Subnet", "AWS::EC2::SecurityGroup", "AWS::EC2::Instance"
                        ],
                        "patterns": ["^[pP](rod)*$", ".*[pP](rod)"]
                        // "patterns": [".*"]
                    }
                ]
            },
            "vulnerability": {
                id: "custom-002",
                name: "AWS Resource Naming Convention Policy Violation",
                description: "AWS Resources were found that do not follow naming convention policy.",
                remediation: "Change the name of the AWS Resource to follow naming convention policy.",
                resolution: "Change the name of the AWS Resource to follow naming convention policy. To change the name of an AWS Resource, set the Name tag to the value that confirms to the naming policy.",
                risk: "Medium",
                scope: "any",
                ccss_score: "3.0",
                resolution_type:"Reconfigure Assets",
                reference:"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html",
                pci_concern:"N/A",
                ccss_vector: "N/A",
                evidence: "{sg_configuration,0}",
                type : "application/json"
            }
        },
        "requiredTags": {
            "name": "requiredTags",
            "enabled": false,
            "mode": ["configurationItem", "snapshotEvent"],
            "configuration": {
                "resourceTypes": ["AWS::EC2::Subnet", "AWS::EC2::SecurityGroup", "AWS::EC2::Instance"],
                "policies": [
                    {
                        "resourceTypes": ["AWS::EC2::Subnet", "AWS::EC2::SecurityGroup", "AWS::EC2::Instance"],
                        "tags": [
                            {
                                "key": "Name"
                            }
                        ]
                    }
                ]
            },
            "vulnerability": {
                id: "custom-003",
                name: "AWS Resource Required Tags Policy Violation",
                description: "AWS Resources were found that do are not tagged according to resource tagging policy.",
                remediation: "Add required tags to the AWS Resource to follow resource tagging policy.",
                resolution: "Add required tags to the AWS Resource to follow resource tagging policy. To add required tags to the AWS Resource, select a resource from the AWS console, go to the tags tab and add requied tags.",
                risk: "Medium",
                scope: "any",
                ccss_score: "3.0",
                resolution_type:"Reconfigure Assets",
                reference:"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html",
                pci_concern:"N/A",
                ccss_vector: "N/A",
                evidence: "{sg_configuration,0}",
                type : "application/json"
            }
        },
        "enableVpcScanning": {
            "name": "enableVpcScanning",
            "enabled": false,
            "mode": ["configurationItem", "snapshotEvent"],
            "configuration": {
                "resourceTypes": ["AWS::EC2::VPC", "AWS::EC2::Instance"]
            }
        },
        "awsConfigRules": {
            "name": "awsConfigRules",
            "enabled": false,
            "mode": ["configurationItem", "snapshotEvent", "configRule"],
            "configuration": {
                "resourceTypes": ["AWS::EC2::Subnet", "AWS::EC2::SecurityGroup", "AWS::EC2::Instance",
                                  "AWS::EC2::NetworkAcl", "AWS::EC2::RouteTable", "AWS::EC2::VPC",
                                  "AWS::EC2::InternetGateway"],
                "vulnerabilities": {
                    "required-tags": {
                        id: "custom-aws-config-rule-required-tags",
                        name: "AWS Config 'required-tags' Rule Violation",
                        description: "AWS Config Rules detected AWS Resources that do not have all required tags.",
                        remediation: "AWS Config Rule Remediation: Add required tags to the AWS Resources to satisfy AWS Config 'required-tags' rule.",
                        resolution: "Add required tags to the AWS Resources to satisfy AWS Config 'required-tags' rule. To add required tags to the AWS Resource, select a resource from the AWS console, go to the tags tab and add requied tags.",
                        risk: "Low",
                        scope: "any",
                        ccss_score: "3.0",
                        resolution_type:"Reconfigure Assets",
                        reference:"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html",
                        pci_concern:"N/A",
                        ccss_vector: "N/A",
                        evidence: {},
                        type : "application/json"
                    },
                    "restricted-common-ports": {
                        id: "custom-aws-config-rule-restricted-common-ports",
                        name: "AWS Config 'restricted-common-ports' Rule Violation",
                        description: "AWS Config Rules detected AWS Security Groups allowing unrestricted incoming TCP traffic to the specified ports.",
                        remediation: "AWS Config Rule Remediation: Ensure that security groups restrict incoming TCP traffic to specific IP address or CIDR ranges.",
                        resolution: "Update AWS Security Group to only allow incoming TCP traffic from specific IP addresses or CIDR ranges. To update security group setting select offending security group from the AWS EC2 console and update/delete offending entries.",
                        risk: "High",
                        scope: "any",
                        ccss_score: 10.0,
                        resolution_type:"Reconfigure Assets",
                        reference:"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html",
                        pci_concern:"PCI DSS 3.1 Requirement 1.1.7 Requirement to review firewall and router rule sets at least every six months",
                        ccss_vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/PL:ND/EM:A",
                        evidence: {},
                        type : "application/json"
                    },
                    "restricted-ssh": {
                        id: "custom-aws-config-rule-restricted-ssh",
                        name: "AWS Config 'restricted-ssh' Rule Violation",
                        description: "AWS Config Rules detected AWS Security Groups allowing unrestricted incoming SSH traffic.",
                        remediation: "AWS Config Rule Remediation: Ensure that security groups restrict SSH traffic to specific IP address or CIDR ranges.",
                        resolution: "Update AWS Security Group to only allow SSH traffic from specific IP addresses or CIDR ranges. To update security group setting select offending security group from the AWS EC2 console and update/delete offending entries.",
                        risk: "High",
                        scope: "any",
                        ccss_score: 10.0,
                        resolution_type:"Reconfigure Assets",
                        reference:"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html",
                        pci_concern:"PCI DSS 3.1 Requirement 1.1.7 Requirement to review firewall and router rule sets at least every six months",
                        ccss_vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C/PL:ND/EM:A",
                        evidence: {},
                        type : "application/json"
                    }
                }
            }
        },
        "awsInspector": {
            "name": "awsInspector",
            "enabled": false,
            "mode": ["scheduledEvent", "inspectorEvent"]
        },
        "eksInfrastructure": {
            "name": "eksInfrastructure",
            "enabled": false,
            "mode": ["configurationItem", "snapshotEvent"],
            "configuration": {
                "resourceTypes": [
                    "AWS::EKS::Cluster",
                    "AWS::EC2::SecurityGroup",
                    "AWS::IAM::Role"
                ],
                "policies": {
                    "clusterLogging": {
                        "requiredLogTypes": ["api", "audit", "authenticator", "controllerManager", "scheduler"]
                    },
                    "clusterVersion": {
                        "minimumVersion": "1.27"
                    },
                    "endpointAccess": {
                        "publicAccessRestricted": true
                    },
                    "encryption": {
                        "secretsEncryptionRequired": true
                    }
                }
            },
            "vulnerability": {
                id: "custom-eks-001",
                name: "EKS Cluster Security Configuration Policy Violation",
                description: "EKS Cluster was found to have security configurations that do not meet organizational policy requirements.",
                remediation: "Update the EKS cluster configuration to meet security policy requirements.",
                resolution: "Update the EKS cluster to enable required logging, restrict public endpoint access, enable secrets encryption, and ensure the cluster is running a supported Kubernetes version.",
                risk: "High",
                scope: "eks-cluster",
                ccss_score: "6.5",
                resolution_type: "Reconfigure EKS Cluster",
                reference: "https://docs.aws.amazon.com/eks/latest/userguide/security-best-practices.html",
                pci_concern: "N/A",
                ccss_vector: "N/A",
                evidence: "{eks_configuration,0}",
                type: "application/json"
            }
        },
        "eksNodeGroup": {
            "name": "eksNodeGroup",
            "enabled": false,
            "mode": ["configurationItem", "snapshotEvent"],
            "configuration": {
                "resourceTypes": [
                    "AWS::EKS::Nodegroup",
                    "AWS::EC2::SecurityGroup"
                ],
                "policies": {
                    "amiType": {
                        "allowedTypes": ["AL2_x86_64", "AL2_x86_64_GPU", "AL2_ARM_64", "BOTTLEROCKET_ARM_64", "BOTTLEROCKET_x86_64"]
                    },
                    "updateConfig": {
                        "maxUnavailable": 1
                    },
                    "requiredTags": ["Environment", "Team", "CostCenter"]
                }
            },
            "vulnerability": {
                id: "custom-eks-002",
                name: "EKS Node Group Configuration Policy Violation",
                description: "EKS Node Group was found to have configurations that do not meet organizational policy requirements.",
                remediation: "Update the EKS node group configuration to meet policy requirements.",
                resolution: "Ensure node groups use approved AMI types, have proper update configurations, and include required tags.",
                risk: "Medium",
                scope: "eks-nodegroup",
                ccss_score: "4.5",
                resolution_type: "Reconfigure EKS Node Group",
                reference: "https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html",
                pci_concern: "N/A",
                ccss_vector: "N/A",
                evidence: "{nodegroup_configuration,0}",
                type: "application/json"
            }
        }
    }
};

module.exports = config;
