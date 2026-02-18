# EKS Infrastructure Checks - Phase 1

## Overview

This document describes Phase 1 of EKS (Amazon Elastic Kubernetes Service) infrastructure checks for the CI Lambda Checks project. These checks enable security and compliance evaluations for EKS resources, similar to existing EC2 resource monitoring.

## Supported EKS Resources

Phase 1 supports the following AWS resource types:

- **AWS::EKS::Cluster** - EKS cluster configuration and security checks
- **AWS::EKS::Nodegroup** - Managed node group configuration checks
- **AWS::EC2::SecurityGroup** - Security groups associated with EKS resources
- **AWS::IAM::Role** - IAM roles used by EKS clusters

Future phases will add support for:
- AWS::EKS::FargateProfile
- EKS add-ons
- Additional security controls

## Checks Implemented

### 1. EKS Infrastructure Check (`eksInfrastructure`)

Validates EKS cluster security configurations against organizational policies.

#### Check: Cluster Logging

**Purpose:** Ensures all required control plane log types are enabled for audit and troubleshooting.

**Policy Configuration:**
```javascript
"clusterLogging": {
    "requiredLogTypes": ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}
```

**What it checks:**
- Validates that all specified log types are enabled in the cluster logging configuration
- Identifies missing log types that should be enabled

**Remediation:**
```bash
aws eks update-cluster-config \
    --name <cluster-name> \
    --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
```

#### Check: Kubernetes Version

**Purpose:** Ensures EKS clusters are running a supported Kubernetes version.

**Policy Configuration:**
```javascript
"clusterVersion": {
    "minimumVersion": "1.27"
}
```

**What it checks:**
- Compares the current cluster Kubernetes version against the minimum required version
- Flags clusters running older versions

**Remediation:**
```bash
aws eks update-cluster-version \
    --name <cluster-name> \
    --kubernetes-version 1.27
```

#### Check: Endpoint Access

**Purpose:** Prevents unrestricted public access to the EKS cluster API endpoint.

**Policy Configuration:**
```javascript
"endpointAccess": {
    "publicAccessRestricted": true
}
```

**What it checks:**
- Validates that if public endpoint access is enabled, it's restricted to specific CIDR blocks
- Flags clusters with unrestricted access (0.0.0.0/0)

**Remediation:**
```bash
aws eks update-cluster-config \
    --name <cluster-name> \
    --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=["203.0.113.0/24"]
```

Or disable public access entirely:
```bash
aws eks update-cluster-config \
    --name <cluster-name> \
    --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true
```

#### Check: Secrets Encryption

**Purpose:** Ensures Kubernetes secrets are encrypted at rest using AWS KMS.

**Policy Configuration:**
```javascript
"encryption": {
    "secretsEncryptionRequired": true
}
```

**What it checks:**
- Validates that envelope encryption is configured for Kubernetes secrets
- Checks that a KMS key is associated with the cluster

**Remediation:**
Encryption must be enabled at cluster creation time. For existing clusters, you must:
1. Create a new cluster with encryption enabled
2. Migrate workloads to the new cluster

```bash
aws eks create-cluster \
    --name <cluster-name> \
    --encryption-config '[{"resources":["secrets"],"provider":{"keyArn":"arn:aws:kms:region:account:key/key-id"}}]' \
    ...
```

### 2. EKS Node Group Check (`eksNodeGroup`)

Validates EKS managed node group configurations against organizational policies.

#### Check: AMI Type

**Purpose:** Ensures node groups use approved Amazon Machine Images.

**Policy Configuration:**
```javascript
"amiType": {
    "allowedTypes": ["AL2_x86_64", "AL2_x86_64_GPU", "AL2_ARM_64", "BOTTLEROCKET_ARM_64", "BOTTLEROCKET_x86_64"]
}
```

**What it checks:**
- Validates that the node group AMI type is in the approved list
- Flags node groups using custom or unapproved AMIs

**Remediation:**
Create a new node group with an approved AMI type:
```bash
aws eks create-nodegroup \
    --cluster-name <cluster-name> \
    --nodegroup-name <nodegroup-name> \
    --ami-type AL2_x86_64 \
    ...
```

#### Check: Update Configuration

**Purpose:** Ensures node groups have safe update policies that limit disruption.

**Policy Configuration:**
```javascript
"updateConfig": {
    "maxUnavailable": 1
}
```

**What it checks:**
- Validates that maxUnavailable doesn't exceed the policy limit
- Ensures gradual rolling updates to maintain availability

**Remediation:**
```bash
aws eks update-nodegroup-config \
    --cluster-name <cluster-name> \
    --nodegroup-name <nodegroup-name> \
    --update-config maxUnavailable=1
```

#### Check: Required Tags

**Purpose:** Enforces organizational tagging policies for cost allocation and management.

**Policy Configuration:**
```javascript
"requiredTags": ["Environment", "Team", "CostCenter"]
```

**What it checks:**
- Validates that all required tags are present on the node group
- Identifies missing tags

**Remediation:**
```bash
aws eks tag-resource \
    --resource-arn <nodegroup-arn> \
    --tags Environment=production,Team=platform,CostCenter=engineering
```

#### Check: Scaling Configuration

**Purpose:** Validates logical consistency of scaling parameters.

**What it checks:**
- minSize ≤ maxSize
- minSize ≤ desiredSize ≤ maxSize
- Basic sanity checks on scaling configuration

**Remediation:**
```bash
aws eks update-nodegroup-config \
    --cluster-name <cluster-name> \
    --nodegroup-name <nodegroup-name> \
    --scaling-config minSize=1,maxSize=10,desiredSize=3
```

## Configuration

### Enabling EKS Checks

By default, EKS checks are **disabled**. To enable them, update `config.js`:

```javascript
"eksInfrastructure": {
    "enabled": true,  // Change from false to true
    ...
}
```

```javascript
"eksNodeGroup": {
    "enabled": true,  // Change from false to true
    ...
}
```

### Customizing Policies

You can customize the policy settings to match your organization's requirements:

```javascript
"eksInfrastructure": {
    "configuration": {
        "policies": {
            "clusterLogging": {
                "requiredLogTypes": ["api", "audit"]  // Require only specific logs
            },
            "clusterVersion": {
                "minimumVersion": "1.28"  // Require newer version
            },
            "endpointAccess": {
                "publicAccessRestricted": true  // Keep as true for security
            },
            "encryption": {
                "secretsEncryptionRequired": false  // Allow unencrypted secrets (not recommended)
            }
        }
    }
}
```

## AWS Config Requirements

These checks rely on AWS Config to track EKS resource changes. You must:

1. **Enable AWS Config** in each region where you have EKS clusters
2. **Configure AWS Config to record EKS resources:**

```bash
aws configservice put-configuration-recorder \
    --configuration-recorder name=default,roleARN=arn:aws:iam::account:role/config-role \
    --recording-group allSupported=false,includeGlobalResources=false,resourceTypes=AWS::EKS::Cluster,AWS::EKS::Nodegroup,AWS::EC2::SecurityGroup,AWS::IAM::Role
```

3. **Start the configuration recorder:**

```bash
aws configservice start-configuration-recorder --configuration-recorder-name default
```

4. **Create an SNS topic** for AWS Config notifications
5. **Configure Lambda function** to subscribe to AWS Config SNS topic

## Event Processing Modes

Both checks support two AWS Config event modes:

### Configuration Item Mode
- Triggered when AWS Config detects a resource change
- Real-time evaluation as resources are modified
- Recommended for production environments

### Snapshot Event Mode
- Triggered by periodic AWS Config snapshots
- Batch evaluation of all resources
- Useful for compliance reporting

## Testing

### Prerequisites

1. AWS Config enabled and recording EKS resources
2. Lambda function deployed with EKS checks enabled
3. Test EKS cluster and node group created

### Test Scenarios

#### Test 1: Cluster Logging Violation

1. Create EKS cluster without full logging:
```bash
aws eks create-cluster \
    --name test-cluster \
    --role-arn <role-arn> \
    --resources-vpc-config subnetIds=<subnets> \
    --logging '{"clusterLogging":[{"types":["api"],"enabled":true}]}'
```

2. Wait for AWS Config to detect the cluster
3. Verify vulnerability is reported for missing log types

#### Test 2: Public Endpoint Violation

1. Create or update cluster with unrestricted public access:
```bash
aws eks update-cluster-config \
    --name test-cluster \
    --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=["0.0.0.0/0"]
```

2. Verify vulnerability is reported

#### Test 3: Node Group Tag Violation

1. Create node group without required tags:
```bash
aws eks create-nodegroup \
    --cluster-name test-cluster \
    --nodegroup-name test-nodegroup \
    --subnets <subnets> \
    --node-role <role-arn>
```

2. Verify vulnerability is reported for missing tags

### Verification

Check CloudWatch Logs for the Lambda function:
```
eksInfrastructure: Creating EKS cluster vulnerability for 'cluster-id'
eksNodeGroup: Creating EKS node group vulnerability for 'nodegroup-id'
```

Verify vulnerabilities appear in Alert Logic Cloud Insight console.

## Phase 1 Limitations

This initial implementation has the following limitations:

1. **No Fargate Profile checks** - Will be added in Phase 2
2. **Basic version comparison** - Only compares major.minor versions
3. **Limited policy customization** - Some checks use fixed logic
4. **No pod security checks** - Only infrastructure-level checks
5. **No add-on validation** - EKS add-ons not evaluated

## Future Phases

### Phase 2 (Planned)
- EKS Fargate profile checks
- EKS add-on version validation
- Enhanced IAM role policy validation
- Network policy checks

### Phase 3 (Proposed)
- Pod Security Standards enforcement
- Runtime security integration
- Container image scanning integration
- Service mesh configuration checks

## Troubleshooting

### Check Not Running

**Problem:** Checks don't execute for EKS resources

**Solutions:**
1. Verify checks are enabled in `config.js`
2. Confirm AWS Config is recording EKS resource types
3. Check Lambda function has correct IAM permissions
4. Review CloudWatch Logs for errors

### False Positives

**Problem:** Vulnerabilities reported for compliant resources

**Solutions:**
1. Review policy configuration in `config.js`
2. Check AWS Config data freshness
3. Verify resource configuration matches expectations
4. Review check logic in `checks/eksInfrastructure.js` or `checks/eksNodeGroup.js`

### Missing Vulnerabilities

**Problem:** Expected vulnerabilities not reported

**Solutions:**
1. Confirm AWS Config detected the configuration change
2. Check Lambda function was triggered by SNS event
3. Review check scoping logic
4. Verify resource is in scope for monitoring

## References

### AWS Documentation
- [EKS Best Practices Guide](https://aws.github.io/aws-eks-best-practices/)
- [EKS Security Best Practices](https://docs.aws.amazon.com/eks/latest/userguide/security-best-practices.html)
- [EKS User Guide](https://docs.aws.amazon.com/eks/latest/userguide/)
- [AWS Config for EKS](https://docs.aws.amazon.com/config/latest/developerguide/eks-resources.html)

### Related Documentation
- [Main README](./README.md) - Overall project documentation
- [AWS Config Integration](./aws_config.json) - Configuration examples

## Support

For issues or questions:
1. Check CloudWatch Logs for detailed error messages
2. Review this documentation for configuration guidance
3. Open an issue in the GitHub repository
4. Refer to AWS EKS documentation for resource-specific questions
