var eksInfrastructure = function(input, callback) {
    "use strict";
    var result = {vulnerable: false, evidence: []};
    
    // Only process AWS::EKS::Cluster resources
    if (input.message.configurationItem.resourceType !== "AWS::EKS::Cluster") {
        return callback(null, result);
    }
    
    if (input.message.configurationItem.configurationItemStatus === "OK" ||
        input.message.configurationItem.configurationItemStatus === "ResourceDiscovered") {
        
        var configuration = input.message.configurationItem.configuration,
            policies = input.config.checks.eksInfrastructure.configuration.policies,
            violations = [];

        // Check cluster logging
        if (policies.clusterLogging) {
            var loggingViolation = checkClusterLogging(configuration, policies.clusterLogging);
            if (loggingViolation) {
                violations.push(loggingViolation);
            }
        }

        // Check Kubernetes version
        if (policies.clusterVersion) {
            var versionViolation = checkClusterVersion(configuration, policies.clusterVersion);
            if (versionViolation) {
                violations.push(versionViolation);
            }
        }

        // Check endpoint access
        if (policies.endpointAccess) {
            var endpointViolation = checkEndpointAccess(configuration, policies.endpointAccess);
            if (endpointViolation) {
                violations.push(endpointViolation);
            }
        }

        // Check encryption
        if (policies.encryption) {
            var encryptionViolation = checkEncryption(configuration, policies.encryption);
            if (encryptionViolation) {
                violations.push(encryptionViolation);
            }
        }

        if (violations.length > 0) {
            result.vulnerable = true;
            result.evidence = violations;
            console.log("eksInfrastructure: Creating EKS cluster vulnerability for '" + 
                       input.message.configurationItem.resourceId + "': " + JSON.stringify(result));
            return callback(null, result);
        }
    }
    
    console.log("eksInfrastructure: Clearing EKS cluster vulnerability");
    return callback(null, result);
};

function checkClusterLogging(configuration, policy) {
    "use strict";
    if (!policy.requiredLogTypes || !policy.requiredLogTypes.length) {
        return null;
    }

    var logging = configuration.logging || {};
    var clusterLogging = logging.clusterLogging || [];
    
    // Find enabled log types
    var enabledLogTypes = [];
    for (var i = 0; i < clusterLogging.length; i++) {
        if (clusterLogging[i].enabled === true && clusterLogging[i].types) {
            enabledLogTypes = enabledLogTypes.concat(clusterLogging[i].types);
        }
    }

    // Check for missing required log types
    var missingLogTypes = [];
    for (var j = 0; j < policy.requiredLogTypes.length; j++) {
        if (enabledLogTypes.indexOf(policy.requiredLogTypes[j]) === -1) {
            missingLogTypes.push(policy.requiredLogTypes[j]);
        }
    }

    if (missingLogTypes.length > 0) {
        return {
            check: "clusterLogging",
            reason: "Missing required log types: " + missingLogTypes.join(", "),
            required: policy.requiredLogTypes,
            enabled: enabledLogTypes,
            missing: missingLogTypes
        };
    }

    return null;
}

function checkClusterVersion(configuration, policy) {
    "use strict";
    if (!policy.minimumVersion) {
        return null;
    }

    var currentVersion = configuration.version || "";
    if (!currentVersion) {
        return {
            check: "clusterVersion",
            reason: "Cluster version is not set",
            required: policy.minimumVersion,
            current: "unknown"
        };
    }

    // Simple version comparison (e.g., "1.27" vs "1.26")
    if (compareVersions(currentVersion, policy.minimumVersion) < 0) {
        return {
            check: "clusterVersion",
            reason: "Cluster version " + currentVersion + " is below minimum required version " + policy.minimumVersion,
            required: policy.minimumVersion,
            current: currentVersion
        };
    }

    return null;
}

function checkEndpointAccess(configuration, policy) {
    "use strict";
    if (!policy.publicAccessRestricted) {
        return null;
    }

    var resourcesVpcConfig = configuration.resourcesVpcConfig || {};
    var endpointPublicAccess = resourcesVpcConfig.endpointPublicAccess;
    var publicAccessCidrs = resourcesVpcConfig.publicAccessCidrs || [];

    // If public access is enabled and not restricted
    if (endpointPublicAccess === true) {
        // Check if it's unrestricted (0.0.0.0/0)
        if (publicAccessCidrs.length === 0 || 
            publicAccessCidrs.indexOf("0.0.0.0/0") !== -1) {
            return {
                check: "endpointAccess",
                reason: "EKS cluster endpoint has unrestricted public access",
                publicAccessEnabled: endpointPublicAccess,
                publicAccessCidrs: publicAccessCidrs
            };
        }
    }

    return null;
}

function checkEncryption(configuration, policy) {
    "use strict";
    if (!policy.secretsEncryptionRequired) {
        return null;
    }

    var encryptionConfig = configuration.encryptionConfig || [];
    
    if (encryptionConfig.length === 0) {
        return {
            check: "encryption",
            reason: "Secrets encryption is not enabled",
            required: true,
            enabled: false
        };
    }

    // Check if secrets are in the encrypted resources
    var secretsEncrypted = false;
    for (var i = 0; i < encryptionConfig.length; i++) {
        var resources = encryptionConfig[i].resources || [];
        if (resources.indexOf("secrets") !== -1) {
            secretsEncrypted = true;
            break;
        }
    }

    if (!secretsEncrypted) {
        return {
            check: "encryption",
            reason: "Secrets encryption is not configured",
            required: true,
            enabled: false
        };
    }

    return null;
}

function compareVersions(version1, version2) {
    "use strict";
    // Simple version comparison for semantic versions
    var v1parts = version1.split('.');
    var v2parts = version2.split('.');
    
    for (var i = 0; i < Math.max(v1parts.length, v2parts.length); i++) {
        var v1part = parseInt(v1parts[i] || 0, 10);
        var v2part = parseInt(v2parts[i] || 0, 10);
        
        if (v1part > v2part) {
            return 1;
        }
        if (v1part < v2part) {
            return -1;
        }
    }
    return 0;
}

module.exports = eksInfrastructure;
