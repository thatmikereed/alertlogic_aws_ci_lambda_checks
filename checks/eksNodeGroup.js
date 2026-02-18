var eksNodeGroup = function(input, callback) {
    "use strict";
    var result = {vulnerable: false, evidence: []};
    
    // Only process AWS::EKS::Nodegroup resources
    if (input.message.configurationItem.resourceType !== "AWS::EKS::Nodegroup") {
        return callback(null, result);
    }
    
    if (input.message.configurationItem.configurationItemStatus === "OK" ||
        input.message.configurationItem.configurationItemStatus === "ResourceDiscovered") {
        
        var configuration = input.message.configurationItem.configuration,
            tags = input.message.configurationItem.tags || {},
            policies = input.config.checks.eksNodeGroup.configuration.policies,
            violations = [];

        // Check AMI type
        if (policies.amiType) {
            var amiViolation = checkAmiType(configuration, policies.amiType);
            if (amiViolation) {
                violations.push(amiViolation);
            }
        }

        // Check update configuration
        if (policies.updateConfig) {
            var updateViolation = checkUpdateConfig(configuration, policies.updateConfig);
            if (updateViolation) {
                violations.push(updateViolation);
            }
        }

        // Check required tags
        if (policies.requiredTags) {
            var tagViolation = checkRequiredTags(tags, policies.requiredTags);
            if (tagViolation) {
                violations.push(tagViolation);
            }
        }

        // Check scaling configuration
        var scalingViolation = checkScalingConfig(configuration);
        if (scalingViolation) {
            violations.push(scalingViolation);
        }

        if (violations.length > 0) {
            result.vulnerable = true;
            result.evidence = violations;
            console.log("eksNodeGroup: Creating EKS node group vulnerability for '" + 
                       input.message.configurationItem.resourceId + "': " + JSON.stringify(result));
            return callback(null, result);
        }
    }
    
    console.log("eksNodeGroup: Clearing EKS node group vulnerability");
    return callback(null, result);
};

function checkAmiType(configuration, policy) {
    "use strict";
    if (!policy.allowedTypes || !policy.allowedTypes.length) {
        return null;
    }

    var amiType = configuration.amiType || "";
    
    if (!amiType) {
        return {
            check: "amiType",
            reason: "AMI type is not set",
            allowed: policy.allowedTypes,
            current: "unknown"
        };
    }

    if (policy.allowedTypes.indexOf(amiType) === -1) {
        return {
            check: "amiType",
            reason: "AMI type '" + amiType + "' is not in the allowed list",
            allowed: policy.allowedTypes,
            current: amiType
        };
    }

    return null;
}

function checkUpdateConfig(configuration, policy) {
    "use strict";
    var updateConfig = configuration.updateConfig || {};
    
    if (!updateConfig) {
        return {
            check: "updateConfig",
            reason: "Update configuration is not set",
            required: policy
        };
    }

    // Check maxUnavailable if specified in policy
    if (policy.hasOwnProperty("maxUnavailable")) {
        var maxUnavailable = updateConfig.maxUnavailable;
        
        if (maxUnavailable === undefined || maxUnavailable === null) {
            return {
                check: "updateConfig",
                reason: "maxUnavailable is not configured",
                required: policy.maxUnavailable,
                current: "not set"
            };
        }

        // Check if maxUnavailable exceeds policy
        if (maxUnavailable > policy.maxUnavailable) {
            return {
                check: "updateConfig",
                reason: "maxUnavailable (" + maxUnavailable + ") exceeds policy limit (" + policy.maxUnavailable + ")",
                required: policy.maxUnavailable,
                current: maxUnavailable
            };
        }
    }

    return null;
}

function checkRequiredTags(tags, requiredTags) {
    "use strict";
    if (!requiredTags || !requiredTags.length) {
        return null;
    }

    var missingTags = [];
    for (var i = 0; i < requiredTags.length; i++) {
        if (!tags.hasOwnProperty(requiredTags[i])) {
            missingTags.push(requiredTags[i]);
        }
    }

    if (missingTags.length > 0) {
        return {
            check: "requiredTags",
            reason: "Missing required tags: " + missingTags.join(", "),
            required: requiredTags,
            missing: missingTags
        };
    }

    return null;
}

function checkScalingConfig(configuration) {
    "use strict";
    var scalingConfig = configuration.scalingConfig || {};
    
    var desiredSize = scalingConfig.desiredSize;
    var minSize = scalingConfig.minSize;
    var maxSize = scalingConfig.maxSize;

    // Basic validation of scaling configuration
    if (minSize !== undefined && maxSize !== undefined && minSize > maxSize) {
        return {
            check: "scalingConfig",
            reason: "Minimum size (" + minSize + ") is greater than maximum size (" + maxSize + ")",
            minSize: minSize,
            maxSize: maxSize
        };
    }

    if (desiredSize !== undefined && minSize !== undefined && desiredSize < minSize) {
        return {
            check: "scalingConfig",
            reason: "Desired size (" + desiredSize + ") is less than minimum size (" + minSize + ")",
            desiredSize: desiredSize,
            minSize: minSize
        };
    }

    if (desiredSize !== undefined && maxSize !== undefined && desiredSize > maxSize) {
        return {
            check: "scalingConfig",
            reason: "Desired size (" + desiredSize + ") is greater than maximum size (" + maxSize + ")",
            desiredSize: desiredSize,
            maxSize: maxSize
        };
    }

    return null;
}

module.exports = eksNodeGroup;
