// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./AgentRegistry.sol";
import "./PolicyRegistry.sol";
import {IMessageRecipient} from "hyperlane-core-v5.0.0/contracts/interfaces/IMessageRecipient.sol";
import {TypeCasts} from "hyperlane-core-v5.0.0/contracts/libs/TypeCasts.sol";

/**
 * @title PolicyCoordinator
 * @author SynthOS - Verifiable DeFAI Agent Marketplace
 * @notice Coordinates validation of transactions against agent policies
 * @dev Acts as the central coordinator for validating agent actions against
 *      their registered policies. Ensures all actions comply with time,
 *      function, and resource constraints.
 *
 */
contract PolicyCoordinator is IMessageRecipient {
    using TypeCasts for bytes32;

    AgentRegistry public agentRegistry;
    PolicyRegistry public policyRegistry;

    // Errors
    error AgentNotRegistered(string dockerfileHash);
    error InvalidAgentId(uint256 agentId);
    error NoPoliciesForAgent(string dockerfileHash);
    error NoValidPolicies(uint256 agentId);

    // Events
    event TransactionValidated(
        bytes32 indexed safeTxHash,
        uint256 indexed agentId,
        bool isValid,
        string reason
    );
    event PolicyValidated(
        uint256 indexed policyId,
        bytes32 indexed safeTxHash,
        bool isValid
    );
    event TaskDataReceived(
        string proofOfTask,
        string taskData,
        uint256 taskDefinitionId
    );

    // Add Hyperlane mailbox
    address public immutable mailbox;

    // Add allowed origin domain (Base)
    uint32 public immutable originDomain;

    constructor(
        address _agentRegistry,
        address _policyRegistry,
        address _mailbox,
        uint32 _originDomain
    ) {
        agentRegistry = AgentRegistry(_agentRegistry);
        policyRegistry = PolicyRegistry(_policyRegistry);
        mailbox = _mailbox;
        originDomain = _originDomain;
    }

    /**
     * @notice Validate a transaction against an agent's policies
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param targetAddress Address of the contract being called
     * @param functionSignature Function selector being called
     * @param executionTime Timestamp when the transaction is to be executed
     * @return isValid True if at least one policy validates the transaction
     * @return reason Explanation of validation result
     */
    function validateTransaction(
        string memory dockerfileHash,
        address targetAddress,
        bytes4 functionSignature,
        uint256 executionTime
    ) public view returns (bool isValid, string memory reason) {
        // Get agent details
        (
            ,
            ,
            uint256[] memory policyIds,
            bool isRegistered,
            ,
            ,
            ,

        ) = agentRegistry.getAgent(dockerfileHash);

        if (!isRegistered) {
            return (false, "Agent not registered");
        }

        if (policyIds.length == 0) {
            return (false, "No policies associated with agent");
        }

        // Track if any policy validates this transaction
        bool anyPolicyValid = false;
        string
            memory validationReason = "No policy matched transaction parameters";

        // Check each policy
        for (uint256 i = 0; i < policyIds.length; i++) {
            uint256 policyId = policyIds[i];

            // Verify policy is active
            if (!policyRegistry.isPolicyActive(policyId)) {
                continue; // Skip inactive policies
            }

            // Get policy metadata
            (
                string memory name,
                ,
                PolicyRegistry.TimeCondition memory whenCondition,
                PolicyRegistry.ActionCondition memory howCondition,
                PolicyRegistry.ResourceCondition memory whatCondition,
                bool isActive,

            ) = policyRegistry.getPolicyMetadata(policyId);

            if (!isActive) {
                continue; // Double-check policy is active
            }

            // Check time conditions
            if (
                whenCondition.startTime != 0 &&
                executionTime < whenCondition.startTime
            ) {
                continue; // Time is before start time
            }
            if (
                whenCondition.endTime != 0 &&
                executionTime > whenCondition.endTime
            ) {
                continue; // Time is after end time
            }

            // If both conditions are specified, ensure executionTime is within the range
            if (whenCondition.startTime != 0 && whenCondition.endTime != 0) {
                if (
                    executionTime < whenCondition.startTime ||
                    executionTime > whenCondition.endTime
                ) {
                    continue; // Transaction time is outside of policy's valid time window
                }
            }

            // Check function signature (action condition)
            bool functionAllowed = false;
            for (uint256 j = 0; j < howCondition.allowedFunctions.length; j++) {
                if (howCondition.allowedFunctions[j] == functionSignature) {
                    functionAllowed = true;
                    break;
                }
            }
            if (!functionAllowed) {
                continue; // Function not allowed
            }

            // Check target contract (resource condition)
            bool targetAllowed = false;
            for (
                uint256 j = 0;
                j < whatCondition.allowedContracts.length;
                j++
            ) {
                if (whatCondition.allowedContracts[j] == targetAddress) {
                    targetAllowed = true;
                    break;
                }
            }
            if (!targetAllowed) {
                continue; // Target contract not allowed
            }

            // If we get here, all conditions are satisfied for this policy
            anyPolicyValid = true;
            validationReason = string(
                abi.encodePacked("Policy '", name, "' authorized transaction")
            );
            break;
        }

        return (anyPolicyValid, validationReason);
    }

    /**
     * @notice Get all policies associated with an agent
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @return policyIds Array of policy IDs
     * @return policyDetails Array of policy metadata
     */
    function getPoliciesForAgent(
        string calldata dockerfileHash
    )
        external
        view
        returns (
            uint256[] memory policyIds,
            PolicyDetails[] memory policyDetails
        )
    {
        // Get agent details
        (
            ,
            ,
            uint256[] memory agentPolicyIds,
            bool isRegistered,
            ,
            ,
            ,

        ) = agentRegistry.getAgent(dockerfileHash);

        if (!isRegistered) {
            revert AgentNotRegistered(dockerfileHash);
        }

        if (agentPolicyIds.length == 0) {
            revert NoPoliciesForAgent(dockerfileHash);
        }

        // Initialize return arrays
        policyIds = agentPolicyIds;
        policyDetails = new PolicyDetails[](agentPolicyIds.length);

        // Populate policy details
        for (uint256 i = 0; i < agentPolicyIds.length; i++) {
            uint256 policyId = agentPolicyIds[i];

            // Get policy metadata
            (
                string memory name,
                string memory description,
                PolicyRegistry.TimeCondition memory whenCondition,
                PolicyRegistry.ActionCondition memory howCondition,
                PolicyRegistry.ResourceCondition memory whatCondition,
                bool isActive,
                address creator
            ) = policyRegistry.getPolicyMetadata(policyId);

            policyDetails[i] = PolicyDetails({
                name: name,
                description: description,
                startTime: whenCondition.startTime,
                endTime: whenCondition.endTime,
                allowedFunctions: howCondition.allowedFunctions,
                allowedContracts: whatCondition.allowedContracts,
                isActive: isActive,
                creator: creator
            });
        }

        return (policyIds, policyDetails);
    }

    // Struct to return policy data in a simplified format
    struct PolicyDetails {
        string name;
        string description;
        uint256 startTime;
        uint256 endTime;
        bytes4[] allowedFunctions;
        address[] allowedContracts;
        bool isActive;
        address creator;
    }

    /**
     * @notice Check if a specific policy validates a transaction
     * @param policyId ID of the policy to check
     * @param targetAddress Address of the contract being called
     * @param functionSignature Function selector being called
     * @param executionTime Timestamp when the transaction is to be executed
     * @return isValid True if the policy validates the transaction
     * @return reason Explanation of validation result
     */
    function validateWithPolicy(
        uint256 policyId,
        address targetAddress,
        bytes4 functionSignature,
        uint256 executionTime
    ) external view returns (bool isValid, string memory reason) {
        if (!policyRegistry.isPolicyRegistered(policyId)) {
            return (false, "Policy not registered");
        }

        if (!policyRegistry.isPolicyActive(policyId)) {
            return (false, "Policy not active");
        }

        // Get policy metadata
        (
            string memory name,
            ,
            PolicyRegistry.TimeCondition memory whenCondition,
            PolicyRegistry.ActionCondition memory howCondition,
            PolicyRegistry.ResourceCondition memory whatCondition,
            bool isActive,

        ) = policyRegistry.getPolicyMetadata(policyId);

        if (!isActive) {
            return (false, "Policy not active");
        }

        // Check time conditions
        if (
            whenCondition.startTime != 0 &&
            executionTime < whenCondition.startTime
        ) {
            return (false, "Transaction time before policy start time");
        }
        if (
            whenCondition.endTime != 0 && executionTime > whenCondition.endTime
        ) {
            return (false, "Transaction time after policy end time");
        }

        // Check function signature (action condition)
        bool functionAllowed = false;
        for (uint256 j = 0; j < howCondition.allowedFunctions.length; j++) {
            if (howCondition.allowedFunctions[j] == functionSignature) {
                functionAllowed = true;
                break;
            }
        }
        if (!functionAllowed) {
            return (false, "Function not allowed by policy");
        }

        // Check target contract (resource condition)
        bool targetAllowed = false;
        for (uint256 j = 0; j < whatCondition.allowedContracts.length; j++) {
            if (whatCondition.allowedContracts[j] == targetAddress) {
                targetAllowed = true;
                break;
            }
        }
        if (!targetAllowed) {
            return (false, "Target contract not allowed by policy");
        }

        // All conditions are satisfied
        return (
            true,
            string(
                abi.encodePacked("Policy '", name, "' authorized transaction")
            )
        );
    }

    /**
     * @notice Handle incoming messages from Hyperlane
     * @param _origin Domain of the sender chain
     * @param _message Encoded message data
     */
    function handle(
        uint32 _origin,
        bytes32 /* _sender */,
        bytes calldata _message
    ) external payable override {
        // Verify sender
        require(msg.sender == mailbox, "Only mailbox can deliver");
        require(_origin == originDomain, "Invalid origin domain");

        // Decode the task data
        (
            string memory proofOfTask,
            bytes memory taskData,
            uint256 taskDefinitionId
        ) = abi.decode(_message, (string, bytes, uint256));

        string memory jsonData = string(taskData);

        emit TaskDataReceived(proofOfTask, jsonData, taskDefinitionId);
    }
}
