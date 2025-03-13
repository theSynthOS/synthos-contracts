// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin-contracts-5.2.0/access/AccessControl.sol";
import "@openzeppelin-contracts-5.2.0/utils/structs/EnumerableSet.sol";

/**
 * @title PolicyRegistry
 * @author SynthOS - Verifiable DeFAI Agent Marketplace
 * @notice Master registry for managing AVS policies and their enforcement
 * @dev Handles registration and management of policies that define constraints
 *      for agent actions. Each policy combines time conditions (when), function
 *      constraints (how), and resource limitations (what contracts can be accessed).
 *
 */
contract PolicyRegistry is AccessControl {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;

    bytes32 public constant POLICY_CREATOR_ROLE =
        keccak256("POLICY_CREATOR_ROLE");

    // Structs to define policy components
    struct TimeCondition {
        uint256 startTime; // 0 means no start time restriction
        uint256 endTime; // 0 means no end time restriction
    }

    struct ActionCondition {
        bytes4[] allowedFunctions; // Function selectors that can be executed
    }

    struct ResourceCondition {
        address[] allowedContracts; // Contracts this policy can interact with
    }

    struct Policy {
        string name;
        string description;
        TimeCondition whenCondition;
        ActionCondition howCondition;
        ResourceCondition whatCondition;
        bool isActive;
        address creator;
    }

    // Policy ID => Policy details
    mapping(uint256 => Policy) public policies;

    // Counter for generating unique policy IDs
    uint256 private _nextPolicyId;

    // Set of all registered policy IDs
    EnumerableSet.UintSet private _registeredPolicyIds;

    // Events
    event PolicyRegistered(
        uint256 indexed policyId,
        string name,
        string description,
        address indexed creator
    );
    event PolicyDeactivated(uint256 indexed policyId);
    event PolicyReactivated(uint256 indexed policyId);
    event PolicyMetadataUpdated(
        uint256 indexed policyId,
        string name,
        string description
    );
    event PolicyTimeConditionUpdated(
        uint256 indexed policyId,
        uint256 startTime,
        uint256 endTime
    );
    event PolicyActionConditionUpdated(
        uint256 indexed policyId,
        bytes4[] allowedFunctions
    );
    event PolicyResourceConditionUpdated(
        uint256 indexed policyId,
        address[] allowedContracts
    );

    // Errors
    error PolicyAlreadyRegistered();
    error PolicyNotRegistered(uint256 policyId);
    error PolicyNotActive(uint256 policyId);
    error EmptyPolicyName();
    error EmptyPolicyDescription();
    error NoActionsDefined();
    error NoResourcesDefined();
    error NotPolicyCreator();
    error InvalidTimeRange();
    error AgentNotAuthorized();
    error EmptyPolicies();

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(POLICY_CREATOR_ROLE, msg.sender);
        _nextPolicyId = 1;
    }

    /**
     * @notice Register a new policy with conditions
     * @param name Name of the policy
     * @param description Description of what the policy enforces
     * @param startTime Start time for policy validity (0 for no restriction)
     * @param endTime End time for policy validity (0 for no restriction)
     * @param allowedFunctions Array of function selectors that can be executed
     * @param allowedContracts Array of contract addresses that can be interacted with
     * @return policyId The ID of the newly created policy
     */
    function registerPolicy(
        string calldata name,
        string calldata description,
        uint256 startTime,
        uint256 endTime,
        bytes4[] calldata allowedFunctions,
        address[] calldata allowedContracts
    ) external onlyRole(POLICY_CREATOR_ROLE) returns (uint256) {
        if (bytes(name).length == 0) revert EmptyPolicyName();
        if (bytes(description).length == 0) revert EmptyPolicyDescription();
        if (allowedFunctions.length == 0) revert NoActionsDefined();
        if (allowedContracts.length == 0) revert NoResourcesDefined();
        if (endTime != 0 && startTime >= endTime) revert InvalidTimeRange();

        uint256 policyId = _nextPolicyId++;

        policies[policyId] = Policy({
            name: name,
            description: description,
            whenCondition: TimeCondition({
                startTime: startTime,
                endTime: endTime
            }),
            howCondition: ActionCondition({allowedFunctions: allowedFunctions}),
            whatCondition: ResourceCondition({
                allowedContracts: allowedContracts
            }),
            isActive: true,
            creator: msg.sender
        });

        _registeredPolicyIds.add(policyId);

        emit PolicyRegistered(policyId, name, description, msg.sender);
        return policyId;
    }

    /**
     * @notice Update a policy's basic metadata
     * @param policyId ID of the policy to update
     * @param name New name for the policy
     * @param description New description for the policy
     */
    function updatePolicyMetadata(
        uint256 policyId,
        string calldata name,
        string calldata description
    ) external {
        if (!_registeredPolicyIds.contains(policyId))
            revert PolicyNotRegistered(policyId);

        Policy storage policy = policies[policyId];
        if (
            msg.sender != policy.creator &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert NotPolicyCreator();
        }

        if (bytes(name).length == 0) revert EmptyPolicyName();
        if (bytes(description).length == 0) revert EmptyPolicyDescription();

        policy.name = name;
        policy.description = description;

        emit PolicyMetadataUpdated(policyId, name, description);
    }

    /**
     * @notice Update a policy's time conditions
     * @param policyId ID of the policy to update
     * @param startTime New start time (0 for no restriction)
     * @param endTime New end time (0 for no restriction)
     */
    function updatePolicyTimeCondition(
        uint256 policyId,
        uint256 startTime,
        uint256 endTime
    ) external {
        if (!_registeredPolicyIds.contains(policyId))
            revert PolicyNotRegistered(policyId);

        Policy storage policy = policies[policyId];
        if (
            msg.sender != policy.creator &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert NotPolicyCreator();
        }

        if (endTime != 0 && startTime >= endTime) revert InvalidTimeRange();

        policy.whenCondition.startTime = startTime;
        policy.whenCondition.endTime = endTime;

        emit PolicyTimeConditionUpdated(policyId, startTime, endTime);
    }

    /**
     * @notice Update a policy's allowed functions
     * @param policyId ID of the policy to update
     * @param allowedFunctions New array of allowed function selectors
     */
    function updatePolicyActionCondition(
        uint256 policyId,
        bytes4[] calldata allowedFunctions
    ) external {
        if (!_registeredPolicyIds.contains(policyId))
            revert PolicyNotRegistered(policyId);

        Policy storage policy = policies[policyId];
        if (
            msg.sender != policy.creator &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert NotPolicyCreator();
        }

        if (allowedFunctions.length == 0) revert NoActionsDefined();

        // Replace the existing function selectors
        delete policy.howCondition.allowedFunctions;
        for (uint256 i = 0; i < allowedFunctions.length; i++) {
            policy.howCondition.allowedFunctions.push(allowedFunctions[i]);
        }

        emit PolicyActionConditionUpdated(policyId, allowedFunctions);
    }

    /**
     * @notice Update a policy's allowed contracts
     * @param policyId ID of the policy to update
     * @param allowedContracts New array of allowed contract addresses
     */
    function updatePolicyResourceCondition(
        uint256 policyId,
        address[] calldata allowedContracts
    ) external {
        if (!_registeredPolicyIds.contains(policyId))
            revert PolicyNotRegistered(policyId);

        Policy storage policy = policies[policyId];
        if (
            msg.sender != policy.creator &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert NotPolicyCreator();
        }

        if (allowedContracts.length == 0) revert NoResourcesDefined();

        // Replace the existing contract addresses
        delete policy.whatCondition.allowedContracts;
        for (uint256 i = 0; i < allowedContracts.length; i++) {
            policy.whatCondition.allowedContracts.push(allowedContracts[i]);
        }

        emit PolicyResourceConditionUpdated(policyId, allowedContracts);
    }

    /**
     * @notice Verify that all policies in an array exist and are active
     * @param policyIds Array of policy IDs to verify
     */
    function verifyPolicies(uint256[] calldata policyIds) external view {
        if (policyIds.length == 0) revert EmptyPolicies();

        for (uint256 i = 0; i < policyIds.length; i++) {
            uint256 policyId = policyIds[i];

            // Check if policy exists with this ID
            if (!isPolicyRegistered(policyId))
                revert PolicyNotRegistered(policyId);

            // Check if policy is active
            if (!isPolicyActive(policyId)) revert PolicyNotActive(policyId);
        }
    }

    /**
     * @notice Check if a policy is registered
     * @param policyId ID of the policy to check
     * @return True if policy is registered
     */
    function isPolicyRegistered(uint256 policyId) public view returns (bool) {
        return _registeredPolicyIds.contains(policyId);
    }

    /**
     * @notice Check if a policy is active
     * @param policyId ID of the policy to check
     * @return True if policy is active
     */
    function isPolicyActive(uint256 policyId) public view returns (bool) {
        Policy storage policy = policies[policyId];
        return policy.isActive;
    }

    /**
     * @notice Deactivate a policy
     * @param policyId ID of the policy to deactivate
     */
    function deactivatePolicy(uint256 policyId) external {
        Policy storage policy = policies[policyId];
        if (!_registeredPolicyIds.contains(policyId))
            revert PolicyNotRegistered(policyId);
        if (
            msg.sender != policy.creator &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert NotPolicyCreator();
        }

        policy.isActive = false;
        emit PolicyDeactivated(policyId);
    }

    /**
     * @notice Reactivate a policy
     * @param policyId ID of the policy to reactivate
     */
    function reactivatePolicy(uint256 policyId) external {
        Policy storage policy = policies[policyId];
        if (!_registeredPolicyIds.contains(policyId))
            revert PolicyNotRegistered(policyId);
        if (
            msg.sender != policy.creator &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert NotPolicyCreator();
        }

        policy.isActive = true;
        emit PolicyReactivated(policyId);
    }

    /**
     * @notice Get all registered policy IDs
     * @return Array of policy IDs
     */
    function getAllPolicyIds() external view returns (uint256[] memory) {
        return _registeredPolicyIds.values();
    }

    /**
     * @notice Get policy metadata for a specific policy
     * @param policyId ID of the policy
     */
    function getPolicyMetadata(
        uint256 policyId
    )
        external
        view
        returns (
            string memory name,
            string memory description,
            TimeCondition memory whenCondition,
            ActionCondition memory howCondition,
            ResourceCondition memory whatCondition,
            bool isActive,
            address creator
        )
    {
        if (!_registeredPolicyIds.contains(policyId))
            revert PolicyNotRegistered(policyId);

        Policy storage policy = policies[policyId];
        return (
            policy.name,
            policy.description,
            policy.whenCondition,
            policy.howCondition,
            policy.whatCondition,
            policy.isActive,
            policy.creator
        );
    }
}
