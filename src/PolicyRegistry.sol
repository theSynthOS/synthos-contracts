// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title PolicyRegistry
 * @notice Master registry for managing AVS policies and their enforcement
 */
contract PolicyRegistry is AccessControl {
    using EnumerableSet for EnumerableSet.AddressSet;

    bytes32 public constant POLICY_CREATOR_ROLE =
        keccak256("POLICY_CREATOR_ROLE");

    struct Policy {
        string name;
        string description;
        address implementation;
        bool isActive;
        address creator;
    }

    // Policy implementation address => Policy details
    mapping(address => Policy) public policies;

    // Set of all registered policy implementations
    EnumerableSet.AddressSet private _registeredPolicies;

    // Events
    event PolicyRegistered(
        address indexed implementation,
        string name,
        string description,
        address indexed creator
    );
    event PolicyDeactivated(address indexed implementation);
    event PolicyReactivated(address indexed implementation);

    // Errors
    error PolicyAlreadyRegistered();
    error PolicyNotRegistered();
    error PolicyNotActive();
    error EmptyPolicyName();
    error EmptyPolicyDescription();
    error InvalidPolicyImplementation();
    error NotPolicyCreator();
    error InvalidIndex();

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(POLICY_CREATOR_ROLE, msg.sender);
    }

    /**
     * @notice Register a new policy
     * @param name Name of the policy
     * @param description Description of what the policy enforces
     * @param implementation Address of the policy implementation contract
     */
    function registerPolicy(
        string calldata name,
        string calldata description,
        address implementation
    ) external onlyRole(POLICY_CREATOR_ROLE) {
        if (bytes(name).length == 0) revert EmptyPolicyName();
        if (bytes(description).length == 0) revert EmptyPolicyDescription();
        if (implementation == address(0)) revert InvalidPolicyImplementation();
        if (_registeredPolicies.contains(implementation))
            revert PolicyAlreadyRegistered();

        policies[implementation] = Policy({
            name: name,
            description: description,
            implementation: implementation,
            isActive: true,
            creator: msg.sender
        });

        _registeredPolicies.add(implementation);

        emit PolicyRegistered(implementation, name, description, msg.sender);
    }

    /**
     * @notice Deactivate a policy
     * @param implementation Address of the policy to deactivate
     */
    function deactivatePolicy(address implementation) external {
        Policy storage policy = policies[implementation];
        if (!_registeredPolicies.contains(implementation))
            revert PolicyNotRegistered();
        if (
            msg.sender != policy.creator &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert NotPolicyCreator();
        }

        policy.isActive = false;
        emit PolicyDeactivated(implementation);
    }

    /**
     * @notice Reactivate a policy
     * @param implementation Address of the policy to reactivate
     */
    function reactivatePolicy(address implementation) external {
        Policy storage policy = policies[implementation];
        if (!_registeredPolicies.contains(implementation))
            revert PolicyNotRegistered();
        if (
            msg.sender != policy.creator &&
            !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)
        ) {
            revert NotPolicyCreator();
        }

        policy.isActive = true;
        emit PolicyReactivated(implementation);
    }

    /**
     * @notice Verify that all policies for an agent are active
     * @param policyAddresses Array of policy addresses to verify
     * @return bool True if all policies are active
     */
    function verifyPolicies(
        address[] calldata policyAddresses
    ) external view returns (bool) {
        for (uint256 i = 0; i < policyAddresses.length; i++) {
            address policyAddr = policyAddresses[i];
            if (!_registeredPolicies.contains(policyAddr))
                revert PolicyNotRegistered();
            if (!policies[policyAddr].isActive) revert PolicyNotActive();
        }
        return true;
    }

    /**
     * @notice Get all registered policy addresses
     * @return Array of policy implementation addresses
     */
    function getAllPolicies() external view returns (address[] memory) {
        return _registeredPolicies.values();
    }

    /**
     * @notice Get active policy count
     * @return Number of active policies
     */
    function getActivePolicyCount() external view returns (uint256) {
        uint256 count = 0;
        uint256 length = _registeredPolicies.length();
        for (uint256 i = 0; i < length; i++) {
            if (policies[_registeredPolicies.at(i)].isActive) {
                count++;
            }
        }
        return count;
    }

    /**
     * @notice Get all policies with their metadata
     * @return policyAddresses Array of policy addresses
     * @return names Array of policy names
     * @return descriptions Array of policy descriptions
     * @return isActives Array of policy active status
     * @return creators Array of policy creators
     */
    function getAllPoliciesWithMetadata()
        external
        view
        returns (
            address[] memory policyAddresses,
            string[] memory names,
            string[] memory descriptions,
            bool[] memory isActives,
            address[] memory creators
        )
    {
        uint256 length = _registeredPolicies.length();

        policyAddresses = new address[](length);
        names = new string[](length);
        descriptions = new string[](length);
        isActives = new bool[](length);
        creators = new address[](length);

        for (uint256 i = 0; i < length; i++) {
            address policyAddr = _registeredPolicies.at(i);
            Policy memory policy = policies[policyAddr];

            policyAddresses[i] = policy.implementation;
            names[i] = policy.name;
            descriptions[i] = policy.description;
            isActives[i] = policy.isActive;
            creators[i] = policy.creator;
        }

        return (policyAddresses, names, descriptions, isActives, creators);
    }

    /**
     * @notice Get policy metadata for a specific policy
     * @param implementation Address of the policy implementation
     * @return name Name of the policy
     * @return description Description of the policy
     * @return isActive Whether the policy is active
     * @return creator Address of the policy creator
     */
    function getPolicyMetadata(
        address implementation
    )
        external
        view
        returns (
            string memory name,
            string memory description,
            bool isActive,
            address creator
        )
    {
        if (!_registeredPolicies.contains(implementation))
            revert PolicyNotRegistered();

        Policy memory policy = policies[implementation];
        return (
            policy.name,
            policy.description,
            policy.isActive,
            policy.creator
        );
    }
}
