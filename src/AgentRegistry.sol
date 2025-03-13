// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EnumerableSet} from "@openzeppelin-contracts-5.2.0/utils/structs/EnumerableSet.sol";
import "./PolicyRegistry.sol";

/**
 * @title AgentRegistry
 * @author SynthOS - Verifiable DeFAI Agent Marketplace
 * @notice Manages registration and metadata of DeFAI agents
 * @dev Handles agent registration, updates, and policy associations. Each agent
 *      is identified by their unique Dockerfile hash and must specify at least
 *      one policy that governs their actions.
 *
 * @custom:security-contact security@synthos.io
 * @custom:version 1.0.0
 */
contract AgentRegistry {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    enum AgentCategory {
        General, // General purpose agents
        DeFi, // DeFi-specific agents (lending, trading, etc.)
        Security, // Security monitoring and analysis
        Oracle, // Oracle monitoring and validation
        Analytics // Data analysis and metrics
    }

    struct Agent {
        address owner;
        uint256 executionFee;
        uint256[] policyIds;
        bool isRegistered;
        string dockerfileHash;
        string agentLocation; // URL/IPFS hash where agent is hosted
        string description; // Brief description of the agent
        AgentCategory category; // Category the agent belongs to
    }

    // Dockerfile hash => Agent details
    mapping(string => Agent) public agents;

    // Set of all registered dockerfile hashes (as bytes32)
    EnumerableSet.Bytes32Set private _registeredHashes;

    // Events
    event AgentRegistered(
        string indexed dockerfileHash,
        address owner,
        uint256 executionFee,
        string agentLocation,
        string description,
        AgentCategory category
    );
    event AgentUpdated(string indexed dockerfileHash, uint256 newExecutionFee);
    event PolicyIdsUpdated(string indexed dockerfileHash, uint256[] policyIds);
    event AgentMetadataUpdated(
        string indexed dockerfileHash,
        string newLocation,
        string newDescription,
        AgentCategory newCategory
    );

    // Errors
    error AgentAlreadyRegistered(string dockerfileHash);
    error AgentNotRegistered();
    error NotAgentOwner();
    error InvalidExecutionFee();
    error EmptyPolicyIds();
    error EmptyDockerfileHash();
    error EmptyAgentLocation();
    error EmptyDescription();
    error InvalidIndex();

    PolicyRegistry public policyRegistry;

    constructor(address _policyRegistry) {
        policyRegistry = PolicyRegistry(_policyRegistry);
    }

    /**
     * @notice Register a new agent with execution fee and policy IDs
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param executionFee Fee to be charged for each agent execution, in wei
     * @param policyIds Array of policy IDs from the PolicyRegistry
     * @param agentLocation URL/IPFS hash where agent is hosted
     * @param description Brief description of the agent
     * @param category Category the agent belongs to
     */
    function registerAgent(
        string calldata dockerfileHash,
        uint256 executionFee,
        uint256[] calldata policyIds,
        string calldata agentLocation,
        string calldata description,
        AgentCategory category
    ) external {
        if (bytes(dockerfileHash).length == 0) revert EmptyDockerfileHash();
        if (bytes(agentLocation).length == 0) revert EmptyAgentLocation();
        if (bytes(description).length == 0) revert EmptyDescription();
        if (agents[dockerfileHash].isRegistered)
            revert AgentAlreadyRegistered(dockerfileHash);
        if (executionFee == 0) revert InvalidExecutionFee();
        if (policyIds.length == 0) revert EmptyPolicyIds();

        // Verify all policies are valid and active
        policyRegistry.verifyPolicies(policyIds);

        // Register the agent
        agents[dockerfileHash] = Agent({
            owner: msg.sender,
            executionFee: executionFee,
            policyIds: policyIds,
            isRegistered: true,
            dockerfileHash: dockerfileHash,
            agentLocation: agentLocation,
            description: description,
            category: category
        });

        // Convert string to bytes32 for storage
        bytes32 hashAsBytes32 = keccak256(bytes(dockerfileHash));
        _registeredHashes.add(hashAsBytes32);

        emit AgentRegistered(
            dockerfileHash,
            msg.sender,
            executionFee,
            agentLocation,
            description,
            category
        );
    }

    /**
     * @notice Update agent's execution fee
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param newExecutionFee New fee to be charged for each agent execution
     */
    function updateExecutionFee(
        string calldata dockerfileHash,
        uint256 newExecutionFee
    ) external {
        if (!agents[dockerfileHash].isRegistered) {
            revert AgentNotRegistered();
        }
        if (msg.sender != agents[dockerfileHash].owner) {
            revert NotAgentOwner();
        }
        if (newExecutionFee == 0) {
            revert InvalidExecutionFee();
        }

        agents[dockerfileHash].executionFee = newExecutionFee;
        emit AgentUpdated(dockerfileHash, newExecutionFee);
    }

    /**
     * @notice Update agent's policy IDs
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param newPolicyIds New array of policy IDs
     */
    function updatePolicyIds(
        string calldata dockerfileHash,
        uint256[] calldata newPolicyIds
    ) external {
        if (!agents[dockerfileHash].isRegistered) {
            revert AgentNotRegistered();
        }
        if (msg.sender != agents[dockerfileHash].owner) {
            revert NotAgentOwner();
        }
        if (newPolicyIds.length == 0) {
            revert EmptyPolicyIds();
        }

        // Verify all policies are valid and active
        policyRegistry.verifyPolicies(newPolicyIds);

        agents[dockerfileHash].policyIds = newPolicyIds;
        emit PolicyIdsUpdated(dockerfileHash, newPolicyIds);
    }

    /**
     * @notice Update agent's metadata
     * @param dockerfileHash Hash of the agent's Dockerfile
     * @param newLocation New URL/IPFS hash where agent is hosted
     * @param newDescription New description of the agent
     * @param newCategory New category for the agent
     */
    function updateAgentMetadata(
        string calldata dockerfileHash,
        string calldata newLocation,
        string calldata newDescription,
        AgentCategory newCategory
    ) external {
        if (!agents[dockerfileHash].isRegistered) revert AgentNotRegistered();
        if (msg.sender != agents[dockerfileHash].owner) revert NotAgentOwner();
        if (bytes(newLocation).length == 0) revert EmptyAgentLocation();
        if (bytes(newDescription).length == 0) revert EmptyDescription();

        Agent storage agent = agents[dockerfileHash];
        agent.agentLocation = newLocation;
        agent.description = newDescription;
        agent.category = newCategory;

        emit AgentMetadataUpdated(
            dockerfileHash,
            newLocation,
            newDescription,
            newCategory
        );
    }

    /**
     * @notice Get agent details
     * @param dockerfileHash Hash of the agent's Dockerfile
     */
    function getAgent(
        string calldata dockerfileHash
    )
        external
        view
        returns (
            address owner,
            uint256 executionFee,
            uint256[] memory policyIds,
            bool isRegistered,
            string memory agentDockerfileHash,
            string memory agentLocation,
            string memory description,
            AgentCategory category
        )
    {
        Agent memory agent = agents[dockerfileHash];
        return (
            agent.owner,
            agent.executionFee,
            agent.policyIds,
            agent.isRegistered,
            agent.dockerfileHash,
            agent.agentLocation,
            agent.description,
            agent.category
        );
    }

    /**
     * @notice Get total number of registered agents
     * @return Number of registered agents
     */
    function getAgentCount() external view returns (uint256) {
        return _registeredHashes.length();
    }

    /**
     * @notice Get agent hash at specific index
     * @param index Index in the set of registered hashes
     * @return Agent's dockerfile hash at the specified index
     */
    function getAgentHashAtIndex(
        uint256 index
    ) external view returns (string memory) {
        if (index >= _registeredHashes.length()) {
            revert InvalidIndex();
        }
        bytes32 hashAsBytes32 = _registeredHashes.at(index);
        // Note: This is a simplified conversion. In practice, you might want to store
        // the original string mapping alongside the bytes32 hash
        return string(abi.encodePacked(hashAsBytes32));
    }

    /**
     * @notice Get all registered agent hashes
     * @return Array of all registered dockerfile hashes
     */
    function getAllAgentHashes() external view returns (string[] memory) {
        uint256 length = _registeredHashes.length();
        string[] memory hashes = new string[](length);

        for (uint256 i = 0; i < length; i++) {
            bytes32 hashAsBytes32 = _registeredHashes.at(i);
            hashes[i] = string(abi.encodePacked(hashAsBytes32));
        }

        return hashes;
    }
}
