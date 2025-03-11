// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {IPolicy} from "../src/interfaces/IPolicy.sol";

// Mock Policy for testing
contract MockPolicy is IPolicy {
    bool private shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function validateAction(
        string calldata,
        bytes calldata
    ) external view returns (bool valid, string memory reason) {
        return (shouldPass, shouldPass ? "" : "Policy check failed");
    }
}

contract AgentRegistryTest is Test {
    AgentRegistry public agentRegistry;
    PolicyRegistry public policyRegistry;
    address public admin;
    address public owner;
    address public user;
    MockPolicy public validPolicy;
    MockPolicy public invalidPolicy;

    event AgentRegistered(
        string indexed dockerfileHash,
        address owner,
        uint256 executionFee,
        string agentLocation,
        string description,
        AgentRegistry.AgentCategory category
    );

    function setUp() public {
        console.log("=== Setup ===");
        admin = makeAddr("admin");
        owner = makeAddr("owner");
        user = makeAddr("user");

        vm.startPrank(admin);
        policyRegistry = new PolicyRegistry();
        validPolicy = new MockPolicy(true);
        invalidPolicy = new MockPolicy(false);

        // Setup policy registry
        policyRegistry.grantRole(policyRegistry.POLICY_CREATOR_ROLE(), admin);
        policyRegistry.registerPolicy(
            "Valid Policy",
            "A policy that always passes",
            address(validPolicy)
        );

        agentRegistry = new AgentRegistry(address(policyRegistry));
        vm.stopPrank();
    }

    function test_RegisterAgent() public {
        vm.startPrank(owner);

        string memory dockerfileHash = "hash1";
        uint256 executionFee = 0.1 ether;
        address[] memory policies = new address[](1);
        policies[0] = address(validPolicy);
        string memory location = "ipfs://location";
        string memory description = "Test Agent";
        AgentRegistry.AgentCategory category = AgentRegistry.AgentCategory.DeFi;

        console.log("=== Register Agent ===");
        console.log("Hash:", dockerfileHash);
        console.log("Fee:", executionFee);
        console.log("Location:", location);
        console.log("Description:", description);

        vm.expectEmit(true, true, false, true);
        emit AgentRegistered(
            dockerfileHash,
            owner,
            executionFee,
            location,
            description,
            category
        );

        agentRegistry.registerAgent(
            dockerfileHash,
            executionFee,
            policies,
            location,
            description,
            category
        );

        (
            address storedOwner,
            uint256 storedFee,
            address[] memory storedPolicies,
            bool isRegistered,
            string memory storedHash,
            string memory storedLocation,
            string memory storedDescription,
            AgentRegistry.AgentCategory storedCategory
        ) = agentRegistry.getAgent(dockerfileHash);

        assertEq(storedOwner, owner);
        assertEq(storedFee, executionFee);
        assertEq(storedPolicies[0], policies[0]);
        assertTrue(isRegistered);
        assertEq(storedHash, dockerfileHash);
        assertEq(storedLocation, location);
        assertEq(storedDescription, description);
        assertEq(uint(storedCategory), uint(category));
        vm.stopPrank();
    }

    function test_ValidateAgentAction() public {
        // First register an agent
        vm.startPrank(owner);

        string memory dockerfileHash = "hash1";
        address[] memory policies = new address[](1);
        policies[0] = address(validPolicy);

        agentRegistry.registerAgent(
            dockerfileHash,
            0.1 ether,
            policies,
            "ipfs://location",
            "Test Agent",
            AgentRegistry.AgentCategory.DeFi
        );

        bool isValid = agentRegistry.validateAgentAction(dockerfileHash, "0x");
        assertTrue(isValid);
        vm.stopPrank();
    }

    function test_RevertWhen_ValidatingWithInvalidPolicy() public {
        vm.startPrank(admin);
        policyRegistry.registerPolicy(
            "Invalid Policy",
            "A policy that always fails",
            address(invalidPolicy)
        );
        vm.stopPrank();

        vm.startPrank(owner);
        string memory dockerfileHash = "hash1";
        address[] memory policies = new address[](1);
        policies[0] = address(invalidPolicy);

        agentRegistry.registerAgent(
            dockerfileHash,
            0.1 ether,
            policies,
            "ipfs://location",
            "Test Agent",
            AgentRegistry.AgentCategory.DeFi
        );

        vm.expectRevert("Policy check failed");
        agentRegistry.validateAgentAction(dockerfileHash, "0x");
        vm.stopPrank();
    }

    function test_UpdateAgentMetadata() public {
        // First register an agent
        vm.startPrank(owner);

        string memory dockerfileHash = "hash1";
        address[] memory policies = new address[](1);
        policies[0] = address(validPolicy);

        agentRegistry.registerAgent(
            dockerfileHash,
            0.1 ether,
            policies,
            "ipfs://location",
            "Test Agent",
            AgentRegistry.AgentCategory.DeFi
        );

        // Update metadata
        string memory newLocation = "ipfs://newlocation";
        string memory newDescription = "Updated Agent";
        AgentRegistry.AgentCategory newCategory = AgentRegistry
            .AgentCategory
            .Security;

        agentRegistry.updateAgentMetadata(
            dockerfileHash,
            newLocation,
            newDescription,
            newCategory
        );

        (
            ,
            ,
            ,
            ,
            ,
            string memory storedLocation,
            string memory storedDescription,
            AgentRegistry.AgentCategory storedCategory
        ) = agentRegistry.getAgent(dockerfileHash);

        assertEq(storedLocation, newLocation);
        assertEq(storedDescription, newDescription);
        assertEq(uint(storedCategory), uint(newCategory));
        vm.stopPrank();
    }
}
