// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

contract AgentRegistryTest is Test {
    AgentRegistry public agentRegistry;
    PolicyRegistry public policyRegistry;
    address public admin;
    address public owner;
    address public user;
    uint256 public policyId1;
    uint256 public policyId2;

    event AgentRegistered(
        string indexed dockerfileHash,
        address owner,
        uint256 executionFee,
        string agentLocation,
        string description,
        AgentRegistry.AgentCategory category
    );

    event PolicyIdsUpdated(string indexed dockerfileHash, uint256[] policyIds);

    function setUp() public {
        console.log("=== Setup ===");
        admin = makeAddr("admin");
        owner = makeAddr("owner");
        user = makeAddr("user");

        vm.startPrank(admin);
        policyRegistry = new PolicyRegistry();

        // Setup policy registry - create policies
        bytes4[] memory functions1 = new bytes4[](1);
        functions1[0] = bytes4(keccak256("transfer(address,uint256)"));
        address[] memory contracts1 = new address[](1);
        contracts1[0] = makeAddr("contract1");

        policyId1 = policyRegistry.registerPolicy(
            "Test Policy 1",
            "A policy for testing",
            0, // no start time
            0, // no end time
            functions1,
            contracts1
        );

        bytes4[] memory functions2 = new bytes4[](1);
        functions2[0] = bytes4(keccak256("approve(address,uint256)"));
        address[] memory contracts2 = new address[](1);
        contracts2[0] = makeAddr("contract2");

        policyId2 = policyRegistry.registerPolicy(
            "Test Policy 2",
            "Another policy for testing",
            0,
            0,
            functions2,
            contracts2
        );

        agentRegistry = new AgentRegistry(address(policyRegistry));
        vm.stopPrank();
    }

    function test_RegisterAgent() public {
        vm.startPrank(owner);

        string memory dockerfileHash = "hash1";
        uint256 executionFee = 0.1 ether;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId1;
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
            policyIds,
            location,
            description,
            category
        );

        (
            address storedOwner,
            uint256 storedFee,
            uint256[] memory storedPolicyIds,
            bool isRegistered,
            string memory storedHash,
            string memory storedLocation,
            string memory storedDescription,
            AgentRegistry.AgentCategory storedCategory
        ) = agentRegistry.getAgent(dockerfileHash);

        assertEq(storedOwner, owner);
        assertEq(storedFee, executionFee);
        assertEq(storedPolicyIds.length, 1);
        assertEq(storedPolicyIds[0], policyId1);
        assertTrue(isRegistered);
        assertEq(storedHash, dockerfileHash);
        assertEq(storedLocation, location);
        assertEq(storedDescription, description);
        assertEq(uint(storedCategory), uint(category));
        vm.stopPrank();
    }

    function test_UpdatePolicyIds() public {
        // First register an agent
        vm.startPrank(owner);

        string memory dockerfileHash = "hash1";
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId1;

        agentRegistry.registerAgent(
            dockerfileHash,
            0.1 ether,
            policyIds,
            "ipfs://location",
            "Test Agent",
            AgentRegistry.AgentCategory.DeFi
        );

        // Update policy IDs
        uint256[] memory newPolicyIds = new uint256[](2);
        newPolicyIds[0] = policyId1;
        newPolicyIds[1] = policyId2;

        vm.expectEmit(true, false, false, true);
        emit PolicyIdsUpdated(dockerfileHash, newPolicyIds);

        agentRegistry.updatePolicyIds(dockerfileHash, newPolicyIds);

        (, , uint256[] memory storedPolicyIds, , , , , ) = agentRegistry
            .getAgent(dockerfileHash);

        assertEq(storedPolicyIds.length, 2);
        assertEq(storedPolicyIds[0], policyId1);
        assertEq(storedPolicyIds[1], policyId2);
        vm.stopPrank();
    }

    function test_UpdateAgentMetadata() public {
        // First register an agent
        vm.startPrank(owner);

        string memory dockerfileHash = "hash1";
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId1;

        agentRegistry.registerAgent(
            dockerfileHash,
            0.1 ether,
            policyIds,
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

    function test_GetAgentHashById() public {
        vm.startPrank(owner);
        
        string memory dockerfileHash = "hash1";
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId1;

        agentRegistry.registerAgent(
            dockerfileHash,
            0.1 ether,
            policyIds,
            "ipfs://location",
            "Test Agent",
            AgentRegistry.AgentCategory.DeFi
        );

        // Agent ID should be 0 since it's the first agent
        assertEq(agentRegistry.getAgentHashById(0), dockerfileHash);
        vm.stopPrank();
    }

    function test_GetNextAgentId() public {
        assertEq(agentRegistry.getNextAgentId(), 0); // Initially 0

        vm.startPrank(owner);
        
        string memory dockerfileHash = "hash1";
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId1;

        agentRegistry.registerAgent(
            dockerfileHash,
            0.1 ether,
            policyIds,
            "ipfs://location",
            "Test Agent",
            AgentRegistry.AgentCategory.DeFi
        );

        assertEq(agentRegistry.getNextAgentId(), 1); // Should be 1 after registration
        vm.stopPrank();
    }

    function test_RevertWhen_GetAgentHashByInvalidId() public {
        vm.expectRevert(AgentRegistry.InvalidIndex.selector);
        agentRegistry.getAgentHashById(999); // Non-existent ID
    }
}
