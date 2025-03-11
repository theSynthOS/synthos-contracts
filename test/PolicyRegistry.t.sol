// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {IPolicy} from "../src/interfaces/IPolicy.sol";

// Mock Policy for testing
contract MockPolicy is IPolicy {
    function validateAction(
        string calldata /* agentId */,
        bytes calldata /* data */
    ) external pure returns (bool valid, string memory reason) {
        return (true, "");
    }
}

contract PolicyRegistryTest is Test {
    PolicyRegistry public policyRegistry;
    address public admin;
    address public creator;
    address public user;
    MockPolicy public mockPolicy;

    event PolicyRegistered(
        address indexed implementation,
        string name,
        string description,
        address indexed creator
    );
    event PolicyDeactivated(address indexed implementation);
    event PolicyReactivated(address indexed implementation);

    function setUp() public {
        admin = makeAddr("admin");
        creator = makeAddr("creator");
        user = makeAddr("user");

        vm.startPrank(admin);
        policyRegistry = new PolicyRegistry();
        mockPolicy = new MockPolicy();

        // Grant creator role to creator address
        policyRegistry.grantRole(policyRegistry.POLICY_CREATOR_ROLE(), creator);
        vm.stopPrank();
    }

    function test_RegisterPolicy() public {
        vm.startPrank(creator);

        string memory name = "Test Policy";
        string memory description = "Test Description";
        address implementation = address(mockPolicy);

        vm.expectEmit(true, true, false, true);
        emit PolicyRegistered(implementation, name, description, creator);

        policyRegistry.registerPolicy(name, description, implementation);

        (
            string memory storedName,
            string memory storedDesc,
            bool isActive,
            address storedCreator
        ) = policyRegistry.getPolicyMetadata(implementation);

        assertEq(storedName, name);
        assertEq(storedDesc, description);
        assertTrue(isActive);
        assertEq(storedCreator, creator);
        vm.stopPrank();
    }

    function test_RevertWhen_NonCreatorRegistersPolicy() public {
        vm.startPrank(user);

        bytes32 role = policyRegistry.POLICY_CREATOR_ROLE();
        vm.expectRevert(
            abi.encodeWithSignature(
                "AccessControlUnauthorizedAccount(address,bytes32)",
                user,
                role
            )
        );

        policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            address(mockPolicy)
        );
        vm.stopPrank();
    }

    function test_DeactivatePolicy() public {
        // First register a policy
        vm.startPrank(creator);
        policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            address(mockPolicy)
        );

        vm.expectEmit(true, false, false, false);
        emit PolicyDeactivated(address(mockPolicy));

        policyRegistry.deactivatePolicy(address(mockPolicy));

        (, , bool isActive, ) = policyRegistry.getPolicyMetadata(
            address(mockPolicy)
        );
        assertFalse(isActive);
        vm.stopPrank();
    }

    function test_ReactivatePolicy() public {
        // First register and deactivate a policy
        vm.startPrank(creator);
        policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            address(mockPolicy)
        );
        policyRegistry.deactivatePolicy(address(mockPolicy));

        vm.expectEmit(true, false, false, false);
        emit PolicyReactivated(address(mockPolicy));

        policyRegistry.reactivatePolicy(address(mockPolicy));

        (, , bool isActive, ) = policyRegistry.getPolicyMetadata(
            address(mockPolicy)
        );
        assertTrue(isActive);
        vm.stopPrank();
    }

    function test_GetAllPoliciesWithMetadata() public {
        // Register multiple policies
        vm.startPrank(creator);
        MockPolicy mockPolicy2 = new MockPolicy();

        policyRegistry.registerPolicy(
            "Policy 1",
            "Description 1",
            address(mockPolicy)
        );
        policyRegistry.registerPolicy(
            "Policy 2",
            "Description 2",
            address(mockPolicy2)
        );

        (
            address[] memory addresses,
            string[] memory names,
            string[] memory descriptions,
            bool[] memory isActives,
            address[] memory creators
        ) = policyRegistry.getAllPoliciesWithMetadata();

        assertEq(addresses.length, 2);
        assertEq(names[0], "Policy 1");
        assertEq(descriptions[1], "Description 2");
        assertTrue(isActives[0]);
        assertEq(creators[0], creator);
        vm.stopPrank();
    }

    function test_VerifyPolicies() public {
        // Register a policy
        vm.startPrank(creator);
        policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            address(mockPolicy)
        );

        address[] memory policies = new address[](1);
        policies[0] = address(mockPolicy);

        bool isValid = policyRegistry.verifyPolicies(policies);
        assertTrue(isValid);
        vm.stopPrank();
    }

    function test_RevertWhen_VerifyingInactivePolicy() public {
        // Register and deactivate a policy
        vm.startPrank(creator);
        policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            address(mockPolicy)
        );
        policyRegistry.deactivatePolicy(address(mockPolicy));

        address[] memory policies = new address[](1);
        policies[0] = address(mockPolicy);

        vm.expectRevert(PolicyRegistry.PolicyNotActive.selector);
        policyRegistry.verifyPolicies(policies);
        vm.stopPrank();
    }
}
