// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

contract PolicyRegistryTest is Test {
    PolicyRegistry public policyRegistry;
    address public admin;
    address public creator;
    address public user;

    // Test function selectors
    bytes4 constant TRANSFER_SELECTOR =
        bytes4(keccak256("transfer(address,uint256)"));
    bytes4 constant APPROVE_SELECTOR =
        bytes4(keccak256("approve(address,uint256)"));

    event PolicyRegistered(
        uint256 indexed policyId,
        string name,
        string description,
        address indexed creator
    );
    event PolicyDeactivated(uint256 indexed policyId);
    event PolicyReactivated(uint256 indexed policyId);

    function setUp() public {
        admin = makeAddr("admin");
        creator = makeAddr("creator");
        user = makeAddr("user");

        vm.startPrank(admin);
        policyRegistry = new PolicyRegistry();

        // Grant creator role to creator address
        policyRegistry.grantRole(policyRegistry.POLICY_CREATOR_ROLE(), creator);
        vm.stopPrank();
    }

    function test_RegisterPolicy() public {
        vm.startPrank(creator);

        string memory name = "Test Policy";
        string memory description = "Test Description";
        uint256 startTime = 0;
        uint256 endTime = 0;
        bytes4[] memory allowedFunctions = new bytes4[](1);
        allowedFunctions[0] = TRANSFER_SELECTOR;
        address[] memory allowedContracts = new address[](1);
        allowedContracts[0] = makeAddr("contract1");

        vm.expectEmit(true, true, false, true);
        emit PolicyRegistered(1, name, description, creator);

        uint256 policyId = policyRegistry.registerPolicy(
            name,
            description,
            startTime,
            endTime,
            allowedFunctions,
            allowedContracts
        );

        assertEq(policyId, 1);

        (
            string memory storedName,
            string memory storedDesc,
            PolicyRegistry.TimeCondition memory whenCondition,
            PolicyRegistry.ActionCondition memory howCondition,
            PolicyRegistry.ResourceCondition memory whatCondition,
            bool isActive,
            address storedCreator
        ) = policyRegistry.getPolicyMetadata(policyId);

        assertEq(storedName, name);
        assertEq(storedDesc, description);
        assertEq(whenCondition.startTime, startTime);
        assertEq(whenCondition.endTime, endTime);
        assertEq(howCondition.allowedFunctions.length, 1);
        assertEq(howCondition.allowedFunctions[0], TRANSFER_SELECTOR);
        assertEq(whatCondition.allowedContracts.length, 1);
        assertEq(whatCondition.allowedContracts[0], allowedContracts[0]);
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

        bytes4[] memory allowedFunctions = new bytes4[](1);
        allowedFunctions[0] = TRANSFER_SELECTOR;
        address[] memory allowedContracts = new address[](1);
        allowedContracts[0] = makeAddr("contract1");

        policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            0,
            0,
            allowedFunctions,
            allowedContracts
        );
        vm.stopPrank();
    }

    function test_DeactivatePolicy() public {
        // First register a policy
        vm.startPrank(creator);

        bytes4[] memory allowedFunctions = new bytes4[](1);
        allowedFunctions[0] = TRANSFER_SELECTOR;
        address[] memory allowedContracts = new address[](1);
        allowedContracts[0] = makeAddr("contract1");

        uint256 policyId = policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            0,
            0,
            allowedFunctions,
            allowedContracts
        );

        vm.expectEmit(true, false, false, false);
        emit PolicyDeactivated(policyId);

        policyRegistry.deactivatePolicy(policyId);

        (, , , , , bool isActive, ) = policyRegistry.getPolicyMetadata(
            policyId
        );
        assertFalse(isActive);
        vm.stopPrank();
    }

    function test_ReactivatePolicy() public {
        // First register and deactivate a policy
        vm.startPrank(creator);

        bytes4[] memory allowedFunctions = new bytes4[](1);
        allowedFunctions[0] = TRANSFER_SELECTOR;
        address[] memory allowedContracts = new address[](1);
        allowedContracts[0] = makeAddr("contract1");

        uint256 policyId = policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            0,
            0,
            allowedFunctions,
            allowedContracts
        );

        policyRegistry.deactivatePolicy(policyId);

        vm.expectEmit(true, false, false, false);
        emit PolicyReactivated(policyId);

        policyRegistry.reactivatePolicy(policyId);

        (, , , , , bool isActive, ) = policyRegistry.getPolicyMetadata(
            policyId
        );
        assertTrue(isActive);
        vm.stopPrank();
    }

    function test_verifyPolicies() public {
        // Register a policy
        vm.startPrank(creator);

        bytes4[] memory allowedFunctions = new bytes4[](1);
        allowedFunctions[0] = TRANSFER_SELECTOR;
        address[] memory allowedContracts = new address[](1);
        allowedContracts[0] = makeAddr("contract1");

        uint256 policyId = policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            0,
            0,
            allowedFunctions,
            allowedContracts
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        // This should not revert
        policyRegistry.verifyPolicies(policyIds);
        vm.stopPrank();
    }

    function test_RevertWhen_VerifyingInactivePolicy() public {
        // Register and deactivate a policy
        vm.startPrank(creator);

        bytes4[] memory allowedFunctions = new bytes4[](1);
        allowedFunctions[0] = TRANSFER_SELECTOR;
        address[] memory allowedContracts = new address[](1);
        allowedContracts[0] = makeAddr("contract1");

        uint256 policyId = policyRegistry.registerPolicy(
            "Test Policy",
            "Test Description",
            0,
            0,
            allowedFunctions,
            allowedContracts
        );

        policyRegistry.deactivatePolicy(policyId);

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        vm.expectRevert(abi.encodeWithSelector(PolicyRegistry.PolicyNotActive.selector, policyId));
        policyRegistry.verifyPolicies(policyIds);
        vm.stopPrank();
    }
}
