// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {PolicyCoordinator} from "../src/PolicyCoordinator.sol";
import {ITaskRegistry} from "../src/interfaces/ITaskRegistry.sol";
import {CrosschainSender} from "../src/CrosschainSender.sol";

contract MockTaskRegistry is ITaskRegistry {
    mapping(bytes32 => Task) private tasks;

    function registerTask(
        bytes32 uuid,
        address from,
        bytes memory callData
    ) external {
        tasks[uuid] = Task({
            from: from,
            to: address(0),
            callData: callData,
            timestamp: block.timestamp
        });
    }

    function getTask(bytes32 uuid) external view returns (Task memory) {
        return tasks[uuid];
    }
}

contract PolicyCoordinatorTest is Test {
    AgentRegistry public agentRegistry;
    PolicyRegistry public policyRegistry;
    PolicyCoordinator public policyCoordinator;
    MockTaskRegistry public taskRegistry;
    CrosschainSender public sender;

    address public admin;
    address public agentOwner;
    address public user;

    bytes32 public constant safeTxHash = keccak256("example_transaction");
    string public dockerfileHash = "agent_dockerfile_hash";
    uint256 public defaultExecutionFee = 0.1 ether;
    address public targetContract1 = address(0x1);
    address public targetContract2 = address(0x2);
    bytes4 public function1 = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 public function2 = bytes4(keccak256("approve(address,uint256)"));
    uint256 public policyId1;
    uint256 public policyId2;
    uint256 public policyId3;

    address constant MAILBOX = address(0x1);
    uint32 constant ORIGIN_DOMAIN = 1;
    bytes32 constant TASK_UUID =
        0x43dca7b000000000000000000000000000000000000000000000000000000000;
    uint256 constant AGENT_ID = 123;
    address constant AGENT_ADDRESS = address(0x456);

    function setUp() public {
        admin = makeAddr("admin");
        agentOwner = makeAddr("agentOwner");
        user = makeAddr("user");

        vm.startPrank(admin);

        // Deploy contracts
        policyRegistry = new PolicyRegistry();
        agentRegistry = new AgentRegistry(address(policyRegistry));
        taskRegistry = new MockTaskRegistry();
        policyCoordinator = new PolicyCoordinator(
            address(agentRegistry),
            address(policyRegistry),
            address(taskRegistry),
            MAILBOX,
            ORIGIN_DOMAIN
        );

        // Setup initial policies
        // Policy 1: No time restrictions, allows both functions on contract1
        bytes4[] memory functions1 = new bytes4[](2);
        functions1[0] = function1;
        functions1[1] = function2;
        address[] memory contracts1 = new address[](1);
        contracts1[0] = targetContract1;
        policyId1 = policyRegistry.registerPolicy(
            "General Policy",
            "Allows transfer and approve on contract1",
            0, // no start time
            0, // no end time
            functions1,
            contracts1
        );

        // Policy 2: With time restrictions, only allows function1 on contract2
        bytes4[] memory functions2 = new bytes4[](1);
        functions2[0] = function1;
        address[] memory contracts2 = new address[](1);
        contracts2[0] = targetContract2;
        uint256 startTime = block.timestamp + 100;
        uint256 endTime = block.timestamp + 1000;
        policyId2 = policyRegistry.registerPolicy(
            "Time-Restricted Policy",
            "Only allows transfer on contract2 during specific time",
            startTime,
            endTime,
            functions2,
            contracts2
        );

        // Policy 3: No time restrictions, only allows function2 on both contracts
        bytes4[] memory functions3 = new bytes4[](1);
        functions3[0] = function2;
        address[] memory contracts3 = new address[](2);
        contracts3[0] = targetContract1;
        contracts3[1] = targetContract2;
        policyId3 = policyRegistry.registerPolicy(
            "Approve-Only Policy",
            "Only allows approve on both contracts",
            0,
            0,
            functions3,
            contracts3
        );

        vm.stopPrank();

        // Register agent
        vm.startPrank(agentOwner);
        uint256[] memory policyIds = new uint256[](2);
        policyIds[0] = policyId1;
        policyIds[1] = policyId2;

        agentRegistry.registerAgent(
            dockerfileHash,
            defaultExecutionFee,
            policyIds,
            "ipfs://location",
            "Test Agent",
            AgentRegistry.AgentCategory.DeFi
        );
        vm.stopPrank();

        // Register a task
        taskRegistry.registerTask(TASK_UUID, AGENT_ADDRESS, hex"a415bcad");
    }

    function test_ValidateTransactionWithValidPolicy() public {
        // This should pass because function1 on targetContract1 is allowed by policy1
        (bool isValid, string memory reason) = policyCoordinator
            .validateTransaction(
                dockerfileHash,
                targetContract1,
                function1,
                block.timestamp
            );

        assertTrue(isValid);
        assertContains(reason, "Policy 'General Policy' authorized");
    }

    function test_ValidateTransactionWithInvalidTarget() public view {
        // Create a random address not in any policy's allowed contracts
        address invalidTarget = address(0xDEAD);

        (bool isValid, string memory reason) = policyCoordinator
            .validateTransaction(
                dockerfileHash,
                invalidTarget,
                function1,
                block.timestamp
            );

        assertFalse(isValid);
        assertEq(reason, "No policy matched transaction parameters");
    }

    function test_ValidateTransactionWithInvalidFunction() public view {
        // Create a random function selector not in any policy
        bytes4 invalidFunction = bytes4(keccak256("invalidFunction()"));

        (bool isValid, string memory reason) = policyCoordinator
            .validateTransaction(
                dockerfileHash,
                targetContract1,
                invalidFunction,
                block.timestamp
            );

        assertFalse(isValid);
        assertEq(reason, "No policy matched transaction parameters");
    }

    function test_ValidateTransactionWithTimeRestrictedPolicy() public {
        // This should fail because we're before the time window for policy2
        (bool isValid, string memory reason) = policyCoordinator
            .validateTransaction(
                dockerfileHash,
                targetContract2,
                function1,
                block.timestamp
            );

        assertFalse(isValid);
        assertEq(reason, "No policy matched transaction parameters");

        // This should pass because we're inside the time window for policy2
        uint256 validTime = block.timestamp + 500; // Inside the time window
        (isValid, reason) = policyCoordinator.validateTransaction(
            dockerfileHash,
            targetContract2,
            function1,
            validTime
        );

        assertTrue(isValid);
        assertContains(reason, "Time-Restricted Policy");

        // This should fail because we're after the time window for policy2
        uint256 lateTime = block.timestamp + 1500; // After the end time
        (isValid, reason) = policyCoordinator.validateTransaction(
            dockerfileHash,
            targetContract2,
            function1,
            lateTime
        );

        assertFalse(isValid);
        assertEq(reason, "No policy matched transaction parameters");
    }

    function test_ValidateWithNonexistentAgent() public view {
        string memory fakeHash = "nonexistent_agent";

        (bool isValid, string memory reason) = policyCoordinator
            .validateTransaction(
                fakeHash,
                targetContract1,
                function1,
                block.timestamp
            );

        assertFalse(isValid);
        assertEq(reason, "Agent not registered");
    }

    function test_GetPoliciesForAgent() public view {
        (
            uint256[] memory policyIds,
            PolicyCoordinator.PolicyDetails[] memory policyDetails
        ) = policyCoordinator.getPoliciesForAgent(dockerfileHash);

        assertEq(policyIds.length, 2);
        assertEq(policyIds[0], policyId1);
        assertEq(policyIds[1], policyId2);
        assertEq(policyDetails.length, 2);
        assertEq(policyDetails[0].name, "General Policy");
        assertEq(policyDetails[1].name, "Time-Restricted Policy");
    }

    function test_ValidateWithSpecificPolicy() public {
        // Direct validation with policy1 should pass for function1 on targetContract1
        (bool isValid, string memory reason) = policyCoordinator
            .validateWithPolicy(
                policyId1,
                targetContract1,
                function1,
                block.timestamp
            );

        assertTrue(isValid);
        assertContains(reason, "General Policy");

        // Direct validation with policy3 should fail for function1 on targetContract1
        // (since policy3 only allows function2)
        (isValid, reason) = policyCoordinator.validateWithPolicy(
            policyId3,
            targetContract1,
            function1,
            block.timestamp
        );

        assertFalse(isValid);
        assertEq(reason, "Function not allowed by policy");
    }

    function test_AddPolicyToAgent() public {
        vm.startPrank(agentOwner);

        // Add policy3 to the agent
        uint256[] memory newPolicyIds = new uint256[](3);
        newPolicyIds[0] = policyId1;
        newPolicyIds[1] = policyId2;
        newPolicyIds[2] = policyId3;

        agentRegistry.updatePolicyIds(dockerfileHash, newPolicyIds);

        vm.stopPrank();

        // Now validate a transaction that would only be allowed by policy3
        (bool isValid, string memory reason) = policyCoordinator
            .validateTransaction(
                dockerfileHash,
                targetContract2,
                function2,
                block.timestamp
            );

        assertTrue(isValid);
        assertContains(reason, "Approve-Only Policy");
    }

    function test_DeactivatePolicyAffectsValidation() public {
        vm.startPrank(admin);

        // First confirm function1 on targetContract1 is valid (allowed by policy1)
        (bool isValid, string memory reason) = policyCoordinator
            .validateTransaction(
                dockerfileHash,
                targetContract1,
                function1,
                block.timestamp
            );
        assertTrue(isValid);

        // Deactivate policy1
        policyRegistry.deactivatePolicy(policyId1);

        // Now the validation should fail since policy1 is inactive and policy2 doesn't allow this combo
        (isValid, reason) = policyCoordinator.validateTransaction(
            dockerfileHash,
            targetContract1,
            function1,
            block.timestamp
        );

        assertFalse(isValid);
        assertEq(reason, "No policy matched transaction parameters");

        vm.stopPrank();
    }

    function test_MultipleValidPolicies() public {
        vm.startPrank(agentOwner);

        // Add policy3 to the agent
        uint256[] memory newPolicyIds = new uint256[](3);
        newPolicyIds[0] = policyId1;
        newPolicyIds[1] = policyId2;
        newPolicyIds[2] = policyId3;

        agentRegistry.updatePolicyIds(dockerfileHash, newPolicyIds);

        vm.stopPrank();

        // function2 on targetContract1 is allowed by both policy1 and policy3
        (bool isValid, string memory reason) = policyCoordinator
            .validateTransaction(
                dockerfileHash,
                targetContract1,
                function2,
                block.timestamp
            );

        assertTrue(isValid);
        // It should find policy1 first since we check in order
        assertContains(reason, "General Policy");
    }

    function test_HandleValidationData() public {
        // Create validation data
        string memory proofOfTask = "proof";
        uint256 timestamp = block.timestamp;
        string memory status = "APPROVED";
        string memory reason = "Policy validated successfully";

        // Encode message as it would come from CrosschainSender
        bytes memory message = abi.encode(
            proofOfTask,
            TASK_UUID,
            AGENT_ID,
            timestamp,
            status,
            reason
        );

        // Mock mailbox call
        vm.prank(MAILBOX);
        policyCoordinator.handle(ORIGIN_DOMAIN, bytes32(0), message);

        // Verify stored data
        (
            string memory storedStatus,
            string memory storedReason
        ) = policyCoordinator.getValidationStatus(TASK_UUID);
        assertEq(storedStatus, status, "Status not stored correctly");
        assertEq(storedReason, reason, "Reason not stored correctly");

        // Verify agent task tracking
        bytes32[] memory agentTasks = policyCoordinator.getAgentTasks(AGENT_ID);
        assertEq(agentTasks.length, 1, "Agent task not tracked");
        assertEq(agentTasks[0], TASK_UUID, "Wrong task UUID stored");

        // Verify task history
        PolicyCoordinator.AgentTaskDetails[] memory history = policyCoordinator
            .getAgentTaskHistory(AGENT_ID);
        assertEq(history.length, 1, "Task history not updated");
        assertEq(history[0].taskUuid, TASK_UUID, "Wrong task UUID in history");
        assertEq(
            history[0].receivedAt,
            timestamp,
            "Wrong timestamp in history"
        );

        // Verify latest task
        (bytes32 latestUuid, uint256 latestTime) = policyCoordinator
            .getAgentLatestTask(AGENT_ID);
        assertEq(latestUuid, TASK_UUID, "Wrong latest task UUID");
        assertEq(latestTime, timestamp, "Wrong latest task timestamp");
    }

    function test_HandleMultipleValidations() public {
        // Register second task
        bytes32 secondTaskUuid = bytes32(uint256(TASK_UUID) + 1);
        taskRegistry.registerTask(secondTaskUuid, AGENT_ADDRESS, hex"a415bcad");

        // First validation
        bytes memory message1 = abi.encode(
            "proof1",
            TASK_UUID,
            AGENT_ID,
            block.timestamp,
            "APPROVED",
            "First validation"
        );

        // Second validation
        bytes memory message2 = abi.encode(
            "proof2",
            secondTaskUuid,
            AGENT_ID,
            block.timestamp + 1,
            "DENIED",
            "Second validation"
        );

        // Process both validations
        vm.startPrank(MAILBOX);
        policyCoordinator.handle(ORIGIN_DOMAIN, bytes32(0), message1);
        policyCoordinator.handle(ORIGIN_DOMAIN, bytes32(0), message2);
        vm.stopPrank();

        // Verify both tasks are tracked
        bytes32[] memory agentTasks = policyCoordinator.getAgentTasks(AGENT_ID);
        assertEq(agentTasks.length, 2, "Not all tasks tracked");

        // Verify task history
        PolicyCoordinator.AgentTaskDetails[] memory history = policyCoordinator
            .getAgentTaskHistory(AGENT_ID);
        assertEq(history.length, 2, "History not complete");
        assertEq(history[0].taskUuid, TASK_UUID, "First task UUID wrong");
        assertEq(history[1].taskUuid, secondTaskUuid, "Second task UUID wrong");

        // Verify latest task is the second one
        (bytes32 latestUuid, ) = policyCoordinator.getAgentLatestTask(AGENT_ID);
        assertEq(latestUuid, secondTaskUuid, "Latest task not updated");
    }

    function test_RevertOnUnauthorizedSender() public {
        bytes memory message = abi.encode(
            "proof",
            TASK_UUID,
            AGENT_ID,
            block.timestamp,
            "APPROVED",
            "Test validation"
        );

        vm.prank(address(0x999));
        vm.expectRevert("Only mailbox can deliver");
        policyCoordinator.handle(ORIGIN_DOMAIN, bytes32(0), message);
    }

    function test_RevertOnInvalidDomain() public {
        bytes memory message = abi.encode(
            "proof",
            TASK_UUID,
            AGENT_ID,
            block.timestamp,
            "APPROVED",
            "Test validation"
        );

        vm.prank(MAILBOX);
        vm.expectRevert("Invalid origin domain");
        policyCoordinator.handle(ORIGIN_DOMAIN + 1, bytes32(0), message);
    }

    // Helper function to check if a string contains a substring
    function assertContains(
        string memory _string,
        string memory _substring
    ) internal {
        bytes memory stringBytes = bytes(_string);
        bytes memory substringBytes = bytes(_substring);

        bool found = false;
        for (uint i = 0; i <= stringBytes.length - substringBytes.length; i++) {
            bool allMatch = true;
            for (uint j = 0; j < substringBytes.length; j++) {
                if (stringBytes[i + j] != substringBytes[j]) {
                    allMatch = false;
                    break;
                }
            }
            if (allMatch) {
                found = true;
                break;
            }
        }

        if (!found) {
            emit log("Error: string does not contain substring");
            emit log_string("  String: ");
            emit log_string(_string);
            emit log_string("  Substring: ");
            emit log_string(_substring);
            fail();
        }
    }
}
