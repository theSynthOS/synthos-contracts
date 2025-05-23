// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface ITaskRegistry {
    // Struct to store task information
    struct Task {
        address from; // Address that created the task
        address to; // Target address for the task execution
        bytes callData; // Calldata to be executed
        uint256 timestamp; // When the task was created
    }

    function registerTask(
        string memory uuid,
        address to,
        bytes calldata callData
    ) external;
    function getTask(string memory uuid) external view returns (Task memory);
}
