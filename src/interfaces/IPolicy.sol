// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IPolicy {
    /**
     * @notice Validate if an action meets policy requirements
     * @param agentId The dockerfile hash of the agent
     * @param data The encoded action data to validate
     * @return valid True if the action is valid according to policy
     * @return reason Reason for rejection if invalid
     */
    function validateAction(
        string calldata agentId,
        bytes calldata data
    ) external view returns (bool valid, string memory reason);
}
