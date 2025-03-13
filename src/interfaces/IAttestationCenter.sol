// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.19;
/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
import {IAvsLogic} from "./IAvsLogic.sol";

interface IAttestationCenter {
    struct TaskInfo {
        string proofOfTask;
        bytes data;
        address taskPerformer;
        uint16 taskDefinitionId;
    }

    function setAvsLogic(address _avsLogic) external;

    function transferAvsGovernanceMultisig(
        address _newAvsGovernanceMultisig
    ) external;
}
