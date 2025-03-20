// SPDX-License-Identifier: MIT
pragma solidity =0.8.29;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {MEVChargeHook} from "./MEVChargeHook.sol";

contract HookFactory {
    event HookDeployed(address indexed hookAddress, bytes32 salt);

    /**
     * @notice Deploys a new MEVChargeHook using CREATE2.
     * @param salt The salt used in CREATE2.
     * @param poolManager The address of the Pool Manager.
     * @param owner The desired owner of the hook.
     * @return hookAddress The address of the deployed hook.
     */
    function deployHook(bytes32 salt, address poolManager, address owner) external returns (address hookAddress) {
        hookAddress = address(new MEVChargeHook{salt: salt}(IPoolManager(poolManager), owner));
        emit HookDeployed(hookAddress, salt);
    }
}
