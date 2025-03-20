// SPDX-License-Identifier: MIT
pragma solidity =0.8.29;

import "forge-std/Script.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {MEVChargeHook} from "../src/MEVChargeHook.sol";
import {HookFactory} from "../src/HookFactory.sol";

contract DeployHookScript is Script {
    function computeSaltAndAddress(
        address deployer,
        uint160 flags,
        bytes memory creationCode,
        bytes memory constructorArgs
    ) internal pure returns (bytes32 salt, address hookAddress) {
        bytes memory creationCodeWithArgs = abi.encodePacked(creationCode, constructorArgs);
        uint256 maxLoop = 160_444;
        for (uint256 s = 0; s < maxLoop; s++) {
            address computed = address(uint160(uint256(keccak256(abi.encodePacked(
                bytes1(0xFF),
                deployer,
                s,
                keccak256(creationCodeWithArgs)
            )))));
            if ((uint160(computed) & 0x3FFF) == flags) {
                return (bytes32(s), computed);
            }
        }
        revert("No valid salt found");
    }

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployerAddress = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        HookFactory factory = new HookFactory();
        address factoryAddress = address(factory);

        uint160 flags = uint160(
            Hooks.BEFORE_ADD_LIQUIDITY_FLAG |
            Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG |
            Hooks.BEFORE_SWAP_FLAG
        );

        address poolManagerAddress = address(0x000000000004444c5dc75cB358380D2e3dE08A90);
        bytes memory constructorArgs = abi.encode(poolManagerAddress, deployerAddress);

        (bytes32 salt, address expectedHookAddress) = computeSaltAndAddress(
            factoryAddress,
            flags,
            type(MEVChargeHook).creationCode,
            constructorArgs
        );

        address deployedAddress = factory.deployHook(salt, poolManagerAddress, deployerAddress);
        require(expectedHookAddress == deployedAddress, "Address mismatch");

        vm.stopBroadcast();

        console.log("Deployed MEVChargeHook at:", deployedAddress);
        console.logBytes32(salt);
    }

}