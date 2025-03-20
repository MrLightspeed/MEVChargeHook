// SPDX-License-Identifier: MIT
pragma solidity =0.8.29;

import {BaseHook} from "@uniswap/v4-periphery/src/utils/BaseHook.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {UD60x18} from "@prb/math/src/UD60x18.sol";

/// @notice Extended interface for Uniswap V4 PoolManager to retrieve pool addresses.
interface IPoolManagerExtended is IPoolManager {
    function pools(bytes32 poolId) external view returns (address);
}

/// @notice Minimal interface for a Uniswap V4 liquidity pool.
interface IUniswapV4Pool {
    function liquidity() external view returns (uint128);
}

/// @title MEVChargeHook
/// @notice Implements cooldown, reversed sqrt decay, and price-impact fees for Uniswap V4 pools.
/// @dev Optimized with immutable variables and gas-efficient calculations.
contract MEVChargeHook is BaseHook, Ownable {
    // ----------------------------- Constants & Immutable -----------------------------------
    uint256 private constant _MAX_COOLDOWN_SECONDS = 600;
    uint256 private constant _MALICIOUS_FEE_MAX = 2500; // 25%
    uint256 private constant _FEE_DENOMINATOR = 10000;

    // --------------------------------- Storage --------------------------------------------
    uint256 public cooldownSeconds = 12;
    uint256 public feeMin = 100; // 1%
    uint256 public feeMax = 500; // 5%

    /// @dev Stores user-specific data (packed for gas savings).
    struct UserData {
        uint64 lastActivityTimestamp;
        bool isFeeAddress;
    }

    mapping(address userAddress => UserData data) public _userData;

    // --------------------------------- Events ---------------------------------------------
    event ActivityRecorded(address indexed user);
    event CooldownSecondsUpdated(address indexed owner, uint256 newCooldownSeconds);
    event FeeRangeUpdated(uint256 indexed feeMin, uint256 indexed feeMax);
    event FeeAddressAdded(address indexed addr);
    event FeeAddressRemoved(address indexed addr);
    event LiquidityAdded(address indexed user, PoolKey poolKey, IPoolManager.ModifyLiquidityParams params, bytes data);
    event LiquidityRemoved(address indexed user, PoolKey poolKey, IPoolManager.ModifyLiquidityParams params, bytes data);

    // --------------------------------- Errors ---------------------------------------------
    error ZeroAddress();
    error CooldownActive();
    error InvalidPoolManagerAddress();
    error CooldownTooHigh();
    error FeeMinNotLessThanFeeMax();
    error FeeMaxTooHigh();
    error AlreadyMarked();
    error NotMarked();
    error NoLiquidity();

    // --------------------------------- Constructor ----------------------------------------
    /// @param _poolManager Uniswap V4 PoolManager (non-zero address).
    /// @param _owner Owner address (non-zero).
    constructor(IPoolManager _poolManager, address _owner)
        BaseHook(_poolManager)
        Ownable(_owner)
    {
        if (address(_poolManager) == address(0)) revert InvalidPoolManagerAddress();
        if (_owner == address(0)) revert ZeroAddress();
        poolManager = _poolManager;
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    // --------------------------- External Admin Functions ----------------------------------
    /// @notice Sets cooldown duration (max 600 seconds).
    /// @param newCooldownSeconds Cooldown duration in seconds.
    function setCooldownSeconds(uint256 newCooldownSeconds) external onlyOwner {
        if (newCooldownSeconds >= _MAX_COOLDOWN_SECONDS + 1) revert CooldownTooHigh();
        uint256 currentCooldownSeconds = cooldownSeconds; // Cache in memory
        if (currentCooldownSeconds != newCooldownSeconds) {
            cooldownSeconds = newCooldownSeconds;
            emit CooldownSecondsUpdated(msg.sender, newCooldownSeconds);
        }
    }

    /// @notice Updates min and max fee range (min < max < 501).
    /// @param newFeeMin Minimum fee (bps).
    /// @param newFeeMax Maximum fee (bps).
    function setFeeRange(uint256 newFeeMin, uint256 newFeeMax) external onlyOwner {
        if (!(newFeeMin < newFeeMax)) revert FeeMinNotLessThanFeeMax();
        if (newFeeMax >= 501) revert FeeMaxTooHigh();

        uint256 currentFeeMin = feeMin;
        uint256 currentFeeMax = feeMax;
        if (currentFeeMin != newFeeMin || currentFeeMax != newFeeMax) {
            feeMin = newFeeMin;
            feeMax = newFeeMax;
            emit FeeRangeUpdated(newFeeMin, newFeeMax);
        }
    }

    /// @notice Marks an address as fee-flagged (max fee applied).
    /// @param addr Address to flag.
    function addFeeAddress(address addr) external onlyOwner {
        if (addr == address(0)) revert ZeroAddress();
        UserData storage user = _userData[addr];  // Cache in storage pointer
        if (user.isFeeAddress) revert AlreadyMarked();
        user.isFeeAddress = true;
        emit FeeAddressAdded(addr);
    }

    /// @notice Removes fee-flag from an address.
    /// @param addr Address to unflag.
    function removeFeeAddress(address addr) external onlyOwner {
        if (addr == address(0)) revert ZeroAddress();
        UserData storage userData = _userData[addr];
        if (!userData.isFeeAddress) revert NotMarked();
        userData.isFeeAddress = false;
        emit FeeAddressRemoved(addr);
    }

    // ---------------------------- Hook Permissions -----------------------------------------
    /// @notice Returns enabled Uniswap V4 hook permissions.
    function getHookPermissions() public pure override returns (Hooks.Permissions memory permissions) {
        permissions = Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: true,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: true,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // ------------------------------ Internal Hooks -----------------------------------------
    /// @notice Executes before swap: computes fee (time & impact-based).
    function _beforeSwap(
        address recipient,
        PoolKey calldata poolKey,
        IPoolManager.SwapParams calldata swapParams,
        bytes calldata
    ) internal override returns (bytes4 selector, BeforeSwapDelta delta, uint24 feeBasisPoints) {
        if (recipient == address(0)) revert ZeroAddress();

        UserData storage cachedUser = _userData[recipient];

        uint256 timeFee = _calculateTimeFee(cachedUser);
        uint256 impactFee = _calculateImpactFee(poolKey, swapParams, timeFee);

        feeBasisPoints = uint24(timeFee > impactFee ? timeFee : impactFee);
        feeBasisPoints = feeBasisPoints == 0 ? 1 : feeBasisPoints;

        cachedUser.lastActivityTimestamp = uint64(block.timestamp);
        emit ActivityRecorded(recipient);

        selector = BaseHook.beforeSwap.selector;
        delta = BeforeSwapDeltaLibrary.ZERO_DELTA;
    }

    // -------------------------- Internal Calculations -------------------------------------
    /**
     * @notice Calculates time-based fee using reversed sqrt decay with UD60x18 precision.
     * @dev Correctly scales values by 1e18 (fixed-point) for UD60x18 compatibility to maintain precision during division and sqrt.
     * @param cachedUser Reference to the stored user data.
      *@return fee The calculated fee in basis points.
     */
    function _calculateTimeFee(UserData storage cachedUser) private view returns (uint256 fee) {
        uint256 lastActivityTimestamp = cachedUser.lastActivityTimestamp;
        bool isFeeAddress = cachedUser.isFeeAddress;

        if (lastActivityTimestamp == 0) {
            fee = feeMin;
        } else if (isFeeAddress) {
            fee = feeMax;
        } else {
            uint256 elapsed = block.timestamp - lastActivityTimestamp;
            if (elapsed >= cooldownSeconds) {
                fee = feeMin;
            } else {
                UD60x18 ratio = UD60x18.wrap((elapsed * 1e36) / cooldownSeconds);
                uint256 reversedFactor = 1e18 - ratio.sqrt().unwrap();
                fee = feeMin + (((feeMax - feeMin) * reversedFactor) / 1e18);
            }
        }
    }

    /**
     * @notice Calculates price impact–based fee with improved precision.
     * @dev Uses enhanced scaling (1e36) before division to minimize truncation errors.
     * @param poolKey Information identifying the liquidity pool.
     * @param swapParams Swap parameters from Uniswap V4.
     * @param timeFee Previously computed time-based fee.
     * @return impactFee Calculated fee in basis points, capped explicitly at _MALICIOUS_FEE_MAX.
     */
    function _calculateImpactFee(
        PoolKey calldata poolKey,
        IPoolManager.SwapParams calldata swapParams,
        uint256 timeFee
    ) private view returns (uint256 impactFee) {
        uint256 absAmount = swapParams.amountSpecified >= 0
            ? uint256(swapParams.amountSpecified)
            : uint256(-swapParams.amountSpecified);

        uint128 liquidity = _getPoolLiquidity(poolKey);
        if (liquidity == 0) revert NoLiquidity();

        uint256 feeDenominator = _FEE_DENOMINATOR; // Cache in memory
        uint256 impactBps = (absAmount * feeDenominator) / liquidity;

        if (impactBps <= 500) {
            impactFee = timeFee;
            return impactFee;
        }

        uint256 adjustedImpact = impactBps > 10000 ? 9500 : impactBps - 500;
        uint256 feeRange = _MALICIOUS_FEE_MAX - feeMin;

        // Cache _MALICIOUS_FEE_MAX in memory
        uint256 maliciousFeeMax = _MALICIOUS_FEE_MAX;

        // Enhanced precision: multiply by 1e36 before division
        UD60x18 normalizedImpact = UD60x18.wrap((adjustedImpact * 1e36) / 9500);
        uint256 sqrtImpact = normalizedImpact.sqrt().unwrap();

        // Scaling factor here is 1e18 to match UD60x18 scaling
        impactFee = feeMin + ((feeRange * sqrtImpact) / 1e18);

        if (impactFee >= maliciousFeeMax) {
            impactFee = maliciousFeeMax;
        }
    }


    /// @dev Retrieves pool liquidity from Uniswap V4 Pool.
    function _getPoolLiquidity(PoolKey calldata poolKey) private view returns (uint128 liquidity) {
        address poolAddr = IPoolManagerExtended(address(poolManager)).pools(
            keccak256(abi.encode(
                poolKey.currency0,
                poolKey.currency1,
                poolKey.fee,
                poolKey.tickSpacing,
                poolKey.hooks
            ))
        );
        liquidity = IUniswapV4Pool(poolAddr).liquidity();
    }

    /**
     * @notice Called before adding liquidity.
     * @dev Reverts if the caller is within an active cooldown period.
     *      For fee-flagged addresses, a stricter cooldown (maximum allowed) is enforced.
     * @param user The address adding liquidity.
     * @param poolKey The key identifying the pool.
     * @param params Parameters for liquidity modification.
     * @param data Additional data provided.
     * @return selector The function selector for beforeAddLiquidity.
     */
    function _beforeAddLiquidity(
        address user,
        PoolKey calldata poolKey,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata data
    )
        internal
        virtual
        override
        returns (bytes4 selector)
    {
        if (user == address(0)) revert ZeroAddress();

        UserData storage cachedUser = _userData[user];
        uint256 effectiveCooldown = cachedUser.isFeeAddress ? _MAX_COOLDOWN_SECONDS : cooldownSeconds;

        if (block.timestamp <= uint256(cachedUser.lastActivityTimestamp) + effectiveCooldown) {
            revert CooldownActive();
        }

        cachedUser.lastActivityTimestamp = uint64(block.timestamp);
        emit LiquidityAdded(user, poolKey, params, data);

        selector = BaseHook.beforeAddLiquidity.selector;
    }

    /**
     * @notice Called before removing liquidity.
     * @dev Reverts if the caller is within an active cooldown period.
     *      For fee-flagged addresses, a stricter cooldown (maximum allowed) is enforced.
     * @param user The address removing liquidity.
     * @param poolKey The key identifying the pool.
     * @param params Parameters for liquidity modification.
     * @param data Additional data provided.
     * @return selector The function selector for beforeRemoveLiquidity.
     */
    function _beforeRemoveLiquidity(
        address user,
        PoolKey calldata poolKey,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata data
    )
        internal
        virtual
        override
        returns (bytes4 selector)
    {
        if (user == address(0)) revert ZeroAddress();

        UserData storage cachedUser = _userData[user];
        uint256 effectiveCooldown = cachedUser.isFeeAddress ? _MAX_COOLDOWN_SECONDS : cooldownSeconds;

        if (block.timestamp <= uint256(cachedUser.lastActivityTimestamp) + effectiveCooldown) {
            revert CooldownActive();
        }

        cachedUser.lastActivityTimestamp = uint64(block.timestamp);
        emit LiquidityRemoved(user, poolKey, params, data);

        selector = BaseHook.beforeRemoveLiquidity.selector;
    }
}