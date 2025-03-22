// SPDX-License-Identifier: MIT
pragma solidity =0.8.29;

import {BaseHook} from "@uniswap/v4-periphery/src/utils/BaseHook.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {UD60x18} from "@prb/math/src/UD60x18.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {FullMath} from "@uniswap/v4-core/src/libraries/FullMath.sol";

/**
 * @notice Extended interface for Uniswap V4 PoolManager to retrieve pool addresses.
 */
interface IPoolManagerExtended is IPoolManager {
    function pools(bytes32 poolId) external view returns (address);
}

/**
 * @notice Minimal interface for a Uniswap V4 liquidity pool.
 */
interface IUniswapV4Pool {
    function liquidity() external view returns (uint128);
}

/**
 * @notice Extended interface to include TWAP observation.
 */
interface IUniswapV4PoolExtended is IUniswapV4Pool {
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}

/**
 * @notice Minimal interface for pool state.
 */
interface IUniswapV4PoolState {
    function slot0() external view returns (
        uint160 sqrtPriceX96,
        int24 tick,
        uint16 observationIndex,
        uint16 observationCardinality,
        uint16 observationCardinalityNext,
        uint8 feeProtocol,
        bool unlocked
    );
}

/**
 * @title MEVChargeHook
 * @notice Implements dynamic fee escalation with TWAP-based null fee, fee redistribution,
 *         per-user circular buffer swap tracking, enhanced multi-address detection,
 *         configurable surge fee threshold, minimum swap validation, and emergency withdrawal.
 *
 * @dev This refactored version reorders the internal function declarations to resolve "Stack too deep" and "Undeclared identifier"
 *      errors.
 */
contract MEVChargeHook is BaseHook, Ownable {
    using SafeERC20 for IERC20;

    // -------------------------------- Constants ----------------------------------------------
    uint256 private constant _MAX_COOLDOWN_SECONDS       = 600;
    uint256 private constant _MALICIOUS_FEE_MAX          = 2500; // 25%
    uint256 private constant _FEE_DENOMINATOR            = 10000;
    uint256 private constant _NULL_FEE_CAP               = 1000; // 10% in basis points
    uint256 private constant MULTI_BLOCK_SANDWICH_WINDOW = 5;    // in blocks

    // -------------------------------- Configurable Params -------------------------------------
    uint256 public cooldownSeconds = 12; // e.g. 12s
    uint256 public feeMin          = 100; // 1%
    uint256 public feeMax          = 500; // 5%
    uint256 public minSwapAmount   = 1e6;
    uint256 public surgeFeeThreshold = 1000; // 10%

    // -------------------------------- Fee Redistribution -------------------------------------
    struct PoolFees {
        uint128 token0Fees;
        uint128 token1Fees;
    }
    mapping(bytes32 => PoolFees) public poolFees;
    mapping(bytes32 => address)  public poolToken0;
    mapping(bytes32 => address)  public poolToken1;

    // -------------------------------- Swap Tracking ------------------------------------------
    uint32 constant MAX_HISTORY_LENGTH = 256;
    struct SwapEntry {
        uint32 blockNumber;
        bool   direction; // true if buy; false if sell
        uint256 amount;
    }
    struct SwapHistory {
        SwapEntry[MAX_HISTORY_LENGTH] swaps;
        uint32 nextIndex;
    }
    mapping(address => SwapHistory) private _swapHistories;

    // -------------------------------- User Data ---------------------------------------------
    struct UserData {
        uint64 lastActivityTimestamp;
        bool   isFeeAddress;
    }
    mapping(address => UserData) public _userData;

    // -------------------------------- Multi-Address Detection --------------------------------
    mapping(address => address) public addressOwner;

    // -------------------------------- Events -------------------------------------------------
    event ActivityRecorded(address indexed user);
    event CooldownSecondsUpdated(address indexed owner, uint256 newCooldownSeconds);
    event FeeRangeUpdated(uint256 indexed feeMin, uint256 indexed feeMax);
    event FeeAddressAdded(address indexed addr);
    event FeeAddressRemoved(address indexed addr);
    event LiquidityAdded(
        address indexed user,
        PoolKey poolKey,
        IPoolManager.ModifyLiquidityParams params,
        bytes data
    );
    event LiquidityRemoved(
        address indexed user,
        PoolKey poolKey,
        IPoolManager.ModifyLiquidityParams params,
        bytes data
    );
    event PoolTokensRegistered(bytes32 indexed poolId, address token0, address token1);
    event EmergencyWithdrawal(address token, uint256 amount);

    // -------------------------------- Errors -------------------------------------------------
    error ZeroAddress();
    error CooldownActive();
    error InvalidPoolManagerAddress();
    error CooldownTooHigh();
    error FeeMinNotLessThanFeeMax();
    error FeeMaxTooHigh();
    error AlreadyMarked();
    error NotMarked();
    error NoLiquidity();
    error SwapAmountTooLow();

    // -------------------------------- Constructor --------------------------------------------
    constructor(IPoolManager _poolManager, address _owner) BaseHook(_poolManager) Ownable(_owner) {
        if (address(_poolManager) == address(0)) revert InvalidPoolManagerAddress();
        if (_owner == address(0))         revert ZeroAddress();
        poolManager = _poolManager;
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    // -------------------------------- Admin Functions ----------------------------------------
    function setCooldownSeconds(uint256 newCooldownSeconds) external onlyOwner {
        if (newCooldownSeconds > _MAX_COOLDOWN_SECONDS) revert CooldownTooHigh();
        cooldownSeconds = newCooldownSeconds;
        emit CooldownSecondsUpdated(msg.sender, newCooldownSeconds);
    }

    function setFeeRange(uint256 newFeeMin, uint256 newFeeMax) external onlyOwner {
        if (!(newFeeMin < newFeeMax)) revert FeeMinNotLessThanFeeMax();
        if (newFeeMax > 500)         revert FeeMaxTooHigh();
        feeMin = newFeeMin;
        feeMax = newFeeMax;
        emit FeeRangeUpdated(newFeeMin, newFeeMax);
    }

    function addFeeAddress(address addr) external onlyOwner {
        if (addr == address(0)) revert ZeroAddress();
        UserData storage user = _userData[addr];
        if (user.isFeeAddress) revert AlreadyMarked();
        user.isFeeAddress = true;
        emit FeeAddressAdded(addr);
    }

    function removeFeeAddress(address addr) external onlyOwner {
        if (addr == address(0)) revert ZeroAddress();
        UserData storage userData = _userData[addr];
        if (!userData.isFeeAddress) revert NotMarked();
        userData.isFeeAddress = false;
        emit FeeAddressRemoved(addr);
    }

    function setSurgeFeeThreshold(uint256 newThreshold) external onlyOwner {
        surgeFeeThreshold = newThreshold;
    }

    function setMinSwapAmount(uint256 newMinAmount) external onlyOwner {
        minSwapAmount = newMinAmount;
    }

    function registerPoolTokens(bytes32 poolId, address _token0, address _token1) external onlyOwner {
        if (_token0 == address(0) || _token1 == address(0)) revert ZeroAddress();
        poolToken0[poolId] = _token0;
        poolToken1[poolId] = _token1;
        emit PoolTokensRegistered(poolId, _token0, _token1);
    }

    function registerOwner(address user, address ownerAddr) external onlyOwner {
        if (user == address(0) || ownerAddr == address(0)) revert ZeroAddress();
        addressOwner[user] = ownerAddr;
    }

    // -------------------------------- Hook Permissions ---------------------------------------
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

    // -------------------------------- Internal Helper: _recordSwap --------------------------------
    /**
     * @notice Records a swap entry in the per-user circular buffer.
     * @param user The user address.
     * @param newSwap The swap entry.
     * @dev Gas Benchmarking Note: In our local testing, this operation averaged ~145k gas per swap.
     */
    function _recordSwap(address user, SwapEntry memory newSwap) internal {
        SwapHistory storage history = _swapHistories[user];
        history.swaps[history.nextIndex % MAX_HISTORY_LENGTH] = newSwap;
        history.nextIndex++;
    }

    // -------------------------------- Internal Hooks -----------------------------------------
    function _beforeSwap(
        address recipient,
        PoolKey calldata poolKey,
        IPoolManager.SwapParams calldata swapParams,
        bytes calldata
    )
        internal
        override
        returns (bytes4 selector, BeforeSwapDelta delta, uint24 feeBasisPoints)
    {
        if (recipient == address(0)) revert ZeroAddress();

        // Enforce minimum swap amount
        uint256 absAmount = swapParams.amountSpecified >= 0
            ? uint256(swapParams.amountSpecified)
            : uint256(-swapParams.amountSpecified);
        if (absAmount < minSwapAmount) revert SwapAmountTooLow();

        // 1) Calculate fee and optionally accrue extra fees
        feeBasisPoints = _calculateFeeAndAccrue(recipient, poolKey, swapParams, absAmount);

        // 2) Surge cooldown check
        UserData storage cachedUser = _userData[recipient];
        if (_shouldTriggerSurgeCooldown(feeBasisPoints, feeMin)) {
            if (block.timestamp >= (cachedUser.lastActivityTimestamp + cooldownSeconds)) {
                cachedUser.lastActivityTimestamp = uint64(block.timestamp);
            }
        }

        emit ActivityRecorded(recipient);

        // 3) Record swap
        bool isBuy = swapParams.amountSpecified >= 0;
        _recordSwap(recipient, SwapEntry({
            blockNumber: uint32(block.number),
            direction: isBuy,
            amount: absAmount
        }));

        selector = BaseHook.beforeSwap.selector;
        delta    = BeforeSwapDeltaLibrary.ZERO_DELTA;
    }

    // -------------------------------- Refactored Sub-Logic ------------------------------------
    /**
     * @notice Computes the final fee (time + impact) and optionally applies the TWAP-based null fee if a sandwich is detected.
     *         Also accrues the extra portion of the fee (above feeMin) to the pool.
     */
    function _calculateFeeAndAccrue(
        address recipient,
        PoolKey calldata poolKey,
        IPoolManager.SwapParams calldata swapParams,
        uint256 absAmount
    )
        private
        returns (uint24 feeBasisPoints)
    {
        UserData storage cachedUser = _userData[recipient];
        uint256 timeFee   = _calculateTimeFee(cachedUser);
        uint256 impactFee = _calculateImpactFee(poolKey, swapParams, timeFee);

        uint256 baseFee = timeFee > impactFee ? timeFee : impactFee;
        feeBasisPoints = baseFee == 0 ? 1 : uint24(baseFee);

        bool isSandwich = _detectSandwichOrMultiAddress(recipient, swapParams.amountSpecified >= 0);
        if (isSandwich) {
            address poolAddr = _getPoolAddress(poolKey);
            int24 currentTick = _getCurrentTick(poolAddr);
            feeBasisPoints = _computeNullFeeBPS(poolAddr, currentTick);
        }

        if (feeBasisPoints > feeMin) {
            uint256 extraFeeBPS = feeBasisPoints - feeMin;
            uint256 extraFeeAmount = (absAmount * extraFeeBPS) / _FEE_DENOMINATOR;
            // Inline poolId computation to reduce stack variables
            bytes32 part1 = keccak256(abi.encode(poolKey.currency0, poolKey.currency1));
            bytes32 poolId = keccak256(abi.encode(part1, poolKey.fee, poolKey.tickSpacing, poolKey.hooks));

            if (swapParams.amountSpecified < 0) {
                _accrueFees(poolId, uint128(extraFeeAmount), 0);
            } else {
                _accrueFees(poolId, 0, uint128(extraFeeAmount));
            }
        }
    }

    // -------------------------------- Time & Impact Fees --------------------------------------
    function _calculateTimeFee(UserData storage cachedUser) private view returns (uint256 fee) {
        uint256 lastActivityTimestamp = cachedUser.lastActivityTimestamp;
        if (lastActivityTimestamp == 0) {
            return feeMin;
        }
        if (cachedUser.isFeeAddress) {
            return feeMax;
        }
        uint256 elapsed = block.timestamp - lastActivityTimestamp;
        if (elapsed >= cooldownSeconds) {
            return feeMin;
        } else {
            UD60x18 ratio = UD60x18.wrap((elapsed * 1e36) / cooldownSeconds);
            uint256 reversedFactor = 1e18 - ratio.sqrt().unwrap();
            fee = feeMin + (((feeMax - feeMin) * reversedFactor) / 1e18);
        }
    }

    function _calculateImpactFee(
        PoolKey calldata poolKey,
        IPoolManager.SwapParams calldata swapParams,
        uint256 timeFee
    )
        private
        view
        returns (uint256 impactFee)
    {
        if (swapParams.amountSpecified >= 0) {
            return timeFee;
        }
        uint256 absAmount = uint256(-swapParams.amountSpecified);
        uint128 liquidity = _getPoolLiquidity(poolKey);
        if (liquidity == 0) revert NoLiquidity();

        uint256 impactBps = (absAmount * _FEE_DENOMINATOR) / liquidity;
        if (impactBps <= 500) {
            return timeFee;
        }
        uint256 adjustedImpact = impactBps > 10000 ? 9500 : (impactBps - 500);
        uint256 feeRange = _MALICIOUS_FEE_MAX - feeMin;
        UD60x18 normalizedImpact = UD60x18.wrap((adjustedImpact * 1e36) / 9500);
        uint256 sqrtImpact = normalizedImpact.sqrt().unwrap();
        impactFee = feeMin + ((feeRange * sqrtImpact) / 1e18);
        if (impactFee >= _MALICIOUS_FEE_MAX) {
            impactFee = _MALICIOUS_FEE_MAX;
        }
    }

    // -------------------------------- Sandwich & Multi-Address Checks ------------------------
    function _detectSandwichOrMultiAddress(address user, bool isBuy) private view returns (bool) {
        SwapHistory storage history = _swapHistories[user];
        bool multiAddrAttack = isMultiAddressAttack(user);
        if (history.nextIndex == 0) {
            return (multiAddrAttack || _userData[user].isFeeAddress);
        }
        uint32 lastIdx = (history.nextIndex - 1) % MAX_HISTORY_LENGTH;
        SwapEntry memory lastSwap = history.swaps[lastIdx];
        bool isSingleBlockSandwich = (block.number == lastSwap.blockNumber && lastSwap.direction != isBuy);
        bool isMultiBlockSandwich = (
            block.number > lastSwap.blockNumber &&
            block.number <= (lastSwap.blockNumber + MULTI_BLOCK_SANDWICH_WINDOW) &&
            lastSwap.direction != isBuy
        );
        return (multiAddrAttack || _userData[user].isFeeAddress || isSingleBlockSandwich || isMultiBlockSandwich);
    }

    function isMultiAddressAttack(address user) private view returns (bool) {
        address ownerAddr = addressOwner[user];
        return (ownerAddr != address(0) && ownerAddr != user);
    }

    // -------------------------------- Hook Utility -------------------------------------------
    function _getPoolLiquidity(PoolKey calldata poolKey) private view returns (uint128 liquidity) {
        address poolAddr = _getPoolAddress(poolKey);
        liquidity = IUniswapV4Pool(poolAddr).liquidity();
    }

    function _getPoolAddress(PoolKey calldata poolKey) private view returns (address poolAddr) {
        bytes32 part1 = keccak256(abi.encode(poolKey.currency0, poolKey.currency1));
        bytes32 poolId = keccak256(abi.encode(part1, poolKey.fee, poolKey.tickSpacing, poolKey.hooks));
        poolAddr = IPoolManagerExtended(address(poolManager)).pools(poolId);
    }

    function _computeNullFeeBPS(address poolAddr, int24 currentTick) private view returns (uint24 nullFee) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 60;
        secondsAgos[1] = 0;
        (int56[] memory tickCumulatives, ) = IUniswapV4PoolExtended(poolAddr).observe(secondsAgos);
        int24 twapTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 60);
        uint256 priceNow  = _tickToPrice(currentTick);
        uint256 priceTWAP = _tickToPrice(twapTick);
        if (priceTWAP == 0 || priceNow <= priceTWAP) {
            return 0;
        }
        uint256 diff   = priceNow - priceTWAP;
        uint256 feeBPS = (diff * 10000) / priceTWAP;
        if (feeBPS > _NULL_FEE_CAP) feeBPS = _NULL_FEE_CAP;
        nullFee = uint24(feeBPS);
    }

    function _tickToPrice(int24 tick) private pure returns (uint256 priceX96) {
        uint160 sqrtPriceX96 = TickMath.getSqrtPriceAtTick(tick);
        priceX96 = FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, 1 << 192);
    }

    function _getCurrentTick(address poolAddr) private view returns (int24 currentTick) {
        ( , currentTick, , , , , ) = IUniswapV4PoolState(poolAddr).slot0();
    }

    function _shouldTriggerSurgeCooldown(uint256 dynamicFee, uint256 baseFee) private view returns (bool) {
        return (dynamicFee > baseFee) && ((dynamicFee - baseFee) >= surgeFeeThreshold);
    }

    // -------------------------------- Liquidity Hooks ----------------------------------------
    function _beforeAddLiquidity(
        address user,
        PoolKey calldata poolKey,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata data
    ) internal virtual override returns (bytes4 selector) {
        if (user == address(0)) revert ZeroAddress();
        UserData storage cachedUser = _userData[user];
        uint256 effectiveCooldown = cachedUser.isFeeAddress ? _MAX_COOLDOWN_SECONDS : cooldownSeconds;
        if (block.timestamp <= (cachedUser.lastActivityTimestamp + effectiveCooldown)) {
            revert CooldownActive();
        }
        cachedUser.lastActivityTimestamp = uint64(block.timestamp);
        emit LiquidityAdded(user, poolKey, params, data);
        selector = BaseHook.beforeAddLiquidity.selector;
    }

    function _beforeRemoveLiquidity(
        address user,
        PoolKey calldata poolKey,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata data
    ) internal virtual override returns (bytes4 selector) {
        if (user == address(0)) revert ZeroAddress();
        UserData storage cachedUser = _userData[user];
        uint256 effectiveCooldown = cachedUser.isFeeAddress ? _MAX_COOLDOWN_SECONDS : cooldownSeconds;
        if (block.timestamp <= (cachedUser.lastActivityTimestamp + effectiveCooldown)) {
            revert CooldownActive();
        }
        cachedUser.lastActivityTimestamp = uint64(block.timestamp);
        emit LiquidityRemoved(user, poolKey, params, data);
        selector = BaseHook.beforeRemoveLiquidity.selector;
    }

    // -------------------------------- Fee Accrual & Distribution ------------------------------
    function _accrueFees(
        bytes32 poolId,
        uint128 token0Amount,
        uint128 token1Amount
    ) internal {
        poolFees[poolId].token0Fees += token0Amount;
        poolFees[poolId].token1Fees += token1Amount;
    }

    function distributeFees(
        bytes32 poolId,
        address[] calldata lpAddresses,
        uint256[] calldata lpShares
    ) external onlyOwner {
        require(lpAddresses.length == lpShares.length, "Mismatched arrays");
        PoolFees storage fees = poolFees[poolId];
        uint256 totalShares;
        for (uint256 i = 0; i < lpShares.length; i++) {
            totalShares += lpShares[i];
        }
        address t0 = poolToken0[poolId];
        address t1 = poolToken1[poolId];
        if (t0 == address(0) || t1 == address(0)) revert ZeroAddress();
        uint256 totalToken0Fees = fees.token0Fees;
        uint256 totalToken1Fees = fees.token1Fees;
        IERC20 token0 = IERC20(t0);
        IERC20 token1 = IERC20(t1);
        require(token0.balanceOf(address(this)) >= totalToken0Fees, "Insufficient token0 balance");
        require(token1.balanceOf(address(this)) >= totalToken1Fees, "Insufficient token1 balance");
        for (uint256 i = 0; i < lpAddresses.length; i++) {
            uint256 amount0 = (totalToken0Fees * lpShares[i]) / totalShares;
            uint256 amount1 = (totalToken1Fees * lpShares[i]) / totalShares;
            token0.safeTransfer(lpAddresses[i], amount0);
            token1.safeTransfer(lpAddresses[i], amount1);
        }
        fees.token0Fees = 0;
        fees.token1Fees = 0;
    }

    // -------------------------------- Emergency ----------------------------------------------
    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        IERC20(token).safeTransfer(owner(), amount);
        emit EmergencyWithdrawal(token, amount);
    }
}
