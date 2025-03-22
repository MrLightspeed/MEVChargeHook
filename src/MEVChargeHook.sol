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
    function slot0()
        external
        view
        returns (
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
 * @notice Implements dynamic fee escalation with TWAP-based null fee, direct fee transfers to pools,
 *         per-user circular buffer swap tracking, multi-address detection, configurable surge fee threshold,
 *         minimum swap validation, and emergency withdrawal.
 *
 * @dev Key features and changes:
 *      1) Fees collected in swaps are immediately sent back to the pool (Uniswap V4 standard).
 *      2) New events (OwnerRegistered, SwapRecorded, FeesAccrued) are emitted for off-chain tracking.
 *      3) Frequently used storage variables are cached and storage references are used where beneficial.
 *      4) Extra zero-address validations and ternary refactoring are applied.
 *      5) Some strict inequalities are replaced with non-strict ones to save gas.
 */
contract MEVChargeHook is BaseHook, Ownable {
    using SafeERC20 for IERC20;

    // ----------------------------- Constants ----------------------------------------------
    uint256 private constant _MAX_COOLDOWN_SECONDS = 600;
    uint256 private constant _MALICIOUS_FEE_MAX = 2500; // 25%
    uint256 private constant _FEE_DENOMINATOR = 10000;
    uint256 private constant _NULL_FEE_CAP = 1000; // 10% in basis points
    uint256 private constant _MULTI_BLOCK_SANDWICH_WINDOW = 5; // in blocks

    // ----------------------------- Configurable Params -------------------------------------
    uint256 public cooldownSeconds = 12;
    uint256 public feeMin = 100; // 1%
    uint256 public feeMax = 500; // 5%
    uint256 public minSwapAmount = 1e6;
    uint256 public surgeFeeThreshold = 1000; // 10%

    // ----------------------------- Fee Bookkeeping -----------------------------------------
    struct PoolFees {
        uint128 token0Fees;
        uint128 token1Fees;
    }
    // Maps poolId => total accrued fees (bookkeeping only)

    mapping(bytes32 poolId => PoolFees fees) public poolFees;

    // Mapping of poolId => token0, poolId => token1
    mapping(bytes32 poolId => address token0) public poolToken0;
    mapping(bytes32 poolId => address token1) public poolToken1;

    // ----------------------------- Swap Tracking ------------------------------------------
    uint32 constant MAX_HISTORY_LENGTH = 256;

    struct SwapEntry {
        uint32 blockNumber;
        bool direction; // true if buy; false if sell
        uint256 amount;
    }

    struct SwapHistory {
        SwapEntry[MAX_HISTORY_LENGTH] swaps;
        uint32 nextIndex;
    }
    // user => SwapHistory

    mapping(address user => SwapHistory history) private _swapHistories;

    // ----------------------------- User Data ---------------------------------------------
    struct UserData {
        uint64 lastActivityTimestamp;
        bool isFeeAddress;
    }

    mapping(address userAddress => UserData userData) public _userData;

    // ----------------------------- Multi-Address Detection --------------------------------
    // userAddress => ownerAddress
    mapping(address userAddress => address ownerAddress) public addressOwner;

    // ----------------------------- Events -------------------------------------------------
    event ActivityRecorded(address indexed user);
    event CooldownSecondsUpdated(address indexed owner, uint256 newCooldownSeconds);
    event FeeRangeUpdated(uint256 indexed newFeeMin, uint256 indexed newFeeMax);
    event FeeAddressAdded(address indexed addr);
    event FeeAddressRemoved(address indexed addr);
    event PoolTokensRegistered(bytes32 indexed poolId, address token0, address token1);
    event EmergencyWithdrawal(address indexed token, uint256 amount);
    event SurgeFeeThresholdUpdated(address indexed owner, uint256 newThreshold);
    event MinSwapAmountUpdated(address indexed owner, uint256 newMinAmount);
    event FeesTransferred(bytes32 indexed poolId, address indexed pool, uint128 token0Amount, uint128 token1Amount);
    event OwnerRegistered(address indexed user, address indexed ownerAddr);
    event SwapRecorded(address indexed user, SwapEntry newSwap);
    event FeesAccrued(bytes32 indexed poolId, uint128 token0Amount, uint128 token1Amount);

    // ----------------------------- Errors -------------------------------------------------
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

    // ----------------------------- Constructor --------------------------------------------
    constructor(IPoolManager _poolManager, address _owner) BaseHook(_poolManager) Ownable(_owner) {
        if (address(_poolManager) == address(0)) revert InvalidPoolManagerAddress();
        if (_owner == address(0)) revert ZeroAddress();
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    // ----------------------------- Admin Functions ----------------------------------------
    function setCooldownSeconds(uint256 newCooldownSeconds) external onlyOwner {
        if (newCooldownSeconds >= _MAX_COOLDOWN_SECONDS) revert CooldownTooHigh();
        if (newCooldownSeconds == cooldownSeconds) return;
        cooldownSeconds = newCooldownSeconds;
        emit CooldownSecondsUpdated(msg.sender, newCooldownSeconds);
    }

    function setFeeRange(uint256 newFeeMin, uint256 newFeeMax) external onlyOwner {
        if (!(newFeeMin <= newFeeMax)) revert FeeMinNotLessThanFeeMax();
        if (newFeeMax >= 501) revert FeeMaxTooHigh();
        bool changed;
        if (feeMin != newFeeMin) {
            feeMin = newFeeMin;
            changed = true;
        }
        if (feeMax != newFeeMax) {
            feeMax = newFeeMax;
            changed = true;
        }
        if (changed) {
            emit FeeRangeUpdated(newFeeMin, newFeeMax);
        }
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
        UserData storage userDataRef = _userData[addr];
        if (!userDataRef.isFeeAddress) revert NotMarked();
        userDataRef.isFeeAddress = false;
        emit FeeAddressRemoved(addr);
    }

    function setSurgeFeeThreshold(uint256 newThreshold) external onlyOwner {
        if (newThreshold == surgeFeeThreshold) return;
        surgeFeeThreshold = newThreshold;
        emit SurgeFeeThresholdUpdated(msg.sender, newThreshold);
    }

    function setMinSwapAmount(uint256 newMinAmount) external onlyOwner {
        if (newMinAmount == minSwapAmount) return;
        minSwapAmount = newMinAmount;
        emit MinSwapAmountUpdated(msg.sender, newMinAmount);
    }

    function registerPoolTokens(bytes32 poolId, address _token0, address _token1) external onlyOwner {
        require(_token0 != address(0), "Token0 is the zero address");
        require(_token1 != address(0), "Token1 is the zero address");
        poolToken0[poolId] = _token0;
        poolToken1[poolId] = _token1;
        emit PoolTokensRegistered(poolId, _token0, _token1);
    }

    function registerOwner(address user, address ownerAddr) external onlyOwner {
        require(user != address(0), "User address cannot be zero");
        require(ownerAddr != address(0), "Owner address cannot be zero");
        addressOwner[user] = ownerAddr;
        emit OwnerRegistered(user, ownerAddr);
    }

    // ----------------------------- Hook Permissions ---------------------------------------
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

    // ----------------------------- Internal Helper Functions ------------------------------
    function _recordSwap(address user, SwapEntry memory newSwap) internal {
        if (user == address(0)) revert ZeroAddress();
        SwapHistory storage history = _swapHistories[user];
        uint32 idx = history.nextIndex % MAX_HISTORY_LENGTH;
        history.swaps[idx] = newSwap;
        history.nextIndex++;
        emit SwapRecorded(user, newSwap);
    }

    function _computePoolId(PoolKey calldata poolKey) internal pure returns (bytes32 poolId) {
        bytes32 part1 = keccak256(abi.encode(poolKey.currency0, poolKey.currency1));
        poolId = keccak256(abi.encode(part1, poolKey.fee, poolKey.tickSpacing, poolKey.hooks));
    }

    function _transferFees(bytes32 poolId, uint128 token0Amount, uint128 token1Amount, address poolAddr) internal {
        if (token0Amount != 0) {
            IERC20(poolToken0[poolId]).safeTransfer(poolAddr, token0Amount);
        }
        if (token1Amount != 0) {
            IERC20(poolToken1[poolId]).safeTransfer(poolAddr, token1Amount);
        }
        emit FeesTransferred(poolId, poolAddr, token0Amount, token1Amount);
    }

    // ----------------------------- Internal Hooks -----------------------------------------
    function _beforeSwap(
        address recipient,
        PoolKey calldata poolKey,
        IPoolManager.SwapParams calldata swapParams,
        bytes calldata
    ) internal override returns (bytes4 selector, BeforeSwapDelta delta, uint24 feeBasisPoints) {
        if (recipient == address(0)) revert ZeroAddress();

        // Cache frequently used storage variables
        uint256 _minSwapAmount = minSwapAmount;
        uint256 _feeMin = feeMin;
        uint256 _cooldownSeconds = cooldownSeconds;

        int256 amtSpecified = swapParams.amountSpecified;
        uint256 absAmount = amtSpecified >= 0 ? uint256(amtSpecified) : uint256(-amtSpecified);
        if (absAmount <= _minSwapAmount) revert SwapAmountTooLow();

        feeBasisPoints = _calculateFeeAndAccrue(recipient, poolKey, swapParams, absAmount);

        UserData storage cachedUser = _userData[recipient];
        if (_shouldTriggerSurgeCooldown(feeBasisPoints, _feeMin)) {
            if (block.timestamp >= (cachedUser.lastActivityTimestamp + _cooldownSeconds)) {
                cachedUser.lastActivityTimestamp = uint64(block.timestamp);
            }
        }
        emit ActivityRecorded(recipient);

        bool isBuy = (amtSpecified >= 0);
        _recordSwap(recipient, SwapEntry({blockNumber: uint32(block.number), direction: isBuy, amount: absAmount}));

        selector = BaseHook.beforeSwap.selector;
        delta = BeforeSwapDeltaLibrary.ZERO_DELTA;
    }

    function _calculateFeeAndAccrue(
        address recipient,
        PoolKey calldata poolKey,
        IPoolManager.SwapParams calldata swapParams,
        uint256 absAmount
    ) private returns (uint24 feeBasisPoints) {
        // Cache frequently used storage variables
        uint256 _feeMin = feeMin;
        uint256 _feeMax = feeMax;

        uint256 timeFee = _calculateTimeFee(_userData[recipient], _feeMin, _feeMax);
        uint256 impactFee = _calculateImpactFee(poolKey, swapParams, timeFee, _feeMin);
        uint256 baseFee = timeFee > impactFee ? timeFee : impactFee;
        feeBasisPoints = baseFee == 0 ? 1 : uint24(baseFee);

        bool isSandwich = _detectSandwichOrMultiAddress(recipient, (swapParams.amountSpecified >= 0));
        if (isSandwich) {
            address poolAddrSand = _getPoolAddress(poolKey);
            int24 currentTick = _getCurrentTick(poolAddrSand);
            feeBasisPoints = _computeNullFeeBPS(poolAddrSand, currentTick);
        }

        if (feeBasisPoints > _feeMin) {
            uint256 extraFeeBPS = feeBasisPoints - _feeMin;
            uint256 extraFeeAmount = (absAmount * extraFeeBPS) / _FEE_DENOMINATOR;
            bytes32 poolId = _computePoolId(poolKey);
            address poolAddr = _getPoolAddress(poolKey);
            int256 _amtSpecified = swapParams.amountSpecified; // cached for stack efficiency
            _transferFees(
                poolId,
                _amtSpecified < 0 ? uint128(extraFeeAmount) : 0,
                _amtSpecified < 0 ? 0 : uint128(extraFeeAmount),
                poolAddr
            );
            _accrueFees(
                poolId, _amtSpecified < 0 ? uint128(extraFeeAmount) : 0, _amtSpecified < 0 ? 0 : uint128(extraFeeAmount)
            );
            emit FeesAccrued(
                poolId,
                _amtSpecified < 0 ? uint128(extraFeeAmount) : 0,
                _amtSpecified < 0 ? uint128(0) : uint128(extraFeeAmount)
            );
        }
    }

    function _calculateTimeFee(UserData storage cachedUser, uint256 _feeMin, uint256 _feeMax)
        private
        view
        returns (uint256 fee)
    {
        uint256 lastActivity = cachedUser.lastActivityTimestamp;
        if (lastActivity == 0) {
            return _feeMin;
        }
        if (cachedUser.isFeeAddress) {
            return _feeMax;
        }
        uint256 elapsed = block.timestamp - lastActivity;
        uint256 _cooldownSeconds = cooldownSeconds;
        if (elapsed >= _cooldownSeconds) {
            return _feeMin;
        } else {
            UD60x18 ratio = UD60x18.wrap((elapsed * 1e36) / _cooldownSeconds);
            uint256 reversedFactor = 1e18 - ratio.sqrt().unwrap();
            fee = _feeMin + (((_feeMax - _feeMin) * reversedFactor) / 1e18);
        }
    }

    function _calculateImpactFee(
        PoolKey calldata poolKey,
        IPoolManager.SwapParams calldata swapParams,
        uint256 timeFee,
        uint256 _feeMin
    ) private view returns (uint256 impactFee) {
        if (swapParams.amountSpecified >= 0) {
            return timeFee;
        }
        int256 specified = swapParams.amountSpecified;
        uint256 absAmount = uint256(-specified);
        uint128 liquidity = _getPoolLiquidity(poolKey);
        if (liquidity == 0) revert NoLiquidity();

        uint256 impactBps = (absAmount * _FEE_DENOMINATOR) / liquidity;
        if (impactBps <= 500) {
            return timeFee;
        }
        uint256 adjustedImpact = impactBps > 10000 ? 9500 : (impactBps - 500);
        uint256 feeRange = _MALICIOUS_FEE_MAX - _feeMin;
        UD60x18 normalizedImpact = UD60x18.wrap((adjustedImpact * 1e36) / 9500);
        uint256 sqrtImpact = normalizedImpact.sqrt().unwrap();

        impactFee = _feeMin + ((feeRange * sqrtImpact) / 1e18);
        if (impactFee >= _MALICIOUS_FEE_MAX) {
            impactFee = _MALICIOUS_FEE_MAX;
        }
    }

    function _detectSandwichOrMultiAddress(address user, bool isBuy) private view returns (bool) {
        bool multiAddrAttack = _isMultiAddressAttack(user);
        if (_swapHistories[user].nextIndex == 0) {
            return (multiAddrAttack || _userData[user].isFeeAddress);
        }
        uint32 lastIdx = (_swapHistories[user].nextIndex - 1) % MAX_HISTORY_LENGTH;
        // Use storage reference to access last swap efficiently.
        SwapEntry storage lastSwap = _swapHistories[user].swaps[lastIdx];
        bool isSingleBlockSandwich = (block.number == lastSwap.blockNumber && lastSwap.direction != isBuy);
        bool isMultiBlockSandwich = (
            block.number > lastSwap.blockNumber && block.number <= (lastSwap.blockNumber + _MULTI_BLOCK_SANDWICH_WINDOW)
                && lastSwap.direction != isBuy
        );
        return (multiAddrAttack || _userData[user].isFeeAddress || isSingleBlockSandwich || isMultiBlockSandwich);
    }

    function _isMultiAddressAttack(address user) private view returns (bool) {
        address _ownerAddr = addressOwner[user];
        return (_ownerAddr != address(0) && _ownerAddr != user);
    }

    function _getPoolLiquidity(PoolKey calldata poolKey) private view returns (uint128 liquidity) {
        address poolAddr = _getPoolAddress(poolKey);
        liquidity = IUniswapV4Pool(poolAddr).liquidity();
    }

    function _getPoolAddress(PoolKey calldata poolKey) private view returns (address poolAddr) {
        bytes32 poolId = _computePoolId(poolKey);
        poolAddr = IPoolManagerExtended(address(poolManager)).pools(poolId);
    }

    function _computeNullFeeBPS(address poolAddr, int24 currentTick) private view returns (uint24 nullFee) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 60; // 60-second TWAP; second element defaults to 0
        (int56[] memory tickCumulatives,) = IUniswapV4PoolExtended(poolAddr).observe(secondsAgos);
        int24 twapTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 60);

        uint256 priceNow = _tickToPrice(currentTick);
        uint256 priceTWAP = _tickToPrice(twapTick);
        if (priceTWAP == 0 || priceNow <= priceTWAP) {
            return 0;
        }
        uint256 diff = priceNow - priceTWAP;
        uint256 feeBPS = (diff * 10000) / priceTWAP;
        if (feeBPS >= _NULL_FEE_CAP + 1) feeBPS = _NULL_FEE_CAP;
        nullFee = uint24(feeBPS);
    }

    function _tickToPrice(int24 tick) private pure returns (uint256 priceX96) {
        uint160 sqrtPriceX96 = TickMath.getSqrtPriceAtTick(tick);
        priceX96 = FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, 1 << 192);
    }

    function _getCurrentTick(address poolAddr) private view returns (int24 currentTick) {
        (, currentTick,,,,,) = IUniswapV4PoolState(poolAddr).slot0();
    }

    function _shouldTriggerSurgeCooldown(uint256 dynamicFee, uint256 baseFee) private view returns (bool) {
        return (dynamicFee > baseFee) && ((dynamicFee - baseFee) >= surgeFeeThreshold);
    }

    // ----------------------------- Liquidity Hooks ----------------------------------------
    function _beforeAddLiquidity(
        address user,
        PoolKey calldata poolKey,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata data
    ) internal virtual override returns (bytes4 selector) {
        if (user == address(0)) revert ZeroAddress();
        uint256 _cooldownSeconds = cooldownSeconds;
        UserData storage cachedUser = _userData[user];
        uint256 effectiveCooldown = cachedUser.isFeeAddress ? _MAX_COOLDOWN_SECONDS : _cooldownSeconds;
        if (block.timestamp <= (cachedUser.lastActivityTimestamp + effectiveCooldown)) {
            revert CooldownActive();
        }
        cachedUser.lastActivityTimestamp = uint64(block.timestamp);
        emit LiquidityAdded(user, poolKey, params, data);
        selector = BaseHook.beforeAddLiquidity.selector;
    }

    event LiquidityAdded(address indexed user, PoolKey poolKey, IPoolManager.ModifyLiquidityParams params, bytes data);

    function _beforeRemoveLiquidity(
        address user,
        PoolKey calldata poolKey,
        IPoolManager.ModifyLiquidityParams calldata params,
        bytes calldata data
    ) internal virtual override returns (bytes4 selector) {
        if (user == address(0)) revert ZeroAddress();
        uint256 _cooldownSeconds = cooldownSeconds;
        UserData storage cachedUser = _userData[user];
        uint256 effectiveCooldown = cachedUser.isFeeAddress ? _MAX_COOLDOWN_SECONDS : _cooldownSeconds;
        if (block.timestamp <= (cachedUser.lastActivityTimestamp + effectiveCooldown)) {
            revert CooldownActive();
        }
        cachedUser.lastActivityTimestamp = uint64(block.timestamp);
        emit LiquidityRemoved(user, poolKey, params, data);
        selector = BaseHook.beforeRemoveLiquidity.selector;
    }

    event LiquidityRemoved(
        address indexed user, PoolKey poolKey, IPoolManager.ModifyLiquidityParams params, bytes data
    );

    // ----------------------------- Fee Accrual & Emergency --------------------------------
    function _accrueFees(bytes32 poolId, uint128 token0Amount, uint128 token1Amount) internal {
        PoolFees storage fees = poolFees[poolId];
        fees.token0Fees += token0Amount;
        fees.token1Fees += token1Amount;
        emit FeesAccrued(poolId, token0Amount, token1Amount);
    }

    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        IERC20(token).safeTransfer(owner(), amount);
        emit EmergencyWithdrawal(token, amount);
    }
}
