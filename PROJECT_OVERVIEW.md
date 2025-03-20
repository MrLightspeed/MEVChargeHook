# MEVChargeHook: Project Overview

The latest iteration of the **MEVChargeHook** introduces significant enhancements focused on fairness, security, and clearly defined operational guidelines. This V4 Liquidity Pool Hook specifically targets harmful behaviors typical of MEV (Maximal Extractable Value) and arbitrage trading, such as executing rapid trades with high price impacts.

By employing dynamic fee structures, the hook effectively protects regular traders and incentivizes stable market practices. Trading bots may continue market-balancing activities; however, under the MEVChargeHook structure, they pay a premium that directly benefits liquidity providers.

## Overview of Fee Mechanisms

The MEVChargeHook implements two distinct fee structures designed to mitigate harmful trading behaviors:

- **Cooldown-Based Fees:** Discourage rapid sequential trades (e.g., sandwich and just-in-time liquidity attacks).
- **Impact-Based Fees:** Penalize large price swings to stabilize markets and protect liquidity providers.

## Cooldown-Based Fee Adjustments

Cooldown-based fees quickly decrease over time, starting high (5%) immediately after a trade and gradually dropping to a standard low rate (1%) using reversed square-root decay. This ensures regular traders who wait even briefly between trades pay standard liquidity pool fees, while rapid traders face higher fees.

### Cooldown intervals:
- **Normal Operation:** 12 seconds (~1 Ethereum L1 block)
- **Token Launch Scenario:** 600 seconds (provides extra protection during new token launches)

### Cooldown Fee Calculation Formula:

Cooldown Fee = Fee_min + (Fee_max - Fee_min) × (1 - √(Elapsed Time / Cooldown Duration))

### Definitions:
- **Fee_max:** Initial maximum fee immediately after a trade (5%)
- **Fee_min:** Minimum fee after cooldown (1%)
- **Elapsed Time:** Time since the user's previous trade
- **Cooldown Duration:** Duration of cooldown interval (12 to 600 seconds); can be disabled with 0

**Example:**  
If you immediately trade again after your previous swap, your fee is the full 5%. Waiting even half the cooldown duration significantly reduces the fee, incentivizing patience.

## Impact-Based Fee Adjustments

Impact-based fees apply when trades cause significant price movements (currently defined as exceeding around 5% slippage). Larger price impacts trigger higher fees, reaching up to a 25% maximum penalty for trades causing drastic price reductions.

### Impact Fee Calculation Formula:

Impact Fee = Fee_min + (Fee_malicious_max - Fee_min) × √((Impact_BPS - Impact_Threshold) / (Impact_BPS_Max - Impact_Threshold))

### Definitions:
- **Fee_malicious_max:** Maximum penalty fee (25%)
- **Impact_BPS:** Size of price impact measured in basis points
- **Impact_Threshold:** Threshold defining harmful price impact (~5%)
- **Impact_BPS_Max:** Maximum possible price impact (100%)

**Example:**  
If a single trade significantly reduces a token’s price beyond the 5% slippage threshold, the trader pays a progressively larger fee, with severe impacts (e.g., a 100% collapse) incurring the maximum 25% penalty.

## Security Enhancements & Liquidity Provider Benefits

- All fees collected go directly to the liquidity pool, incentivizing providers and protecting their investments from impermanent loss.
- Addresses identified as harmful (such as arbitrage or MEV bots) always incur maximum fees.
- Fee caps are permanently coded to ensure transparency and security.

## Options for Liquidity Providers

Liquidity providers directly benefit from the collected fees, enhancing returns and offsetting risks. Providers have several options:

- **Direct Collection:** Fees can be withdrawn directly.
- **Reinvestment:** Providers may automatically reinvest collected fees, increasing their pool share.

If providers don't explicitly collect fees, the fees remain in the liquidity pool, compounding their positions.

## Open Considerations

The exact slippage threshold for "normal" vs. "harmful" trades remains under review, ensuring alignment with market practices. Currently set at 5%, it may be adjusted following analysis.

This update transparently explains how MEVChargeHook fees protect users, incentivize liquidity provision, and enhance market stability.