# Autonomous Whistleblower Protection Vault (AWPV)
> **Decentralized Corporate Governance & DAO Malfeasance Whistleblower Escrow with Multi-Validator Dossier Adjudication on GenLayer**

[![GenLayer Intelligent Contracts](https://img.shields.io/badge/GenLayer-Intelligent%20Contract%20v0.2.1-blue.svg)](https://genlayer.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Security Hardened](https://img.shields.io/badge/Steward%20Audited-15--Phase%20Verified-brightgreen.svg)](test/test_autonomous_whistleblower_vault.py)
[![Account: tumhi4](https://img.shields.io/badge/GitHub-tumhi4-orange.svg)](https://github.com/tumhi4)

The **Autonomous Whistleblower Protection Vault** is an immutable, sovereign governance primitive engineered to resolve the catastrophic incentive misalignment in corporate and DAO whistleblowing: internal whistleblowers fearing career destruction, blacklisting, or leaked identities, and organizations fearing frivolous extortion or unverified smear campaigns.

---

## 1. Verified GenLayer Studio Testnet Deployment

| Parameter | On-Chain Value |
| :--- | :--- |
| **Protocol Name** | `AutonomousWhistleblowerProtectionVault` |
| **Contract Address** | [`0xc07209282b2110aBFc00883C372b24a94675C656`](https://explorer-studio.genlayer.com/address/0xc07209282b2110aBFc00883C372b24a94675C656) |
| **Deployment Transaction** | `0x0deee642685757d9da1004f28fdd3742a8ef6123362ae5740e829a14852d0e9c` |
| **Receipt Status** | `7` (`FINALIZED`) |
| **Studio RPC** | `https://studio.genlayer.com/api` |
| **Target Repository** | [https://github.com/tumhi4/autonomous-whistleblower-protection-vault](https://github.com/tumhi4/autonomous-whistleblower-protection-vault) |
| **Genesis Escrow Obligation** | `0` Wei (100% Backed, Zero Unbacked Genesis Liabilities) |

---

## 2. System Architecture & Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Sponsor as DAO / Corporate Treasury
    actor Whistleblower as Anonymous Informant
    participant Vault as Whistleblower Vault (GenVM)
    participant Consensus as GenLayer Multi-Validator Network

    Sponsor->>Vault: create_whistleblower_pool(org_name) [@gl.public.write.payable]
    Note over Vault: Native GEN locked in bounty escrow. Zero unbacked debt.
    
    Whistleblower->>Vault: submit_whistleblower_report(pool_id, category, dossier_url, requested_bps, nonce)
    Note over Vault: Anti-spam bond escrowed (>= 20 Gwei). Fingerprint registered.
    
    Vault->>Consensus: adjudicate_whistleblower_report(report_id)
    Consensus->>Consensus: Fetch dossier (Fail-Closed gl.get_webpage)
    Consensus->>Consensus: Multi-Validator LLM Audit & Scoring (0-1000)
    
    alt Score >= 750 (MALFEASANCE_SUBSTANTIATED)
        Consensus-->>Vault: MALFEASANCE_SUBSTANTIATED verdict
        Vault->>Whistleblower: emit_transfer(bounty_payout + 100% bond refund)
        Note over Vault: Entity flagged is_sanctioned = True
    else Score < 400 (DISMISSED_FRIVOLOUS)
        Consensus-->>Vault: DISMISSED_FRIVOLOUS verdict
        Vault->>Vault: Slash anti-spam bond to organization pool reserves
    else Intermediate (INSUFFICIENT_EVIDENCE)
        Consensus-->>Vault: INSUFFICIENT_EVIDENCE verdict
        Vault->>Whistleblower: emit_transfer(100% bond refund, 0 bounty)
    end

    opt Native Transfer Failure Recovery
        Whistleblower->>Vault: withdraw_claimable()
        Note over Vault: Optimistically zeroes balance; restores if transfer fails
    end
```

---

## 3. Core Technical Invariants & Steward Compliance

1. **100% Backed Payable Escrow**: Pool reserves, top-ups, and anti-spam bonds require native GEN strictly via `@gl.public.write.payable` reading `gl.message.value`.
2. **Zero Genesis Debt**: Initialized without synthetic seed claims or unbacked liabilities in `__init__`.
3. **Delimiter-Resistant Hashing**: Report fingerprints encode canonical length prefixes (`L<len>:<val>|...`) preventing preimage collision attacks.
4. **Strict Address & SSRF Defense**: Comprehensive URL verification rejecting loopback, numeric IPs, RFC1918 subnets, and userinfo delimiters.
5. **Fail-Closed Evidence Ingestion**: If consensus web ingestion fails or returns empty payloads, reverts with `[ERR_EVIDENCE_FETCH_FAILED]` without state mutation.
6. **Recoverable Claimable Balances**: Failed EVM transfers credit to `claimable_balances`, safely recoverable via `withdraw_claimable()`.

---

## 4. Verification & Testing

The contract has been audited through a 15-phase Python regression test suite covering all operational edge cases:

```bash
python test/test_autonomous_whistleblower_vault.py
```

```
================================================================================
ALL 15 PHASES OF AutonomousWhistleblowerProtectionVault PASSED WITH 0 ERRORS!
================================================================================
```

---

## 5. License

MIT License. Designed and deployed for GenLayer by [tumhi4](https://github.com/tumhi4).
