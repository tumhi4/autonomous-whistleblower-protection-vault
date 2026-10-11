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
| **Contract Address** | [`0xE8299566ec82eC9839B6F6350105a40549eC540f`](https://explorer-studio.genlayer.com/address/0xE8299566ec82eC9839B6F6350105a40549eC540f) |
| **Deployment Transaction** | `0x84f3d4ab3b85dc23cbd5a7b93c4dcfea4bf4818b421d0a05d0ff8219ed0d78f6` |
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
    Note over Vault: Anti-spam bond escrowed (>= 20 Gwei). Duplicate dossier shield enforced.
    
    Vault->>Consensus: adjudicate_whistleblower_report(report_id)
    Consensus->>Consensus: Ingest dossier via Equivalence Principle (gl.nondet.web.render)
    Consensus->>Consensus: Multi-validator audit & scoring (gl.eq_principle.prompt_non_comparative)
    
    alt Score >= 750 AND Verdict SUBSTANTIATED
        Consensus-->>Vault: MALFEASANCE_SUBSTANTIATED verdict
        Vault->>Whistleblower: emit_transfer(bounty_payout + 100% bond refund)
        Note over Vault: Entity flagged is_sanctioned = True
    else Score < 400 OR Verdict DISMISSED
        Consensus-->>Vault: DISMISSED_FRIVOLOUS verdict
        Vault->>Vault: Slash anti-spam bond to organization pool reserves
    else Intermediate / Inconclusive
        Consensus-->>Vault: INSUFFICIENT_EVIDENCE verdict
        Vault->>Whistleblower: emit_transfer(100% bond refund, 0 bounty)
    end

    opt Unreachable Dossier Timeout Recovery (>= 7 Days)
        Whistleblower->>Vault: claim_abandoned_report_bond(report_id)
        Vault->>Whistleblower: emit_transfer(100% bond principal)
    end

    opt Clean Sponsor Capital Exit
        Sponsor->>Vault: decommission_pool(pool_id)
        Vault->>Sponsor: emit_transfer(unencumbered remaining escrow)
    end
```

---

## 3. Core Technical Invariants & Steward Compliance

1. **100% Backed Payable Escrow**: Pool reserves, top-ups, and anti-spam bonds require native GEN strictly via `@gl.public.write.payable` reading `gl.message.value`.
2. **Duplicate Dossier Shield**: Tracks canonical `pool_id + dossier_url` hashes to prevent copycats and mempool front-running bounty drains.
3. **Strict Metric Binding**: Bounties require proof score $\ge 750$ and explicit consensus verification; frivolous reports ($< 400$) slash anti-spam bonds.
4. **Dossier Timeout Bond Recovery**: If an external leak site goes offline permanently, whistleblowers can recover their bond principal after 7 days via `claim_abandoned_report_bond()`.
5. **Prompt Injection Hardening**: External web payloads are boundary-boxed inside `<untrusted_evidence_dossier>` tags with strict system directives.
6. **Controlled Sponsor Exit**: Unsanctioned organizations can decommission pools and reclaim unencumbered capital via `decommission_pool()`.
7. **Recoverable Claimable Balances**: Failed EVM transfers credit to `claimable_balances`, safely recoverable via `withdraw_claimable()`.
8. **Multi-Validator Equivalence Consensus**: Adjudication executes inside `gl.eq_principle.prompt_non_comparative` where validators independently refetch the evidence dossier URL with `gl.nondet.web.render` and enforce bidirectional rejection criteria binding the verdict and proof score.

---

## 4. Verification & Testing

The contract has been audited through a 15-phase Python regression test suite covering all operational edge cases:

```bash
python test/test_autonomous_whistleblower_vault.py
```

```
================================================================================
ALL 15 PHASES OF AutonomousWhistleblowerProtectionVault (REMEDIATED) PASSED WITH 0 ERRORS!
================================================================================
```

---

## 5. License

MIT License. Designed and deployed for GenLayer by [tumhi4](https://github.com/tumhi4).
