== PROTOCOL DISCLOSURE: AUTONOMOUS WHISTLEBLOWER PROTECTION VAULT ==

[1. SYSTEM CLASS & PURPOSE]
Decentralized corporate governance & DAO malfeasance whistleblower escrow on GenLayer. Eliminates hotline leaks and retaliation by anchoring disclosures to consensus-verified evidence dossiers.

[2. TECHNICAL INVARIANTS]
• Payable Escrow: Bounty reserves and anti-spam bonds escrowed strictly via @gl.public.write.payable (gl.message.value); disbursements execute via emit_transfer().
• Zero Genesis Obligation: Zero unbacked debt in __init__; 100% principal backed on-chain.
• Consensus Adjudication: Multi-validator consensus ingests external dossiers; scores malfeasance proof (0–1000). Score >= 750 releases proportional bounty + 100% bond refund.
• Fail-Closed Ingestion: Network failures abort with [ERR_EVIDENCE_FETCH_FAILED] with zero state mutation.
• Recoverable Claims: Failed payouts credit to claimable_balances with safe withdraw_claimable().
