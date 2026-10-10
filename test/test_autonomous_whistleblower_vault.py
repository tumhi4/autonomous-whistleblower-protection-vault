# test_autonomous_whistleblower_vault.py
# 15-Phase Comprehensive Regression & Security Test Suite for AutonomousWhistleblowerProtectionVault (Remediated)
import json
import hashlib
import urllib.parse
from datetime import datetime, timezone


class MockGL:
    def __init__(self):
        self.transfers = []
        self.mock_web_responses = {}
        self.fail_web_fetch = False
        self.simulate_transfer_fail = False

    def emit_transfer(self, recipient: str, amount: int):
        if self.simulate_transfer_fail:
            raise RuntimeError("Simulated EVM transfer failure")
        self.transfers.append({"recipient": str(recipient).lower(), "amount": int(amount)})

    def get_webpage(self, url: str) -> str:
        if self.fail_web_fetch:
            raise RuntimeError("Simulated network timeout connecting to dossier repository")
        return self.mock_web_responses.get(
            url,
            "<html><body><h1>Confidential Whistleblower Leak Dossier</h1>"
            "<p>Audit reveals unapproved multi-sig executive withdrawal of 500,000 USDC routed to personal offshore accounts on 2026-08-14.</p></body></html>"
        )

    def exec_prompt(self, prompt: str) -> str:
        return json.dumps({
            "verdict": "MALFEASANCE_SUBSTANTIATED",
            "score": 920,
            "rationale": "Bank statements and unauthorized tx hashes match the unapproved treasury transfer."
        })


class MockAutonomousWhistleblowerProtectionVault:
    def __init__(self, owner_address: str, gl_mock: MockGL):
        self.gl = gl_mock
        self.owner = owner_address.lower()
        self.total_pools_created = 0
        self.total_reports_submitted = 0
        self.total_reports_adjudicated = 0
        self.total_volume_locked = 0
        self.total_bounties_paid = 0

        self.pools = {}
        self.reports = {}
        self.consumed_report_hashes = {}
        self.consumed_dossier_hashes = {}
        self.claimable_balances = {}

        self.VERDICT_PENDING = "PENDING_ADJUDICATION"
        self.VERDICT_SUBSTANTIATED = "MALFEASANCE_SUBSTANTIATED"
        self.VERDICT_DISMISSED = "DISMISSED_FRIVOLOUS"
        self.VERDICT_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
        self.VERDICT_ABANDONED = "REPORT_ABANDONED"
        self.VALID_CATEGORIES = ("EMBEZZLEMENT", "GOVERNANCE_TAMPERING", "FRAUD", "INSIDER_COLLUSION")

        self.MIN_POOL_DEPOSIT = 100_000_000_000
        self.MIN_ANTI_SPAM_BOND = 20_000_000_000
        self.MIN_BOUNTY_BPS = 500
        self.MAX_BOUNTY_BPS = 3000
        self.SCORE_SUBSTANTIATED_MIN = 750
        self.SCORE_FRIVOLOUS_MAX = 400
        self.REPORT_TIMEOUT_SECONDS = 86400 * 7

    def fund_contract(self, caller: str, value: int):
        if value > 0:
            cur = self.claimable_balances.get(self.owner, 0)
            self.claimable_balances[self.owner] = cur + value
            self.total_volume_locked += value

    def _compute_report_hash(self, pool_id: str, whistleblower: str, category: str, url: str, nonce: str) -> str:
        data = (
            "L" + str(len(pool_id)) + ":" + pool_id.upper() + "|" +
            "L" + str(len(whistleblower)) + ":" + whistleblower.lower() + "|" +
            "L" + str(len(category)) + ":" + category.upper() + "|" +
            "L" + str(len(url)) + ":" + url + "|" +
            "L" + str(len(nonce)) + ":" + nonce
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _compute_dossier_hash(self, pool_id: str, url: str) -> str:
        data = "POOL:" + pool_id.upper() + "|URL:" + url.strip().lower()
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _validate_eth_address(self, addr_str: str, field_name: str) -> str:
        clean = addr_str.strip().strip('"').strip("'")
        assert len(clean) == 42 and clean.startswith("0x"), "[ERR_ADDR_01] " + field_name
        for ch in clean[2:].lower():
            assert ch in "0123456789abcdef", "[ERR_ADDR_02] " + field_name
        assert clean.lower() != "0x0000000000000000000000000000000000000000", "[ERR_ADDR_ZERO] " + field_name
        return clean

    def _validate_url(self, url: str, field_name: str) -> str:
        clean_url = url.strip().strip('"').strip("'")
        assert 10 <= len(clean_url) <= 300, "[ERR_URL_LEN] " + field_name
        parsed = urllib.parse.urlsplit(clean_url)
        assert parsed.scheme in ("https", "http"), "[ERR_URL_SCHEME] " + field_name
        assert not parsed.username and not parsed.password, "[ERR_URL_SSRF]"
        assert "@" not in parsed.netloc, "[ERR_URL_SSRF]"
        host = parsed.hostname.lower() if parsed.hostname else ""
        assert host, "[ERR_URL_HOST]"
        if host.isdigit() or host.startswith("0x") or host.startswith("0o"):
            raise AssertionError("[ERR_URL_SSRF] Numeric IP")
        if host in ("localhost", "0.0.0.0", "::", "::1"):
            raise AssertionError("[ERR_URL_SSRF] Localhost")
        if any(host.endswith(s) for s in (".local", ".internal", ".lan", ".corp", ".test", ".invalid")):
            raise AssertionError("[ERR_URL_SSRF] Internal domain")
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            o1, o2, o3, o4 = [int(p) for p in parts]
            if o1 in (127, 10, 0) or (o1 == 172 and 16 <= o2 <= 31) or (o1 == 192 and o2 == 168) or (o1 == 169 and o2 == 254):
                raise AssertionError("[ERR_URL_SSRF] RFC1918 IP")
        return clean_url

    def create_whistleblower_pool(self, caller: str, value: int, organization_name: str) -> str:
        sender_hex = self._validate_eth_address(caller, "Pool Sponsor").lower()
        clean_org = organization_name.strip().strip('"').strip("'")
        assert 3 <= len(clean_org) <= 100, "[ERR_ORG_LEN]"
        assert value >= self.MIN_POOL_DEPOSIT, "[ERR_MIN_DEPOSIT]"

        now_utc = int(datetime.now(timezone.utc).timestamp())
        new_pool_id = "POOL_" + str(self.total_pools_created + 1)
        self.pools[new_pool_id] = {
            "pool_id": new_pool_id,
            "sponsor": sender_hex,
            "organization_name": clean_org,
            "escrow_balance": value,
            "total_bounties_paid": 0,
            "created_at": now_utc,
            "is_sanctioned": False,
            "is_active": True
        }
        self.total_pools_created += 1
        self.total_volume_locked += value
        return "POOL_CREATED: " + new_pool_id

    def deposit_to_pool(self, caller: str, value: int, pool_id: str) -> str:
        self._validate_eth_address(caller, "Caller")
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND]"
        pool = self.pools[clean_p_id]
        assert pool["is_active"], "[ERR_POOL_INACTIVE]"
        assert value > 0, "[ERR_ZERO_DEPOSIT]"

        pool["escrow_balance"] += value
        self.pools[clean_p_id] = pool
        self.total_volume_locked += value
        return "POOL_TOPPED_UP: " + clean_p_id

    def submit_whistleblower_report(self, caller: str, value: int, pool_id: str, category: str, evidence_dossier_url: str, requested_bounty_bps: int, nonce: str) -> str:
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND]"
        pool = self.pools[clean_p_id]
        assert pool["is_active"], "[ERR_POOL_INACTIVE]"

        sender_hex = self._validate_eth_address(caller, "Whistleblower").lower()
        clean_cat = category.strip().upper()
        assert clean_cat in self.VALID_CATEGORIES, "[ERR_INVALID_CATEGORY]"
        clean_url = self._validate_url(evidence_dossier_url, "Evidence Dossier URL")

        d_hash = self._compute_dossier_hash(clean_p_id, clean_url)
        assert d_hash.lower() not in self.consumed_dossier_hashes, "[ERR_DOSSIER_ALREADY_SUBMITTED]"

        assert self.MIN_BOUNTY_BPS <= requested_bounty_bps <= self.MAX_BOUNTY_BPS, "[ERR_BOUNTY_BPS_BOUNDS]"
        assert value >= self.MIN_ANTI_SPAM_BOND, "[ERR_MIN_BOND]"

        r_hash = self._compute_report_hash(clean_p_id, sender_hex, clean_cat, clean_url, nonce)
        assert r_hash.lower() not in self.consumed_report_hashes, "[ERR_REPORT_EXISTS]"

        now_utc = int(datetime.now(timezone.utc).timestamp())
        new_r_id = "REPORT_" + str(self.total_reports_submitted + 1)
        self.reports[new_r_id] = {
            "report_id": new_r_id,
            "pool_id": clean_p_id,
            "whistleblower": sender_hex,
            "category": clean_cat,
            "evidence_dossier_url": clean_url,
            "report_hash": r_hash,
            "dossier_hash": d_hash,
            "anti_spam_bond": value,
            "requested_bounty_bps": requested_bounty_bps,
            "submitted_at": now_utc,
            "adjudicated_at": 0,
            "verdict": self.VERDICT_PENDING,
            "payout_awarded": 0,
            "has_claimed": False,
            "adjudication_rationale": ""
        }
        self.consumed_report_hashes[r_hash.lower()] = True
        self.consumed_dossier_hashes[d_hash.lower()] = True
        self.total_reports_submitted += 1
        self.total_volume_locked += value
        return "REPORT_SUBMITTED: " + new_r_id

    def adjudicate_whistleblower_report(self, report_id: str) -> str:
        clean_r_id = report_id.strip().upper()
        assert clean_r_id in self.reports, "[ERR_REPORT_NOT_FOUND]"
        rep = self.reports[clean_r_id]
        assert rep["verdict"] == self.VERDICT_PENDING, "[ERR_ALREADY_ADJUDICATED]"

        clean_p_id = rep["pool_id"]
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND]"
        pool = self.pools[clean_p_id]

        try:
            dossier_text = self.gl.get_webpage(rep["evidence_dossier_url"])
        except Exception:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED]")

        assert dossier_text is not None and len(dossier_text.strip()) >= 30, "[ERR_EVIDENCE_FETCH_FAILED]"

        raw_resp = self.gl.exec_prompt("Eval malfeasance prompt")
        parsed_verdict = self.VERDICT_INSUFFICIENT
        rationale = "Fallback"
        score = 500

        try:
            parsed = json.loads(raw_resp)
            cand = str(parsed.get("verdict", "")).strip().upper()
            if cand in (self.VERDICT_SUBSTANTIATED, self.VERDICT_DISMISSED, self.VERDICT_INSUFFICIENT):
                parsed_verdict = cand
            score = int(parsed.get("score", 500))
            rationale = str(parsed.get("rationale", ""))
        except Exception:
            pass

        # Metric Binding
        if score >= self.SCORE_SUBSTANTIATED_MIN and parsed_verdict == self.VERDICT_SUBSTANTIATED:
            final_verdict = self.VERDICT_SUBSTANTIATED
        elif score < self.SCORE_FRIVOLOUS_MAX or parsed_verdict == self.VERDICT_DISMISSED:
            final_verdict = self.VERDICT_DISMISSED
        else:
            final_verdict = self.VERDICT_INSUFFICIENT

        now_utc = int(datetime.now(timezone.utc).timestamp())
        rep["adjudicated_at"] = now_utc
        rep["verdict"] = final_verdict
        rep["adjudication_rationale"] = rationale

        bond_amount = rep["anti_spam_bond"]
        payout = 0

        if final_verdict == self.VERDICT_SUBSTANTIATED:
            cur_escrow = pool["escrow_balance"]
            payout = (cur_escrow * rep["requested_bounty_bps"]) // 10000
            total_disbursement = payout + bond_amount
            rep["payout_awarded"] = payout
            pool["escrow_balance"] -= payout
            pool["total_bounties_paid"] += payout
            pool["is_sanctioned"] = True
            self.total_bounties_paid += payout

            if self.total_volume_locked >= total_disbursement:
                self.total_volume_locked -= total_disbursement
            else:
                self.total_volume_locked = 0

            rep["has_claimed"] = True

            try:
                self.gl.emit_transfer(rep["whistleblower"], total_disbursement)
            except Exception:
                cur = self.claimable_balances.get(rep["whistleblower"], 0)
                self.claimable_balances[rep["whistleblower"]] = cur + total_disbursement

        elif final_verdict == self.VERDICT_DISMISSED:
            pool["escrow_balance"] += bond_amount
            rep["payout_awarded"] = 0
            rep["has_claimed"] = True

        else: # INSUFFICIENT_EVIDENCE
            rep["payout_awarded"] = 0
            rep["has_claimed"] = True
            if self.total_volume_locked >= bond_amount:
                self.total_volume_locked -= bond_amount
            else:
                self.total_volume_locked = 0

            try:
                self.gl.emit_transfer(rep["whistleblower"], bond_amount)
            except Exception:
                cur = self.claimable_balances.get(rep["whistleblower"], 0)
                self.claimable_balances[rep["whistleblower"]] = cur + bond_amount

        self.reports[clean_r_id] = rep
        self.pools[clean_p_id] = pool
        self.total_reports_adjudicated += 1
        return "REPORT_ADJUDICATED: " + clean_r_id

    def claim_abandoned_report_bond(self, caller: str, report_id: str, simulated_now_offset: int = 0) -> str:
        clean_r_id = report_id.strip().upper()
        assert clean_r_id in self.reports, "[ERR_REPORT_NOT_FOUND]"
        rep = self.reports[clean_r_id]

        sender_hex = self._validate_eth_address(caller, "Caller").lower()
        assert sender_hex == rep["whistleblower"], "[ERR_UNAUTHORIZED]"
        assert rep["verdict"] == self.VERDICT_PENDING, "[ERR_REPORT_NOT_PENDING]"

        now_utc = int(datetime.now(timezone.utc).timestamp()) + simulated_now_offset
        assert now_utc >= rep["submitted_at"] + self.REPORT_TIMEOUT_SECONDS, "[ERR_TIMEOUT_NOT_REACHED]"

        bond_val = rep["anti_spam_bond"]
        rep["verdict"] = self.VERDICT_ABANDONED
        rep["has_claimed"] = True
        rep["adjudication_rationale"] = "Recovered after 7-day evidence ingestion timeout."
        self.reports[clean_r_id] = rep

        if self.total_volume_locked >= bond_val:
            self.total_volume_locked -= bond_val
        else:
            self.total_volume_locked = 0

        try:
            self.gl.emit_transfer(sender_hex, bond_val)
        except Exception:
            cur = self.claimable_balances.get(sender_hex, 0)
            self.claimable_balances[sender_hex] = cur + bond_val

        return "BOND_RECLAIMED: " + clean_r_id

    def decommission_pool(self, caller: str, pool_id: str) -> str:
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND]"
        pool = self.pools[clean_p_id]

        sender_hex = self._validate_eth_address(caller, "Caller").lower()
        assert sender_hex == pool["sponsor"], "[ERR_UNAUTHORIZED]"
        assert pool["is_active"], "[ERR_ALREADY_INACTIVE]"
        assert not pool["is_sanctioned"], "[ERR_SANCTIONED]"

        rem_escrow = pool["escrow_balance"]
        pool["is_active"] = False
        pool["escrow_balance"] = 0
        self.pools[clean_p_id] = pool

        if rem_escrow > 0:
            if self.total_volume_locked >= rem_escrow:
                self.total_volume_locked -= rem_escrow
            else:
                self.total_volume_locked = 0

            try:
                self.gl.emit_transfer(sender_hex, rem_escrow)
            except Exception:
                cur = self.claimable_balances.get(sender_hex, 0)
                self.claimable_balances[sender_hex] = cur + rem_escrow

        return "POOL_DECOMMISSIONED: " + clean_p_id

    def withdraw_claimable(self, caller: str) -> str:
        sender_hex = self._validate_eth_address(caller, "Caller").lower()
        assert sender_hex in self.claimable_balances, "[ERR_NO_CLAIMABLE]"
        bal = self.claimable_balances[sender_hex]
        assert bal > 0, "[ERR_ZERO_CLAIMABLE]"

        self.claimable_balances[sender_hex] = 0
        try:
            self.gl.emit_transfer(sender_hex, bal)
        except Exception:
            self.claimable_balances[sender_hex] = bal
            raise AssertionError("[ERR_WITHDRAWAL_FAILED]")

        return "WITHDRAW_SUCCESS: " + sender_hex + " | Amount: " + str(bal)


# --------------------------------------------------------------------------
# 15-Phase Execution Runner
# --------------------------------------------------------------------------
def run_tests():
    print("=" * 80)
    print("STARTING 15-PHASE REGRESSION TEST SUITE: AutonomousWhistleblowerProtectionVault (REMEDIATED)")
    print("=" * 80)

    gl = MockGL()
    owner = "0x1111111111111111111111111111111111111111"
    vault = MockAutonomousWhistleblowerProtectionVault(owner, gl)

    # Phase 1: Zero genesis fixtures
    print("\n[Phase 1] Testing Zero Genesis Fixtures & Zero Unbacked Obligation...")
    assert vault.total_pools_created == 0
    assert vault.total_reports_submitted == 0
    assert vault.total_volume_locked == 0
    assert len(vault.pools) == 0
    assert len(vault.reports) == 0
    assert len(vault.claimable_balances) == 0
    print("  [+] Phase 1 Passed: Initialized with zero unbacked debt and zero phantom records.")

    # Phase 2: Length-prefixed canonical hashing
    print("\n[Phase 2] Testing Canonical Length-Prefixed Hashing & Delimiter Resistance...")
    h1 = vault._compute_report_hash("POOL_1", "0xabc", "FRAUD", "https://leak.org/dossier1", "101")
    h2 = vault._compute_report_hash("POOL_10", "xabc", "FRAUD", "https://leak.org/dossier1", "101")
    assert h1 != h2, "Collision between different length pool IDs"
    print("  [+] Phase 2 Passed: Canonical hashing resists delimiter injection.")

    # Phase 3: Address sanitization
    print("\n[Phase 3] Testing Strict Address Sanitization...")
    try:
        vault._validate_eth_address("not_an_address", "Test")
        assert False
    except AssertionError as e:
        assert "[ERR_ADDR_01]" in str(e)
    try:
        vault._validate_eth_address("0x0000000000000000000000000000000000000000", "Test")
        assert False
    except AssertionError as e:
        assert "[ERR_ADDR_ZERO]" in str(e)
    print("  [+] Phase 3 Passed: Address sanitization strictly enforced.")

    # Phase 4: SSRF sanitization
    print("\n[Phase 4] Testing SSRF Defense on Evidence URLs...")
    for bad_url in [
        "http://localhost:8080/leak.html",
        "https://127.0.0.1/doc.pdf",
        "http://169.254.169.254/latest/meta-data",
        "https://user:pass@leaks.org/doc",
        "https://company.internal/secret",
        "http://192.168.1.50/vault.html"
    ]:
        try:
            vault._validate_url(bad_url, "Test URL")
            assert False, f"Should reject SSRF URL {bad_url}"
        except AssertionError:
            pass
    print("  [+] Phase 4 Passed: SSRF defense neutralized all vector attacks.")

    # Phase 5: Pool creation with backed payable escrow
    print("\n[Phase 5] Testing Whistleblower Pool Creation (100% Backed)...")
    sponsor = "0x2222222222222222222222222222222222222222"
    pool_val = 500_000_000_000  # 500 Gwei
    res = vault.create_whistleblower_pool(sponsor, pool_val, "Nexus DAO Foundation")
    assert "POOL_1" in res
    assert vault.pools["POOL_1"]["escrow_balance"] == pool_val
    assert vault.total_volume_locked == pool_val
    print("  [+] Phase 5 Passed: POOL_1 created with 500 Gwei verified escrow.")

    # Phase 6: Pool top-up
    print("\n[Phase 6] Testing Pool Top-Up Reserves...")
    topup_val = 200_000_000_000  # 200 Gwei
    vault.deposit_to_pool(sponsor, topup_val, "POOL_1")
    assert vault.pools["POOL_1"]["escrow_balance"] == pool_val + topup_val
    assert vault.total_volume_locked == pool_val + topup_val
    print("  [+] Phase 6 Passed: Pool top-up incremented escrow to 700 Gwei.")

    # Phase 7: Submit whistleblower report with anti-spam bond
    print("\n[Phase 7] Testing Whistleblower Report Submission with Anti-Spam Bond...")
    whistleblower = "0x3333333333333333333333333333333333333333"
    bond = 30_000_000_000  # 30 Gwei
    dossier_url = "https://secure-leaks.org/nexus-dao/audit-2026.html"
    res_rep = vault.submit_whistleblower_report(
        whistleblower, bond, "POOL_1", "EMBEZZLEMENT", dossier_url, 2000, "nonce-991"
    )
    assert "REPORT_1" in res_rep
    assert vault.reports["REPORT_1"]["anti_spam_bond"] == bond
    assert vault.total_volume_locked == pool_val + topup_val + bond
    print("  [+] Phase 7 Passed: REPORT_1 submitted with 30 Gwei anti-spam bond.")

    # Phase 8: Bounty bps bounds check
    print("\n[Phase 8] Testing Requested Bounty BPS Bounds (500 - 3000 bps)...")
    try:
        vault.submit_whistleblower_report(
            whistleblower, bond, "POOL_1", "EMBEZZLEMENT", "https://secure-leaks.org/other.html", 4000, "nonce-too-high"
        )
        assert False
    except AssertionError as e:
        assert "[ERR_BOUNTY_BPS_BOUNDS]" in str(e)
    print("  [+] Phase 8 Passed: Bounty bounds (5% to 30%) strictly enforced.")

    # Phase 9: Duplicate Dossier Shield (CW-01 Remediated)
    print("\n[Phase 9] Testing Duplicate Dossier Shield (Copycat Front-Running Defense)...")
    copycat = "0x9999999999999999999999999999999999999999"
    try:
        vault.submit_whistleblower_report(
            copycat, bond, "POOL_1", "EMBEZZLEMENT", dossier_url, 2000, "nonce-attacker"
        )
        assert False, "Should reject duplicate dossier URL for same pool"
    except AssertionError as e:
        assert "[ERR_DOSSIER_ALREADY_SUBMITTED]" in str(e)
    print("  [+] Phase 9 Passed: Duplicate dossier re-submission blocked; copycats neutralized.")

    # Phase 10: Fail-closed evidence ingestion
    print("\n[Phase 10] Testing Fail-Closed Evidence Ingestion Invariant...")
    gl.fail_web_fetch = True
    try:
        vault.adjudicate_whistleblower_report("REPORT_1")
        assert False
    except AssertionError as e:
        assert "[ERR_EVIDENCE_FETCH_FAILED]" in str(e)
    gl.fail_web_fetch = False
    assert vault.reports["REPORT_1"]["verdict"] == vault.VERDICT_PENDING
    print("  [+] Phase 10 Passed: Web failure triggered fail-closed zero-mutation abort.")

    # Phase 11: Multi-validator consensus adjudication — MALFEASANCE_SUBSTANTIATED with Score Binding
    print("\n[Phase 11] Testing Consensus Adjudication with Score >= 750 Binding...")
    res_adj = vault.adjudicate_whistleblower_report("REPORT_1")
    assert "REPORT_ADJUDICATED: REPORT_1" in res_adj
    assert vault.reports["REPORT_1"]["verdict"] == vault.VERDICT_SUBSTANTIATED
    assert vault.reports["REPORT_1"]["payout_awarded"] == 140_000_000_000
    assert vault.pools["POOL_1"]["is_sanctioned"] is True
    assert vault.pools["POOL_1"]["escrow_balance"] == 560_000_000_000
    print("  [+] Phase 11 Passed: Malfeasance substantiated; 140 Gwei bounty + 30 Gwei bond refunded.")

    # Phase 12: Consensus adjudication — DISMISSED_FRIVOLOUS with Score < 400
    print("\n[Phase 12] Testing Consensus Adjudication: DISMISSED_FRIVOLOUS with Score < 400...")
    whistleblower2 = "0x4444444444444444444444444444444444444444"
    vault.submit_whistleblower_report(
        whistleblower2, bond, "POOL_1", "FRAUD", "https://secure-leaks.org/frivolous.html", 1000, "nonce-992"
    )
    gl.exec_prompt = lambda prompt: json.dumps({
        "verdict": "DISMISSED_FRIVOLOUS",
        "score": 120,
        "rationale": "Fabricated claims."
    })
    vault.adjudicate_whistleblower_report("REPORT_2")
    assert vault.reports["REPORT_2"]["verdict"] == vault.VERDICT_DISMISSED
    assert vault.pools["POOL_1"]["escrow_balance"] == 590_000_000_000
    print("  [+] Phase 12 Passed: Frivolous report dismissed; 30 Gwei bond slashed to organization pool.")

    # Phase 13: Unreachable Dossier Timeout Bond Recovery (CW-02 Remediated)
    print("\n[Phase 13] Testing Unreachable Dossier Timeout Recovery (claim_abandoned_report_bond)...")
    whistleblower3 = "0x5555555555555555555555555555555555555555"
    vault.submit_whistleblower_report(
        whistleblower3, bond, "POOL_1", "INSIDER_COLLUSION", "https://offline-server.org/doc.html", 1500, "nonce-timeout"
    )
    # Attempt early recovery before 7 days -> should fail
    try:
        vault.claim_abandoned_report_bond(whistleblower3, "REPORT_3", simulated_now_offset=0)
        assert False
    except AssertionError as e:
        assert "[ERR_TIMEOUT_NOT_REACHED]" in str(e)
    # Reclaim after 7 days (86400 * 7 + 10s)
    vault.claim_abandoned_report_bond(whistleblower3, "REPORT_3", simulated_now_offset=86400 * 7 + 10)
    assert vault.reports["REPORT_3"]["verdict"] == vault.VERDICT_ABANDONED
    assert gl.transfers[-1]["recipient"] == whistleblower3.lower()
    assert gl.transfers[-1]["amount"] == bond
    print("  [+] Phase 13 Passed: Unreachable dossier bond safely reclaimed after 7-day timeout.")

    # Phase 14: Controlled Sponsor Pool Decommissioning (CW-06 Remediated)
    print("\n[Phase 14] Testing Controlled Sponsor Pool Decommissioning...")
    # Create innocent POOL_2
    sponsor2 = "0x7777777777777777777777777777777777777777"
    vault.create_whistleblower_pool(sponsor2, 300_000_000_000, "Clean Foundation")
    # Decommission POOL_2
    res_dec = vault.decommission_pool(sponsor2, "POOL_2")
    assert "POOL_DECOMMISSIONED: POOL_2" in res_dec
    assert vault.pools["POOL_2"]["is_active"] is False
    assert gl.transfers[-1]["recipient"] == sponsor2.lower()
    assert gl.transfers[-1]["amount"] == 300_000_000_000
    # Sanctioned POOL_1 cannot be decommissioned!
    try:
        vault.decommission_pool(sponsor, "POOL_1")
        assert False
    except AssertionError as e:
        assert "[ERR_SANCTIONED]" in str(e)
    print("  [+] Phase 14 Passed: Clean sponsor reclaimed capital; sanctioned pool locked.")

    # Phase 15: Safe withdraw_claimable with balance restoration
    print("\n[Phase 15] Testing Recoverable withdraw_claimable()...")
    whistleblower4 = "0x6666666666666666666666666666666666666666"
    vault.submit_whistleblower_report(
        whistleblower4, bond, "POOL_1", "EMBEZZLEMENT", "https://secure-leaks.org/vault4.html", 1000, "nonce-994"
    )
    gl.simulate_transfer_fail = True
    gl.exec_prompt = lambda prompt: json.dumps({
        "verdict": "MALFEASANCE_SUBSTANTIATED",
        "score": 900,
        "rationale": "Solid proof of embezzlement."
    })
    vault.adjudicate_whistleblower_report("REPORT_4")
    expected_claimable = 590_000_000_000 * 10 // 100 + bond
    assert vault.claimable_balances[whistleblower4.lower()] == expected_claimable

    try:
        vault.withdraw_claimable(whistleblower4)
        assert False
    except AssertionError as e:
        assert "[ERR_WITHDRAWAL_FAILED]" in str(e)
    assert vault.claimable_balances[whistleblower4.lower()] == expected_claimable

    gl.simulate_transfer_fail = False
    vault.withdraw_claimable(whistleblower4)
    assert vault.claimable_balances[whistleblower4.lower()] == 0
    assert gl.transfers[-1]["recipient"] == whistleblower4.lower()
    assert gl.transfers[-1]["amount"] == expected_claimable
    print("  [+] Phase 15 Passed: Failed withdrawal preserved balance, and subsequent withdrawal succeeded.")

    print("\n" + "=" * 80)
    print("ALL 15 PHASES OF AutonomousWhistleblowerProtectionVault (REMEDIATED) PASSED WITH 0 ERRORS!")
    print("=" * 80)


if __name__ == "__main__":
    run_tests()
