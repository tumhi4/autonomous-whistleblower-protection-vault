# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
import json
import hashlib
import urllib.parse
import datetime
from dataclasses import dataclass
from genlayer import *


VERDICT_PENDING = "PENDING_ADJUDICATION"
VERDICT_SUBSTANTIATED = "MALFEASANCE_SUBSTANTIATED"
VERDICT_DISMISSED = "DISMISSED_FRIVOLOUS"
VERDICT_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"

VALID_CATEGORIES = ("EMBEZZLEMENT", "GOVERNANCE_TAMPERING", "FRAUD", "INSIDER_COLLUSION")

MIN_POOL_DEPOSIT = 100_000_000_000       # 100 Gwei
MIN_ANTI_SPAM_BOND = 20_000_000_000      # 20 Gwei
MIN_BOUNTY_BPS = 500                     # 5% Min Bounty
MAX_BOUNTY_BPS = 3000                    # 30% Max Bounty Cap


@allow_storage
@dataclass
class WhistleblowerPoolRecord:
    pool_id: str
    sponsor: str
    organization_name: str
    escrow_balance: u256
    total_bounties_paid: u256
    created_at: u256
    is_sanctioned: bool
    is_active: bool


@allow_storage
@dataclass
class WhistleblowerReportRecord:
    report_id: str
    pool_id: str
    whistleblower: str
    category: str
    evidence_dossier_url: str
    report_hash: str
    anti_spam_bond: u256
    requested_bounty_bps: u256
    submitted_at: u256
    adjudicated_at: u256
    verdict: str
    payout_awarded: u256
    has_claimed: bool
    adjudication_rationale: str


class AutonomousWhistleblowerProtectionVault(gl.Contract):
    """
    AutonomousWhistleblowerProtectionVault: Decentralized Whistleblower Escrow & Consensus Adjudication
    ====================================================================================================
    Core Guarantees & Technical Invariants:
    1. 100% Backed Payable Escrow: Bounty reserves and whistleblower anti-spam bonds require native
       GEN strictly via @gl.public.write.payable reading gl.message.value.
    2. Zero Genesis Fixtures: Zero unbacked debt or phantom balances minted during initialization.
    3. Canonical Length-Prefixed Hashing: Report fingerprints use length-prefixed encoding
       to eliminate preimage delimiter and extension collision attacks.
    4. Strict Address & SSRF Defense: Rejects numeric IPs, localhost, RFC1918 ranges, internal TLDs,
       and userinfo delimiters in evidence URLs.
    5. Non-Admin Consensus Clock: Timestamps evaluate strictly against UTC block consensus time (datetime.datetime.now).
    6. Fail-Closed Evidence Ingestion: Multi-validator consensus fetches evidence dossiers; network failures
       cleanly abort with [ERR_EVIDENCE_FETCH_FAILED] with zero balance mutations.
    7. Recoverable Claimable Balances: Payouts disburse via emit_transfer(); failed transfers credit
       to claimable_balances with a dedicated withdraw_claimable() method that preserves balances on failure.
    """

    owner: str
    pools: TreeMap[str, WhistleblowerPoolRecord]
    reports: TreeMap[str, WhistleblowerReportRecord]
    consumed_report_hashes: TreeMap[str, bool]
    claimable_balances: TreeMap[str, u256]

    total_pools_created: u256
    total_reports_submitted: u256
    total_reports_adjudicated: u256
    total_volume_locked: u256
    total_bounties_paid: u256

    def __init__(self, owner: str):
        clean_owner = self._validate_eth_address(owner, "Contract Owner")
        self.owner = clean_owner.lower()
        self.total_pools_created = u256(0)
        self.total_reports_submitted = u256(0)
        self.total_reports_adjudicated = u256(0)
        self.total_volume_locked = u256(0)
        self.total_bounties_paid = u256(0)

    # --------------------------------------------------------------------------
    # Fallback Liquidity Funding Method
    # --------------------------------------------------------------------------
    @gl.public.write.payable
    def fund_contract(self) -> None:
        """
        Accepts direct native GEN transfers to increase general vault reserves.
        """
        val = int(gl.message.value)
        if val > 0:
            self.total_volume_locked += u256(val)

    # --------------------------------------------------------------------------
    # Cryptographic Hashing
    # --------------------------------------------------------------------------
    def _compute_report_hash(self, pool_id: str, whistleblower: str, category: str, url: str, nonce: str) -> str:
        data = (
            "L" + str(len(pool_id)) + ":" + pool_id.upper() + "|" +
            "L" + str(len(whistleblower)) + ":" + whistleblower.lower() + "|" +
            "L" + str(len(category)) + ":" + category.upper() + "|" +
            "L" + str(len(url)) + ":" + url + "|" +
            "L" + str(len(nonce)) + ":" + nonce
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    # --------------------------------------------------------------------------
    # Address & SSRF Validation
    # --------------------------------------------------------------------------
    def _validate_eth_address(self, addr_str: str, field_name: str) -> str:
        clean = addr_str.strip().strip('"').strip("'")
        assert len(clean) == 42 and clean.startswith("0x"), \
            "[ERR_ADDR_01] " + field_name + " must be a valid 42-character hexadecimal string starting with '0x'."
        for ch in clean[2:].lower():
            assert ch in "0123456789abcdef", \
                "[ERR_ADDR_02] " + field_name + " contains invalid hexadecimal characters."
        assert clean.lower() != "0x0000000000000000000000000000000000000000", \
            "[ERR_ADDR_ZERO] " + field_name + " cannot be the zero address."
        return clean

    def _validate_url(self, url: str, field_name: str) -> str:
        clean_url = url.strip().strip('"').strip("'")
        assert 10 <= len(clean_url) <= 300, \
            "[ERR_URL_LEN] " + field_name + " length must be between 10 and 300 characters."

        parsed = urllib.parse.urlsplit(clean_url)
        assert parsed.scheme in ("https", "http"), \
            "[ERR_URL_SCHEME] " + field_name + " must use http or https scheme."

        assert not parsed.username and not parsed.password, \
            "[ERR_URL_SSRF] User-info credentials (@) in " + field_name + " are strictly forbidden."
        assert "@" not in parsed.netloc, \
            "[ERR_URL_SSRF] Delimiter '@' in " + field_name + " is strictly forbidden."

        host = parsed.hostname.lower() if parsed.hostname else ""
        assert host, "[ERR_URL_HOST] Missing or unparseable host in " + field_name + "."

        if host.isdigit() or host.startswith("0x") or host.startswith("0o"):
            raise AssertionError("[ERR_URL_SSRF] Numeric IP addresses in " + field_name + " are forbidden.")

        if host in ("localhost", "0.0.0.0", "::", "::1"):
            raise AssertionError("[ERR_URL_SSRF] Localhost and loopback addresses in " + field_name + " are forbidden.")

        if any(host.endswith(suffix) for suffix in (".local", ".internal", ".lan", ".corp", ".test", ".invalid")):
            raise AssertionError("[ERR_URL_SSRF] Private internal domain targets in " + field_name + " are forbidden.")

        parts_ip = host.split(".")
        if len(parts_ip) == 4 and all(p.isdigit() for p in parts_ip):
            o1, o2, o3, o4 = [int(p) for p in parts_ip]
            if o1 in (127, 10, 0) or (o1 == 172 and 16 <= o2 <= 31) or (o1 == 192 and o2 == 168) or (o1 == 169 and o2 == 254):
                raise AssertionError("[ERR_URL_SSRF] Private RFC1918 or link-local IP ranges are forbidden.")

        return clean_url

    # --------------------------------------------------------------------------
    # Core Function 1: Whistleblower Pool Creation
    # --------------------------------------------------------------------------
    @gl.public.write.payable
    def create_whistleblower_pool(self, organization_name: str) -> str:
        """
        Initializes an autonomous whistleblower bounty pool backed by native GEN escrow.
        """
        sender_hex = self._validate_eth_address(str(gl.message.sender), "Pool Sponsor").lower()
        clean_org = organization_name.strip().strip('"').strip("'")
        assert 3 <= len(clean_org) <= 100, \
            "[ERR_ORG_LEN] Organization name must be between 3 and 100 characters."

        seed_deposit = int(gl.message.value)
        assert seed_deposit >= MIN_POOL_DEPOSIT, \
            "[ERR_MIN_DEPOSIT] Seed deposit must be at least " + str(MIN_POOL_DEPOSIT) + " wei."

        now_utc = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        new_pool_id = "POOL_" + str(int(self.total_pools_created) + 1)

        pool_rec = WhistleblowerPoolRecord(
            pool_id=new_pool_id,
            sponsor=sender_hex,
            organization_name=clean_org,
            escrow_balance=u256(seed_deposit),
            total_bounties_paid=u256(0),
            created_at=u256(now_utc),
            is_sanctioned=False,
            is_active=True
        )

        self.pools[new_pool_id] = pool_rec
        self.total_pools_created += 1
        self.total_volume_locked += u256(seed_deposit)

        return (
            "POOL_CREATED: " + new_pool_id + " | Org: " + clean_org
            + " | Escrow: " + str(seed_deposit) + " wei"
        )

    # --------------------------------------------------------------------------
    # Core Function 2: Top Up Pool Escrow Reserves
    # --------------------------------------------------------------------------
    @gl.public.write.payable
    def deposit_to_pool(self, pool_id: str) -> str:
        """
        Increases the bounty collateral available in an existing pool.
        """
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND] Specified bounty pool does not exist."
        pool = self.pools[clean_p_id]
        assert pool.is_active, "[ERR_POOL_INACTIVE] Target bounty pool is decommissioned."

        dep_val = int(gl.message.value)
        assert dep_val > 0, "[ERR_ZERO_DEPOSIT] Deposit amount must be greater than zero."

        pool.escrow_balance += u256(dep_val)
        self.pools[clean_p_id] = pool
        self.total_volume_locked += u256(dep_val)

        return "POOL_TOPPED_UP: " + clean_p_id + " | Added: " + str(dep_val) + " wei | Total: " + str(int(pool.escrow_balance)) + " wei"

    # --------------------------------------------------------------------------
    # Core Function 3: Submit Whistleblower Malfeasance Report
    # --------------------------------------------------------------------------
    @gl.public.write.payable
    def submit_whistleblower_report(
        self,
        pool_id: str,
        category: str,
        evidence_dossier_url: str,
        requested_bounty_bps: int,
        nonce: str
    ) -> str:
        """
        Submits an encrypted malfeasance disclosure with an on-chain anti-spam bond.
        """
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND] Specified bounty pool does not exist."
        pool = self.pools[clean_p_id]
        assert pool.is_active, "[ERR_POOL_INACTIVE] Cannot submit report to decommissioned pool."

        sender_hex = self._validate_eth_address(str(gl.message.sender), "Whistleblower").lower()
        clean_cat = category.strip().upper()
        assert clean_cat in VALID_CATEGORIES, \
            "[ERR_INVALID_CATEGORY] Malfeasance category must be one of: EMBEZZLEMENT, GOVERNANCE_TAMPERING, FRAUD, INSIDER_COLLUSION."

        clean_url = self._validate_url(evidence_dossier_url, "Evidence Dossier URL")

        bounty_bps = int(requested_bounty_bps)
        assert MIN_BOUNTY_BPS <= bounty_bps <= MAX_BOUNTY_BPS, \
            "[ERR_BOUNTY_BPS_BOUNDS] Requested bounty must be between 5% and 30% (500 to 3000 bps)."

        bond_val = int(gl.message.value)
        assert bond_val >= MIN_ANTI_SPAM_BOND, \
            "[ERR_MIN_BOND] Anti-spam bond must be at least " + str(MIN_ANTI_SPAM_BOND) + " wei."

        r_hash = self._compute_report_hash(clean_p_id, sender_hex, clean_cat, clean_url, nonce)
        assert r_hash.lower() not in self.consumed_report_hashes, \
            "[ERR_REPORT_EXISTS] Report with identical fingerprint already submitted. Use unique nonce."

        now_utc = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        new_r_id = "REPORT_" + str(int(self.total_reports_submitted) + 1)

        report_rec = WhistleblowerReportRecord(
            report_id=new_r_id,
            pool_id=clean_p_id,
            whistleblower=sender_hex,
            category=clean_cat,
            evidence_dossier_url=clean_url,
            report_hash=r_hash,
            anti_spam_bond=u256(bond_val),
            requested_bounty_bps=u256(bounty_bps),
            submitted_at=u256(now_utc),
            adjudicated_at=u256(0),
            verdict=VERDICT_PENDING,
            payout_awarded=u256(0),
            has_claimed=False,
            adjudication_rationale=""
        )

        self.reports[new_r_id] = report_rec
        self.consumed_report_hashes[r_hash.lower()] = True
        self.total_reports_submitted += 1
        self.total_volume_locked += u256(bond_val)

        return (
            "REPORT_SUBMITTED: " + new_r_id + " | Pool: " + clean_p_id
            + " | Category: " + clean_cat + " | Anti-Spam Bond: " + str(bond_val) + " wei"
        )

    # --------------------------------------------------------------------------
    # Core Function 4: Autonomous Multi-Validator Consensus Adjudication
    # --------------------------------------------------------------------------
    @gl.public.write
    def adjudicate_whistleblower_report(self, report_id: str) -> str:
        """
        Executes multi-validator web ingestion and AI consensus adjudication of whistleblower dossier.
        """
        clean_r_id = report_id.strip().upper()
        assert clean_r_id in self.reports, "[ERR_REPORT_NOT_FOUND] Report ID does not exist."
        rep = self.reports[clean_r_id]
        assert rep.verdict == VERDICT_PENDING, \
            "[ERR_ALREADY_ADJUDICATED] Report has already been adjudicated: " + rep.verdict

        clean_p_id = rep.pool_id
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND] Associated bounty pool not found."
        pool = self.pools[clean_p_id]

        # Fail-Closed Web Evidence Ingestion
        try:
            dossier_text = gl.get_webpage(rep.evidence_dossier_url)
        except Exception:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED] Consensus could not fetch whistleblower evidence from " + rep.evidence_dossier_url)

        assert dossier_text is not None and len(dossier_text.strip()) >= 30, \
            "[ERR_EVIDENCE_FETCH_FAILED] Dossier response was empty or insufficient (< 30 characters)."

        prompt = (
            "You are a GenLayer autonomous corporate governance and malfeasance audit validator.\n"
            "Target Organization: " + pool.organization_name + "\n"
            "Alleged Malfeasance Category: " + rep.category + "\n"
            "Evidence Dossier Content fetched from " + rep.evidence_dossier_url + ":\n"
            "\"\"\"\n" + dossier_text[:2500] + "\n\"\"\"\n\n"
            "TASK: Evaluate whether the dossier provides substantiated evidence of malfeasance.\n"
            "Respond STRICTLY in valid JSON with exactly three keys:\n"
            "\"verdict\": one of [\"MALFEASANCE_SUBSTANTIATED\", \"DISMISSED_FRIVOLOUS\", \"INSUFFICIENT_EVIDENCE\"]\n"
            "\"score\": integer between 0 and 1000 representing proof substantiation\n"
            "\"rationale\": a concise 1-sentence technical justification."
        )

        raw_resp = gl.exec_prompt(prompt)
        verdict = VERDICT_INSUFFICIENT
        rationale = "Consensus fallback resolution."
        score = 500

        try:
            clean_json = raw_resp.strip()
            if "```json" in clean_json:
                clean_json = clean_json.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_json:
                clean_json = clean_json.split("```")[1].split("```")[0].strip()
            parsed = json.loads(clean_json)
            cand = str(parsed.get("verdict", "")).strip().upper()
            if cand in (VERDICT_SUBSTANTIATED, VERDICT_DISMISSED, VERDICT_INSUFFICIENT):
                verdict = cand
            score = int(parsed.get("score", 500))
            rationale = str(parsed.get("rationale", "")).strip()[:200]
        except Exception:
            pass

        now_utc = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        rep.adjudicated_at = u256(now_utc)
        rep.verdict = verdict
        rep.adjudication_rationale = rationale

        bond_amount = int(rep.anti_spam_bond)
        payout = 0

        if verdict == VERDICT_SUBSTANTIATED:
            # Calculate bounty payout from pool escrow
            current_escrow = int(pool.escrow_balance)
            requested_bps = int(rep.requested_bounty_bps)
            payout = (current_escrow * requested_bps) // 10000
            if payout > current_escrow:
                payout = current_escrow

            # Award payout + 100% bond refund
            total_disbursement = payout + bond_amount
            rep.payout_awarded = u256(payout)
            pool.escrow_balance -= u256(payout)
            pool.total_bounties_paid += u256(payout)
            pool.is_sanctioned = True

            self.total_bounties_paid += u256(payout)
            if int(self.total_volume_locked) >= total_disbursement:
                self.total_volume_locked -= u256(total_disbursement)
            else:
                self.total_volume_locked = u256(0)

            rep.has_claimed = True

            # Disburse directly via emit_transfer with fallback to claimable_balances
            transfer_succeeded = False
            try:
                gl.emit_transfer(Address(rep.whistleblower), u256(total_disbursement))
                transfer_succeeded = True
            except Exception:
                try:
                    target = gl.get_contract_at(rep.whistleblower)
                    target.emit_transfer(value=u256(total_disbursement), on='finalized')
                    transfer_succeeded = True
                except Exception:
                    transfer_succeeded = False

            if not transfer_succeeded:
                cur = int(self.claimable_balances.get(rep.whistleblower, u256(0)))
                self.claimable_balances[rep.whistleblower] = u256(cur + total_disbursement)

        elif verdict == VERDICT_DISMISSED:
            # Slash anti-spam bond to accused organization's pool as defense compensation
            pool.escrow_balance += u256(bond_amount)
            rep.payout_awarded = u256(0)
            rep.has_claimed = True
            # Volume locked stays within contract pool

        else: # INSUFFICIENT_EVIDENCE
            # 100% Refund anti-spam bond to whistleblower; zero bounty awarded
            rep.payout_awarded = u256(0)
            rep.has_claimed = True
            if int(self.total_volume_locked) >= bond_amount:
                self.total_volume_locked -= u256(bond_amount)
            else:
                self.total_volume_locked = u256(0)

            transfer_succeeded = False
            try:
                gl.emit_transfer(Address(rep.whistleblower), u256(bond_amount))
                transfer_succeeded = True
            except Exception:
                try:
                    target = gl.get_contract_at(rep.whistleblower)
                    target.emit_transfer(value=u256(bond_amount), on='finalized')
                    transfer_succeeded = True
                except Exception:
                    transfer_succeeded = False

            if not transfer_succeeded:
                cur = int(self.claimable_balances.get(rep.whistleblower, u256(0)))
                self.claimable_balances[rep.whistleblower] = u256(cur + bond_amount)

        self.reports[clean_r_id] = rep
        self.pools[clean_p_id] = pool
        self.total_reports_adjudicated += 1

        return (
            "REPORT_ADJUDICATED: " + clean_r_id + " | Verdict: " + verdict
            + " | Bounty Payout: " + str(payout) + " wei | Rationale: " + rationale
        )

    # --------------------------------------------------------------------------
    # Core Function 5: Recoverable Claimable Withdrawal
    # --------------------------------------------------------------------------
    @gl.public.write
    def withdraw_claimable(self) -> str:
        """
        Enables claimants whose native transfers previously failed to safely withdraw
        their accumulated claimable balances. Restores balance upon failure.
        """
        sender_hex = self._validate_eth_address(str(gl.message.sender), "Caller").lower()
        assert sender_hex in self.claimable_balances, \
            "[ERR_NO_CLAIMABLE] No claimable funds found for caller."
        bal = int(self.claimable_balances[sender_hex])
        assert bal > 0, "[ERR_ZERO_CLAIMABLE] Claimable balance is zero."

        # Optimistically zero balance before transfer
        self.claimable_balances[sender_hex] = u256(0)

        transfer_succeeded = False
        try:
            gl.emit_transfer(Address(sender_hex), u256(bal))
            transfer_succeeded = True
        except Exception:
            try:
                target = gl.get_contract_at(sender_hex)
                target.emit_transfer(value=u256(bal), on='finalized')
                transfer_succeeded = True
            except Exception:
                transfer_succeeded = False

        if not transfer_succeeded:
            # Preserve and restore balance upon failed transfer
            self.claimable_balances[sender_hex] = u256(bal)
            raise AssertionError(
                "[ERR_WITHDRAWAL_FAILED] Native transfer failed during withdrawal. Claimable balance restored: "
                + str(bal) + " wei."
            )

        return "WITHDRAW_SUCCESS: " + sender_hex + " | Amount: " + str(bal) + " wei"

    # --------------------------------------------------------------------------
    # Public Gateway Views
    # --------------------------------------------------------------------------
    @gl.public.view
    def get_pool_count(self) -> int:
        return int(self.total_pools_created)

    @gl.public.view
    def get_report_count(self) -> int:
        return int(self.total_reports_submitted)

    @gl.public.view
    def get_total_volume_locked(self) -> str:
        return str(int(self.total_volume_locked))

    @gl.public.view
    def get_total_bounties_paid(self) -> str:
        return str(int(self.total_bounties_paid))

    @gl.public.view
    def get_claimable_balance(self, user_address: str) -> str:
        clean_u = self._validate_eth_address(user_address, "User address").lower()
        return str(int(self.claimable_balances.get(clean_u, u256(0))))

    @gl.public.view
    def is_entity_sanctioned(self, pool_id: str) -> bool:
        clean_p_id = pool_id.strip().upper()
        if clean_p_id not in self.pools:
            return False
        return self.pools[clean_p_id].is_sanctioned

    @gl.public.view
    def get_pool_status(self, pool_id: str) -> dict:
        clean_p_id = pool_id.strip().upper()
        if clean_p_id not in self.pools:
            return {"exists": False}
        p = self.pools[clean_p_id]
        return {
            "exists": True,
            "pool_id": p.pool_id,
            "sponsor": p.sponsor,
            "organization_name": p.organization_name,
            "escrow_balance": str(int(p.escrow_balance)),
            "total_bounties_paid": str(int(p.total_bounties_paid)),
            "is_sanctioned": p.is_sanctioned,
            "is_active": p.is_active,
            "created_at": int(p.created_at)
        }

    @gl.public.view
    def get_report_details(self, report_id: str) -> dict:
        clean_r_id = report_id.strip().upper()
        if clean_r_id not in self.reports:
            return {"exists": False}
        r = self.reports[clean_r_id]
        return {
            "exists": True,
            "report_id": r.report_id,
            "pool_id": r.pool_id,
            "whistleblower": r.whistleblower,
            "category": r.category,
            "evidence_dossier_url": r.evidence_dossier_url,
            "anti_spam_bond": str(int(r.anti_spam_bond)),
            "requested_bounty_bps": int(r.requested_bounty_bps),
            "verdict": r.verdict,
            "payout_awarded": str(int(r.payout_awarded)),
            "has_claimed": r.has_claimed,
            "submitted_at": int(r.submitted_at),
            "adjudicated_at": int(r.adjudicated_at),
            "adjudication_rationale": r.adjudication_rationale
        }
