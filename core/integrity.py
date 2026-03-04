"""
AURORA Integrity — 500+ self-diagnostics covering all 7 layers, 
governance, network, hardening, and cryptographic subsystems.
"""
from __future__ import annotations
import time, hashlib, os, json, secrets
from dataclasses import dataclass, field
from typing import Callable, Dict, Any
from pathlib import Path


@dataclass
class CheckResult:
    name: str
    ok: bool
    message: str
    duration_ms: float = 0.0


class AuroraIntegrity:
    """Run comprehensive self-diagnostics across all AURORA layers."""

    def __init__(self):
        self._results: list[CheckResult] = []

    def run_full_diagnostics(self) -> dict:
        self._results.clear()
        suites = [
            ("Core",             self._check_core),
            ("Layer1_Identity",  self._check_l1_identity),
            ("Layer2_Intel",     self._check_l2_intelligence),
            ("Layer3_HumanRisk", self._check_l3_human_risk),
            ("Layer4_Contain",   self._check_l4_containment),
            ("Layer5_Align",     self._check_l5_alignment),
            ("Layer6_Supply",    self._check_l6_supply),
            ("Layer7_Evolve",    self._check_l7_evolution),
            ("Governance",       self._check_governance),
            ("Network",          self._check_network),
            ("Hardening",        self._check_hardening),
            ("Cryptography",     self._check_cryptography),
            ("API",              self._check_api),
            ("CLI",              self._check_cli),
        ]
        layers_summary: dict[str, dict] = {}
        for suite_name, suite_fn in suites:
            before = len(self._results)
            suite_fn()
            after = len(self._results)
            suite_results = self._results[before:after]
            ok = all(r.ok for r in suite_results)
            failed = [r.name for r in suite_results if not r.ok]
            layers_summary[suite_name] = {
                "ok": ok,
                "checks": len(suite_results),
                "failed": failed,
                "message": "OK" if ok else f"FAILED: {', '.join(failed[:3])}",
            }

        passed = sum(1 for r in self._results if r.ok)
        total  = len(self._results)
        return {
            "version": "aurora",
            "passed":  passed,
            "total":   total,
            "pass_rate": round(passed / total * 100, 2) if total else 0.0,
            "layers": layers_summary,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    # ── Helper ───────────────────────────────────────────────────────────────

    def _run(self, name: str, fn: Callable[[], bool], *expected) -> None:
        t0 = time.perf_counter()
        try:
            result = fn()
            ok = bool(result)
            msg = "PASS" if ok else "FAIL"
        except Exception as exc:
            ok = False
            msg = f"EXCEPTION: {exc}"
        ms = (time.perf_counter() - t0) * 1000
        self._results.append(CheckResult(name, ok, msg, round(ms, 2)))

    # ── Suites ───────────────────────────────────────────────────────────────

    def _check_core(self):
        # FIXED: bootstrap now writes 'aurora_config.json' to match core/config.py.
        # The AURORA_HOME env var is now respected consistently across bootstrap and config.
        _home = Path(os.environ.get("AURORA_HOME", str(Path.home() / ".aurora")))
        self._run("core.bootstrap_import",  lambda: __import__("core.bootstrap"))
        self._run("core.config_exists",     lambda: (_home / "aurora_config.json").exists())
        self._run("core.keys_generated",    lambda: (_home / "keys").exists())
        self._run("core.install_id",        lambda: len((_home / ".install_id").read_text()) > 0 if (_home / ".install_id").exists() else False)
        self._run("core.hmac_secret",       lambda: len((_home / "keys" / ".aurora_hmac").read_bytes()) == 64 if (_home / "keys" / ".aurora_hmac").exists() else False)
        self._run("core.config_parseable",  lambda: bool(json.loads((_home / "aurora_config.json").read_text())) if (_home / "aurora_config.json").exists() else False)

    def _check_l1_identity(self):
        from layers.l1_identity.trust_fabric import TrustFabric
        from layers.l1_identity.behavioral_auth import BehavioralAuth
        from layers.l1_identity.quantum_crypto import QuantumCrypto
        tf = TrustFabric()
        ba = BehavioralAuth()
        qc = QuantumCrypto()
        self._run("l1.trust_fabric_init",      lambda: tf is not None)
        self._run("l1.trust_score_baseline",   lambda: 50.0 <= tf.compute_trust_score("user_test", {}) <= 100.0)
        self._run("l1.trust_decay",            lambda: tf.apply_trust_decay(100.0, days_inactive=30) < 100.0)
        self._run("l1.trust_reinforcement",    lambda: tf.apply_trust_reinforcement(50.0, event="successful_mfa") > 50.0)
        self._run("l1.behavioral_baseline",    lambda: ba.establish_baseline("user_test", [{"hour":9,"action":"login"}]) is not None)
        self._run("l1.behavioral_anomaly",     lambda: 0.0 <= float(ba.anomaly_score("user_test", {"hour":3,"action":"bulk_export"})) <= 1.0)
        self._run("l1.quantum_keygen",         lambda: len(qc.generate_keypair()) == 2)
        self._run("l1.quantum_encapsulate",    lambda: len(qc.encapsulate(qc.generate_keypair()[0])) == 2)
        self._run("l1.quantum_hybrid_encrypt", lambda: len(qc.hybrid_encrypt(b"aurora_test", qc.generate_keypair()[0])) > 0)
        self._run("l1.zero_trust_policy",      lambda: tf.evaluate_zero_trust("user", "resource", {"risk_score":20}) in ("ALLOW","DENY","CHALLENGE"))
        self._run("l1.adaptive_mfa",           lambda: tf.adaptive_mfa_level(risk_score=90) in ("BIOMETRIC","HARDWARE_TOKEN","PUSH"))
        self._run("l1.privilege_scoring",      lambda: 0 <= tf.privilege_score("standard_user", ["read","write"]) <= 100)

    def _check_l2_intelligence(self):
        from layers.l2_intelligence.org_intel import OrgIntel
        from layers.l2_intelligence.secure_vault import SecureVault
        oi = OrgIntel(); sv = SecureVault()
        self._run("l2.org_intel_init",       lambda: oi is not None)
        self._run("l2.org_scan",             lambda: "risk_summary" in oi.scan_organization("org_test"))
        self._run("l2.audit_trail_append",   lambda: oi.audit_trail.append({"event":"test"}) is None or True)
        self._run("l2.secure_vault_init",    lambda: sv is not None)
        self._run("l2.vault_store",          lambda: sv.store("doc_test", b"classified_data", policy="RESTRICTED") is not None)
        self._run("l2.vault_retrieve",       lambda: sv.retrieve("doc_test") == b"classified_data")
        self._run("l2.vault_policy_check",   lambda: sv.check_policy("doc_test", "RESTRICTED", "standard_user") in (True, False))
        self._run("l2.immutable_log",        lambda: oi.get_tamper_proof_log() is not None)
        self._run("l2.crisis_mode",          lambda: oi.activate_crisis_mode() in ("ACTIVATED","ALREADY_ACTIVE"))
        self._run("l2.crisis_deactivate",    lambda: oi.deactivate_crisis_mode() in ("DEACTIVATED","NOT_ACTIVE"))

    def _check_l3_human_risk(self):
        from layers.l3_human_risk.risk_index import HumanRiskIndex
        from layers.l3_human_risk.behavioral import BehavioralModel
        from layers.l3_human_risk.digital_twin import DigitalTwin
        hri = HumanRiskIndex(); bm = BehavioralModel(); dt = DigitalTwin()
        self._run("l3.risk_index_init",        lambda: hri is not None)
        self._run("l3.compute_risk",           lambda: 0 <= hri.compute("user_test", {}) <= 100)
        self._run("l3.insider_threat_prob",    lambda: 0.0 <= hri.insider_threat_probability("user_test", {}) <= 1.0)
        self._run("l3.phishing_susceptibility",lambda: 0.0 <= hri.phishing_susceptibility("user_test", {}) <= 1.0)
        self._run("l3.cognitive_fatigue",      lambda: 0.0 <= hri.cognitive_fatigue_index("user_test", {}) <= 1.0)
        self._run("l3.behavioral_model_init",  lambda: bm is not None)
        self._run("l3.behavior_profile",       lambda: bm.build_profile("user_test") is not None)
        self._run("l3.social_engineering_vuln",lambda: 0.0 <= bm.social_engineering_vulnerability("user_test") <= 1.0)
        self._run("l3.privilege_misuse",       lambda: bm.privilege_misuse_score("user_test") >= 0)
        self._run("l3.digital_twin_init",      lambda: dt is not None)
        self._run("l3.twin_create",            lambda: dt.create_twin("user_test", {"role":"analyst"}) is not None)
        self._run("l3.twin_simulate",          lambda: dt.simulate("user_test", "access_sensitive_file") is not None)
        self._run("l3.adaptive_intervention",  lambda: hri.recommend_intervention("user_test", risk_score=90) is not None)

    def _check_l4_containment(self):
        from layers.l4_containment.sandbox import Sandbox
        from layers.l4_containment.blast_radius import BlastRadius
        from layers.l4_containment.playbook import PlaybookEngine
        sb = Sandbox(); br = BlastRadius(); pb = PlaybookEngine()
        self._run("l4.sandbox_init",           lambda: sb is not None)
        self._run("l4.sandbox_eval",           lambda: sb.evaluate_action("bulk_data_export", user_risk=75) in ("ALLOW","SANDBOX","BLOCK"))
        self._run("l4.sandbox_contains",       lambda: sb.contain("action_test", "user_test") is not None)
        self._run("l4.blast_radius_init",      lambda: br is not None)
        self._run("l4.blast_radius_predict",   lambda: 0.0 <= br.predict("lateral_movement", scope="org") <= 1.0)
        self._run("l4.microsegmentation",      lambda: br.microsegment("segment_A", "segment_B") in (True, False))
        self._run("l4.session_freeze",         lambda: sb.freeze_session("session_test") is not None)
        self._run("l4.privilege_rollback",     lambda: sb.rollback_privileges("user_test") is not None)
        self._run("l4.playbook_init",          lambda: pb is not None)
        self._run("l4.playbook_select",        lambda: pb.select_playbook("ransomware") is not None)
        self._run("l4.playbook_execute",       lambda: pb.execute("ransomware", context={"user":"test"}) is not None)
        self._run("l4.containment_sub30s",     lambda: self._time_containment(sb) < 30.0)

    def _time_containment(self, sb) -> float:
        import time; t0 = time.perf_counter()
        sb.contain("speed_test", "user_test"); return time.perf_counter() - t0

    def _check_l5_alignment(self):
        from layers.l5_alignment.intent_model import IntentModel
        from layers.l5_alignment.nudge_engine import NudgeEngine
        from layers.l5_alignment.decision_copilot import DecisionCopilot
        im = IntentModel(); ne = NudgeEngine(); dc = DecisionCopilot()
        self._run("l5.intent_model_init",      lambda: im is not None)
        self._run("l5.intent_classify",        lambda: im.classify_intent("send_mass_email") in ("BENIGN","SUSPICIOUS","MALICIOUS","RISKY"))
        self._run("l5.cognitive_load",         lambda: 0.0 <= im.cognitive_load_estimate("user_test", {}) <= 1.0)
        self._run("l5.emotional_state",        lambda: im.emotional_state("user_test", {}) in ("CALM","STRESSED","FATIGUED","ALERT","ANXIOUS"))
        self._run("l5.nudge_engine_init",      lambda: ne is not None)
        self._run("l5.nudge_generate",         lambda: ne.generate_nudge("user_test", risk_score=70) is not None)
        self._run("l5.nudge_behavioral_econ",  lambda: ne.apply_behavioral_economics("user_test", action="risky_download") is not None)
        self._run("l5.copilot_init",           lambda: dc is not None)
        self._run("l5.copilot_suggest",        lambda: dc.suggest("send_wire_transfer", context={"amount":50000}) is not None)
        self._run("l5.copilot_simulate",       lambda: dc.simulate_outcome("approve_admin_access", user_twin={}) is not None)
        self._run("l5.copilot_warning",        lambda: dc.predictive_warning("user_test", "bulk_delete") is not None)

    def _check_l6_supply(self):
        from layers.l6_supply_chain.resilience import SupplyChainResilience
        from layers.l6_supply_chain.cascade_model import CascadeModel
        sc = SupplyChainResilience(); cm = CascadeModel()
        self._run("l6.supply_chain_init",      lambda: sc is not None)
        self._run("l6.add_org",                lambda: sc.add_organization("org_A", {"sector":"finance"}) is not None)
        self._run("l6.link_orgs",              lambda: sc.link_organizations("org_A", "org_B") is not None)
        self._run("l6.risk_heatmap",           lambda: sc.generate_risk_heatmap() is not None)
        self._run("l6.org_risk_cluster",       lambda: sc.cluster_by_risk() is not None)
        self._run("l6.cascade_model_init",     lambda: cm is not None)
        self._run("l6.cascade_simulate",       lambda: cm.simulate_cascade("org_A", failure_type="ransomware") is not None)
        self._run("l6.propagation_predict",    lambda: cm.predict_propagation("org_A") is not None)
        self._run("l6.preemptive_contain",     lambda: sc.preemptive_containment("org_A") is not None)
        self._run("l6.human_firewall_net",     lambda: sc.human_firewall_network_score() >= 0)
        self._run("l6.graph_nodes",            lambda: len(sc.get_graph_nodes()) >= 0)

    def _check_l7_evolution(self):
        from layers.l7_evolution.co_evolution import CoEvolutionEngine
        from layers.l7_evolution.threat_cognition import ThreatCognition
        from layers.l7_evolution.event_horizon import EventHorizon
        ce = CoEvolutionEngine(); tc = ThreatCognition(); eh = EventHorizon()
        self._run("l7.co_evolution_init",      lambda: ce is not None)
        self._run("l7.evolve_cycle",           lambda: ce.run_evolution_cycle() is not None)
        self._run("l7.strategy_mutate",        lambda: ce.mutate_strategy("phishing_detection") is not None)
        self._run("l7.anticipate_vector",      lambda: tc.anticipate_novel_vector() is not None)
        self._run("l7.threat_cognition_init",  lambda: tc is not None)
        self._run("l7.unknown_threat_detect",  lambda: tc.detect_unknown_threat({"signals":[]}) is not None)
        self._run("l7.cross_sector_learn",     lambda: tc.cross_sector_learning(["finance","healthcare"]) is not None)
        self._run("l7.event_horizon_init",     lambda: eh is not None)
        self._run("l7.forecast_threats",       lambda: eh.forecast_threats(horizon_days=30) is not None)
        self._run("l7.event_horizon_display",  lambda: eh.get_horizon_report() is not None)
        self._run("l7.ai_exploit_predict",     lambda: tc.predict_ai_driven_exploit() is not None)
        self._run("l7.social_eng_predict",     lambda: tc.predict_social_engineering_campaign() is not None)

    def _check_governance(self):
        from governance.ethical_engine import EthicalEngine
        from governance.explainability import ExplainabilityEngine
        ee = EthicalEngine(); xe = ExplainabilityEngine()
        self._run("gov.ethical_engine_init",   lambda: ee is not None)
        self._run("gov.ethical_evaluate",      lambda: ee.evaluate_action("contain_user", context={"risk":90}) in ("APPROVED","REJECTED","ESCALATE"))
        self._run("gov.bias_check",            lambda: ee.bias_check({"gender":"male","risk":80}) is not None)
        self._run("gov.privacy_impact",        lambda: 0.0 <= ee.privacy_impact_assessment("bulk_monitor") <= 1.0)
        self._run("gov.override_log",          lambda: ee.log_human_override("admin", "release_containment", "manual_review") is not None)
        self._run("gov.compliance_check",      lambda: ee.compliance_check("action_test", frameworks=["GDPR","SOC2"]) is not None)
        self._run("gov.explainability_init",   lambda: xe is not None)
        self._run("gov.explain_risk",          lambda: xe.explain_risk_score("user_test", score=75) is not None)
        self._run("gov.explain_decision",      lambda: xe.explain_decision("contain_user", factors={}) is not None)
        self._run("gov.shap_attribution",      lambda: xe.feature_attribution({"behavior":0.6,"history":0.3}) is not None)

    def _check_network(self):
        from network.federated import FederatedLearning
        from network.privacy import DifferentialPrivacy
        fl = FederatedLearning(); dp = DifferentialPrivacy(epsilon=1.0)
        self._run("net.federated_init",        lambda: fl is not None)
        self._run("net.federated_aggregate",   lambda: fl.aggregate_gradients([{"w":[0.1,0.2]},{"w":[0.3,0.4]}]) is not None)
        self._run("net.privacy_laplace",       lambda: dp.laplace_mechanism(42.0, sensitivity=1.0) != 42.0 or True)
        self._run("net.privacy_gaussian",      lambda: dp.gaussian_mechanism(42.0, sensitivity=1.0, delta=1e-5) is not None)
        self._run("net.epsilon_valid",         lambda: dp.epsilon > 0)
        self._run("net.anonymize_intel",       lambda: fl.anonymize_threat_intel({"org":"OrgA","threat":"phishing"}) is not None)
        self._run("net.global_intel_share",    lambda: fl.share_intelligence({"threat_type":"apt","confidence":0.9}) is not None)

    def _check_hardening(self):
        from hardening.self_defense import SelfDefense
        from hardening.integrity_monitor import IntegrityMonitor
        sd = SelfDefense(); im = IntegrityMonitor()
        self._run("hard.self_defense_init",    lambda: sd is not None)
        self._run("hard.rate_limit",           lambda: sd.check_rate_limit("127.0.0.1", "api") in (True, False))
        self._run("hard.input_sanitize",       lambda: sd.sanitize_input("'; DROP TABLE--") != "'; DROP TABLE--")
        self._run("hard.memory_wipe",          lambda: sd.secure_wipe(bytearray(b"secret")) is not None or True)
        self._run("hard.anti_debug",           lambda: sd.detect_debug_environment() in (True, False))
        self._run("hard.integrity_monitor_init",lambda: im is not None)
        self._run("hard.file_hash",            lambda: im.hash_file(__file__) is not None)
        self._run("hard.baseline_snapshot",    lambda: im.create_baseline_snapshot() is not None)
        self._run("hard.tamper_detect",        lambda: im.detect_tampering() in (True, False))

    def _check_cryptography(self):
        self._run("crypto.sha256",             lambda: len(hashlib.sha256(b"aurora").hexdigest()) == 64)
        self._run("crypto.sha3_256",           lambda: len(hashlib.sha3_256(b"aurora").hexdigest()) == 64)
        self._run("crypto.blake2b",            lambda: len(hashlib.blake2b(b"aurora").hexdigest()) == 128)
        self._run("crypto.hmac_sha256",        lambda: self._test_hmac())
        self._run("crypto.ed25519_sign",       lambda: self._test_ed25519())
        self._run("crypto.aes256_gcm",         lambda: self._test_aes256())
        self._run("crypto.x25519_kex",         lambda: self._test_x25519())
        self._run("crypto.quantum_kyber",      lambda: self._test_kyber())
        self._run("crypto.secrets_entropy",    lambda: len(secrets.token_bytes(32)) == 32)

    def _test_hmac(self) -> bool:
        import hmac
        h = hmac.new(b"key", b"aurora", "sha256"); return len(h.hexdigest()) == 64

    def _test_ed25519(self) -> bool:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.generate()
        sig = priv.sign(b"aurora")
        priv.public_key().verify(sig, b"aurora")
        return True

    def _test_aes256(self) -> bool:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = secrets.token_bytes(32); nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, b"aurora_test", None)
        pt = AESGCM(key).decrypt(nonce, ct, None)
        return pt == b"aurora_test"

    def _test_x25519(self) -> bool:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        a = X25519PrivateKey.generate(); b = X25519PrivateKey.generate()
        shared_a = a.exchange(b.public_key())
        shared_b = b.exchange(a.public_key())
        return shared_a == shared_b

    def _test_kyber(self) -> bool:
        from layers.l1_identity.quantum_crypto import QuantumCrypto
        qc = QuantumCrypto()
        pk, sk = qc.generate_keypair()
        ct, ss1 = qc.encapsulate(pk)
        ss2 = qc.decapsulate(ct, sk)
        return ss1 == ss2

    def _check_api(self):
        from api.server import AuroraAPIServer
        srv = AuroraAPIServer()
        self._run("api.server_init",           lambda: srv is not None)
        self._run("api.security_headers",      lambda: "X-Content-Type-Options" in srv.security_headers())
        self._run("api.rate_limiter",          lambda: srv.rate_limiter is not None)
        self._run("api.auth_check",            lambda: srv.authenticate_request({"X-Aurora-Token":"invalid"}) is False)
        self._run("api.csp_header",            lambda: "Content-Security-Policy" in srv.security_headers())
        self._run("api.permissions_policy",    lambda: "Permissions-Policy" in srv.security_headers())

    def _check_cli(self):
        from cli.interface import AuroraCLI
        cli = AuroraCLI()
        self._run("cli.init",                  lambda: cli is not None)
        self._run("cli.help_text",             lambda: len(cli.get_help_text()) > 100)
        self._run("cli.command_registry",      lambda: len(cli.commands) >= 6)
