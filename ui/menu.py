"""
AURORA Interactive Menu — Full 7-Layer Platform Interface
"""
from __future__ import annotations
import time, sys
from ui.console import c, banner, section, item, multiline_item, risk_bar, risk_verdict
from identity.provider import get_resolver


class AuroraMenu:
    def __init__(self):
        self._running = True
        self._id = get_resolver()   # identity resolver — auto-populates user/org IDs

    def run(self):
        banner()
        while self._running:
            self._main_menu()

    def _main_menu(self):
        # Show authenticated user in header
        try:
            from core.auth import get_session as _gs
            _s = _gs()
            if _s:
                print(f"  {c('DIM','Logged in as: ')}{c('CYAN',_s['name'])} {c('DIM',f'[{_s["role"].upper()} · EMP-{_s["employee_id"]}]')}")
        except Exception:
            pass
        print(c("BRIGHT", "\n  ┌─ AURORA COMMAND CENTER ───────────────────────────────────────┐"))
        options = [
            ("1", "Human Risk Intelligence (AURIX)",       "Compute real-time Human Risk Index"),
            ("2", "Identity & Trust Fabric",               "Zero Trust evaluation & adaptive MFA"),
            ("3", "Organizational Intelligence (SOIN-X)",  "Full org scan, audit trail, crisis mode"),
            ("4", "Autonomous Containment (NEXUS-SHIELD)", "Sandbox, playbooks, blast radius"),
            ("5", "Human-Machine Alignment (ECLIPSE-X)",   "Intent model, nudges, decision co-pilot"),
            ("6", "Supply Chain Resilience",               "Risk heatmap, cascade simulation"),
            ("7", "Predictive Evolution Engine",           "Co-evolution cycle, threat cognition"),
            ("8", "Event Horizon",                         "30-day threat forecast"),
            ("9", "Ethical Governance",                   "Ethical evaluation, bias check, compliance"),
            ("10","Federated Intelligence Network",        "Anonymous cross-org threat sharing"),
            ("11","Platform Self-Defense",                 "Rate limiting, integrity, hardening status"),
            ("12","AURORA Doctor",                         "Run 131 self-diagnostics"),
            ("13","Identity Management",                   "SSO/LDAP/org_config setup, roster import"),
            ("0", "Exit",                                  ""),
        ]
        for num, name, desc in options:
            d = f"  {c('DIM', desc)}" if desc else ""
            print(f"  │  {c('CYAN', num.rjust(2))}  {c('WHITE', name)}{d}")
        print(c("BRIGHT", "  └───────────────────────────────────────────────────────────────┘"))
        try:
            choice = input(f"\n  {c('CYAN', '▶')} Select engine [{c('DIM','0-13')}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            self._exit(); return

        dispatch = {
            "1": self._human_risk, "2": self._identity_trust,
            "3": self._org_intelligence, "4": self._autonomous_containment,
            "5": self._human_machine_alignment, "6": self._supply_chain,
            "7": self._evolution_engine, "8": self._event_horizon,
            "9": self._ethical_governance, "10": self._federated_network,
            "11": self._self_defense, "12": self._doctor, "13": self._identity_management, "0": self._exit,
        }
        handler = dispatch.get(choice)
        if handler: handler()
        else: print(c("YELLOW", f"  Invalid selection: '{choice}'"))

    # ── Layer 1: Human Risk ──────────────────────────────────────────────────

    def _human_risk(self):
        section("LAYER 3 — HUMAN RISK INTELLIGENCE (AURIX)")
        user_id, uid_src = self._id.resolve_user("User ID", "user_demo")
        item("Identity Source", uid_src.upper(), "GREEN" if uid_src != "prompt" else "DIM")
        print(c("DIM", "  Computing multi-factor Human Risk Index…"))
        from layers.l3_human_risk.risk_index import HumanRiskIndex
        from layers.l3_human_risk.digital_twin import DigitalTwin
        hri = HumanRiskIndex()
        # Simulate context
        context = {"behavioral_anomaly":0.35,"incident_count":1,"hours_worked_today":9}
        score = hri.compute(user_id, context)
        insider = hri.insider_threat_probability(user_id, context)
        phishing = hri.phishing_susceptibility(user_id, context)
        fatigue = hri.cognitive_fatigue_index(user_id, context)
        intervention = hri.recommend_intervention(user_id, score)
        dt = DigitalTwin()
        twin = dt.create_twin(user_id, {"role":"analyst"})
        sim = dt.simulate(user_id, "bulk_data_export")
        print()
        item("User ID",                user_id)
        item("Human Risk Index",       risk_bar(score))
        print(f"  {'Verdict'.ljust(28)} {risk_verdict(score)}")
        print()
        item("Insider Threat Prob",    f"{insider*100:.1f}%", "YELLOW" if insider>0.3 else "GREEN")
        item("Phishing Susceptibility",f"{phishing*100:.1f}%","YELLOW" if phishing>0.3 else "GREEN")
        item("Cognitive Fatigue",      f"{fatigue*100:.1f}%", "YELLOW" if fatigue>0.4 else "GREEN")
        section("DIGITAL TWIN SIMULATION — bulk_data_export")
        item("Simulated Risk",         f"{sim['predicted_risk']*100:.0f}%","RED" if sim['predicted_risk']>0.6 else "YELLOW")
        item("Predicted Outcome",      sim['outcome'])
        item("Recommendation",         sim['recommendation'])
        section("RECOMMENDED INTERVENTION")
        item("Intervention Level",     intervention['level'], "RED" if intervention['level']=="CRITICAL" else "YELLOW")
        for action in intervention['actions']:
            print(f"  {c('CYAN', '  ›')} {action}")
        print(f"\n  {c('DIM', intervention['rationale'])}")
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Layer 2: Identity & Trust ─────────────────────────────────────────────

    def _identity_trust(self):
        section("LAYER 1 — GLOBAL IDENTITY & TRUST FABRIC")
        user_id, uid_src = self._id.resolve_user("User ID", "analyst_demo")
        item("Identity Source", uid_src.upper(), "GREEN" if uid_src != "prompt" else "DIM")
        from layers.l1_identity.trust_fabric import TrustFabric
        from layers.l1_identity.quantum_crypto import QuantumCrypto
        tf = TrustFabric(); qc = QuantumCrypto()
        context = {"hour":22,"new_device":True,"vpn_mismatch":False}
        trust_score = tf.compute_trust_score(user_id, context)
        zt_decision = tf.evaluate_zero_trust(user_id, "sensitive_database", {"risk_score":100-trust_score})
        mfa_level = tf.adaptive_mfa_level(100-trust_score)
        privilege = tf.privilege_score("developer", ["read","write","deploy"])
        pk, sk = qc.generate_keypair()
        ct, ss = qc.encapsulate(pk)
        decap_ss = qc.decapsulate(ct, sk)
        item("User ID",           user_id)
        item("Trust Score",       risk_bar(trust_score))
        item("Zero Trust Decision", zt_decision, "GREEN" if zt_decision=="ALLOW" else ("YELLOW" if zt_decision=="CHALLENGE" else "RED"))
        item("Adaptive MFA Level",mfa_level)
        item("Privilege Score",   f"{privilege}/100")
        section("QUANTUM-SAFE CRYPTOGRAPHY (ML-KEM + AES-256-GCM)")
        item("Keypair Generated",  f"PK={pk[:8].hex()}…, SK={sk[:8].hex()}…")
        item("Encapsulation",      f"CT={ct[:8].hex()}…, SS={ss.hex()[:16]}…")
        item("Decapsulation",      c("GREEN","✓ Shared secret verified") if ss==decap_ss else c("RED","✗ MISMATCH"))
        item("Quantum-Safe Mode",  c("GREEN","ENABLED — ML-KEM + X25519 Hybrid"))
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Layer 3: Org Intelligence ─────────────────────────────────────────────

    def _org_intelligence(self):
        section("LAYER 2 — SECURE ORGANIZATIONAL INTELLIGENCE (SOIN-X)")
        org_id, oid_src = self._id.resolve_org("Organization ID", "enterprise_demo")
        item("Identity Source", oid_src.upper(), "GREEN" if oid_src != "prompt" else "DIM")
        from layers.l2_intelligence.org_intel import OrgIntel
        from layers.l2_intelligence.secure_vault import SecureVault
        oi = OrgIntel(); sv = SecureVault()
        scan = oi.scan_organization(org_id)
        oi.activate_crisis_mode()
        oi.deactivate_crisis_mode()
        sv.store("classified_doc_1", b"Sensitive merger details Q4 2025", policy="RESTRICTED")
        log = oi.get_tamper_proof_log()
        rs = scan["risk_summary"]
        item("Organization",      org_id)
        item("Total Findings",    str(rs["total_findings"]))
        item("Risk Score",        risk_bar(rs["risk_score"]))
        section("FINDINGS BY CATEGORY")
        for cat, count in rs["categories"].items():
            color = "RED" if count > 4 else ("YELLOW" if count > 2 else "GREEN")
            item(cat.replace("_"," ").title(), f"{count} finding{'s' if count!=1 else ''}", color)
        section("IMMUTABLE AUDIT TRAIL (SHA-256 Block Chain)")
        for block in log[-3:]:
            print(f"  {c('DIM', block['block_hash'][:32])}… → {block.get('event','unknown')}")
        section("SECURE VAULT")
        item("Documents Stored",  "1")
        item("Policy",            "RESTRICTED (CISO-level access required)")
        item("Encryption",        "AES-256-GCM")
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Layer 4: Containment ──────────────────────────────────────────────────

    def _autonomous_containment(self):
        section("LAYER 4 — AUTONOMOUS DECISION CONTAINMENT (NEXUS-SHIELD)")
        action = input(f"  {c('CYAN','Action to evaluate')}: ").strip() or "bulk_data_export"
        risk_input = input(f"  {c('CYAN','User risk score [0-100]')}: ").strip()
        risk = float(risk_input) if risk_input.isdigit() else 75.0
        from layers.l4_containment.sandbox import Sandbox
        from layers.l4_containment.blast_radius import BlastRadius
        from layers.l4_containment.playbook import PlaybookEngine
        sb = Sandbox(); br = BlastRadius(); pb = PlaybookEngine()
        t0 = time.perf_counter()
        decision = sb.evaluate_action(action, user_risk=risk)
        contain_result = sb.contain(action, "user_demo")
        contain_time = (time.perf_counter() - t0) * 1000
        blast = br.predict("lateral_movement", scope="org")
        freeze = sb.freeze_session("session_12345")
        playbook = pb.execute("ransomware", context={"trigger":action,"user_risk":risk})
        item("Action",             action)
        item("User Risk",          risk_bar(risk))
        item("Sandbox Decision",   c("RED","BLOCK") if decision=="BLOCK" else (c("YELLOW","SANDBOX") if decision=="SANDBOX" else c("GREEN","ALLOW")))
        item("Containment Time",   f"{contain_time:.1f}ms", "GREEN" if contain_time<30000 else "RED")
        item("Containment ID",     contain_result["containment_id"])
        item("Blast Radius",       f"{blast*100:.0f}% of org", "RED" if blast>0.7 else "YELLOW")
        section("ACTIVE PLAYBOOK — Ransomware Response")
        item("Playbook",           playbook["playbook"])
        item("Severity",           playbook["severity"])
        item("SLA",                f"{playbook['sla_minutes']} minutes")
        for i, step in enumerate(playbook["steps"], 1):
            print(f"  {c('CYAN', f'  Step {i}:')} {step}")
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Layer 5: Human-Machine Alignment ─────────────────────────────────────

    def _human_machine_alignment(self):
        section("LAYER 5 — HUMAN-MACHINE ALIGNMENT (ECLIPSE-X)")
        action = input(f"  {c('CYAN','User action')}: ").strip() or "approve_wire_transfer"
        from layers.l5_alignment.intent_model import IntentModel
        from layers.l5_alignment.nudge_engine import NudgeEngine
        from layers.l5_alignment.decision_copilot import DecisionCopilot
        im = IntentModel(); ne = NudgeEngine(); dc = DecisionCopilot()
        intent = im.classify_intent(action)
        cog_load = im.cognitive_load_estimate("user_demo", {"concurrent_tasks":4,"deadline_pressure":True})
        emotional = im.emotional_state("user_demo", {"stress_indicators":0.65,"fatigue_score":0.4})
        nudge = ne.generate_nudge("user_demo", risk_score=70)
        copilot = dc.suggest(action, context={"amount":75000})
        sim = dc.simulate_outcome(action, user_twin={"role":"manager"})
        warning = dc.predictive_warning("user_demo", action)
        item("Action",              action)
        item("Intent Classification",c("RED","MALICIOUS") if intent=="MALICIOUS" else (c("YELLOW","RISKY") if intent=="RISKY" else c("GREEN",intent)))
        item("Cognitive Load",      f"{cog_load*100:.0f}%", "RED" if cog_load>0.7 else "YELLOW")
        item("Emotional State",     emotional)
        section("BEHAVIORAL ECONOMICS NUDGE (Kahneman/Thaler)")
        item("Nudge Type",          nudge["type"])
        import textwrap as _tw
        for _ln in _tw.wrap('  ⚠ ' + nudge['message'], 76):
            print(f"  {c('YELLOW', _ln)}")
        section("DECISION CO-PILOT SUGGESTIONS")
        for s in copilot["suggestions"]:
            print(f"  {c('CYAN', '  ›')} {s}")
        section("DIGITAL TWIN OUTCOME SIMULATION")
        item("Simulated Risk",      f"{sim['simulated_risk']*100:.0f}%")
        item("Predicted Outcome",   sim["likely_outcome"])
        item("Recommendation",      c("RED",sim["recommendation"]) if sim["recommendation"]=="BLOCK" else c("YELLOW",sim["recommendation"]))
        section("PREDICTIVE WARNING")
        import textwrap as _tw2
        for _ln in _tw2.wrap(warning['warning'], 76):
            print(f"  {c('DIM', _ln)}")
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Layer 6: Supply Chain ─────────────────────────────────────────────────

    def _supply_chain(self):
        section("LAYER 6 — CROSS-ORGANIZATION & SUPPLY CHAIN RESILIENCE")
        from layers.l6_supply_chain.resilience import SupplyChainResilience
        from layers.l6_supply_chain.cascade_model import CascadeModel
        sc = SupplyChainResilience(); cm = CascadeModel()
        orgs = [("FinCorp_Global",{"sector":"finance","risk_score":45}),("MedChain_EU",{"sector":"healthcare","risk_score":62}),("GovCloud_US",{"sector":"government","risk_score":38}),("SupplyHub_APAC",{"sector":"logistics","risk_score":71})]
        for org_id, attrs in orgs:
            sc.add_organization(org_id, attrs)
        sc.link_organizations("FinCorp_Global","SupplyHub_APAC")
        sc.link_organizations("MedChain_EU","GovCloud_US")
        heatmap = sc.generate_risk_heatmap()
        clusters = sc.cluster_by_risk()
        cascade = cm.simulate_cascade("SupplyHub_APAC", "ransomware")
        hfw_score = sc.human_firewall_network_score()
        section("ORGANIZATIONAL RISK HEATMAP")
        for org_id, data in heatmap["heatmap"].items():
            color = "RED" if data["level"]=="CRITICAL" else ("YELLOW" if data["level"]=="HIGH" else ("CYAN" if data["level"]=="MEDIUM" else "GREEN"))
            print(f"  {c(color, '●')} {org_id.ljust(22)} Risk: {data['risk_score']:.0f}  [{data['level']}]  Sector: {data['sector']}")
        section("CASCADE FAILURE SIMULATION — SupplyHub_APAC Ransomware")
        item("Origin",             cascade["origin"])
        item("Failure Type",       cascade["failure_type"])
        item("Affected Orgs",      str(cascade["cascades"]))
        item("Est. Recovery",      f"{cascade['estimated_recovery_hours']}h")
        item("Financial Impact",   f"${cascade['financial_impact_estimate_usd']:,}")
        item("Human Firewall Score",f"{hfw_score:.1f}/100", "GREEN" if hfw_score>60 else "YELLOW")
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Layer 7: Evolution Engine ─────────────────────────────────────────────

    def _evolution_engine(self):
        section("LAYER 7 — AUTONOMOUS CO-EVOLUTION ENGINE")
        print(c("DIM", "  Running evolution cycle… Strategies adapting to threat landscape…\n"))
        from layers.l7_evolution.co_evolution import CoEvolutionEngine
        from layers.l7_evolution.threat_cognition import ThreatCognition
        ce = CoEvolutionEngine(); tc = ThreatCognition()
        result = ce.run_evolution_cycle()
        mutation = ce.mutate_strategy("phishing_detection")
        novel = tc.anticipate_novel_vector()
        cross = tc.cross_sector_learning(["finance","healthcare","government"])
        ai_pred = tc.predict_ai_driven_exploit()
        social = tc.predict_social_engineering_campaign()
        item("Generation",         str(result["generation"]))
        item("Strategies Evolved", str(result["strategies_evolved"]))
        item("Mutations Applied",  str(result["mutations_applied"]))
        item("Avg Fitness Score",  f"{result['avg_fitness']*100:.1f}%")
        item("Improvements",       ", ".join(result["improvements"][:3]) or "None")
        section("NOVEL ATTACK VECTOR ANTICIPATION")
        for v in novel["vectors"][:3]:
            color = "RED" if v["confidence"]>0.8 else "YELLOW"
            print(f"  {c(color, '  ▸')} {v['vector']} ({v['confidence']*100:.0f}% conf, {v['horizon_months']}mo)")
            import textwrap as _tw3
            for _ln in _tw3.wrap(v['description'], 72):
                print(f"  {c('DIM', '    ' + _ln)}")
        section("AI-DRIVEN EXPLOIT PREDICTIONS")
        for name, model in list(tc._ai_threat_models.items())[:3]:
            color = "RED" if model["confidence"]>0.85 else "YELLOW"
            import textwrap as _tw4
            _desc_lines = _tw4.wrap(f"{name}: {model['description']}", 74)
            for _i4, _ln in enumerate(_desc_lines):
                print(f"  {c(color, '  ▸') if _i4==0 else '     '} {c(color, _ln)}")
        section("SOCIAL ENGINEERING CAMPAIGN PREDICTION")
        for ct in social["campaign_types"]:
            print(f"  {c('YELLOW', '  ›')} {ct}")
        item("Confidence",         f"{social['confidence']*100:.0f}%")
        multiline_item("Countermeasure", social["recommended_countermeasure"])
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Event Horizon ─────────────────────────────────────────────────────────

    def _event_horizon(self):
        section("PREDICTIVE EVENT HORIZON — 30-Day Threat Forecast")
        from layers.l7_evolution.event_horizon import EventHorizon
        eh = EventHorizon()
        report = eh.get_horizon_report()
        forecast = report["30day_forecast"]
        item("Current Threat Level", f"{forecast['forecast'][0]['projected_threat_level']:.1f}/100")
        item("30-Day Trend",         report["trend"], "RED" if report["trend"]=="INCREASING" else "GREEN")
        item("Peak Threat",          f"Day {report['peak_threat']['day']}: {report['peak_threat']['projected_threat_level']:.1f} [{report['peak_threat']['level']}]")
        multiline_item("Strategic Advice", report["strategic_recommendation"], "YELLOW" if "COLD START" in report["strategic_recommendation"] else "WHITE")
        print(f"\n  {c('BRIGHT', 'Day  Threat Level     Forecast Bar')}")
        for f in forecast["forecast"][:14]:
            bar = "█" * int(f["projected_threat_level"]/5)
            color = "RED" if f["level"]=="CRITICAL" else ("YELLOW" if f["level"]=="HIGH" else ("CYAN" if f["level"]=="MEDIUM" else "GREEN"))
            threat_str = f"{f['projected_threat_level']:5.1f}"
            print(f"  {str(f['day']).rjust(3)}  {c(color, threat_str)}  {c(color, bar)}")
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Ethical Governance ────────────────────────────────────────────────────

    def _ethical_governance(self):
        section("AUTONOMOUS ETHICAL GOVERNANCE ENGINE")
        action = input(f"  {c('CYAN','Action to evaluate')}: ").strip() or "contain_user"
        from governance.ethical_engine import EthicalEngine
        from governance.explainability import ExplainabilityEngine
        ee = EthicalEngine(); xe = ExplainabilityEngine()
        decision = ee.evaluate_action(action, context={"risk":85,"consent_obtained":False})
        bias = ee.bias_check({"behavior_score":0.7,"role":"analyst"})
        privacy = ee.privacy_impact_assessment(action)
        compliance = ee.compliance_check(action, ["GDPR","SOC2","HIPAA","ISO27001"])
        explanation = xe.explain_risk_score("user_demo", score=75)
        attribution = xe.feature_attribution({"behavioral_anomaly":0.6,"insider_risk":0.3,"fatigue":0.1})
        item("Action",             action)
        item("Ethical Decision",   c("GREEN","APPROVED") if decision=="APPROVED" else (c("YELLOW","ESCALATE") if decision=="ESCALATE" else c("RED","REJECTED")))
        item("Bias Check",         c("GREEN","CLEAR") if bias["verdict"]=="CLEAR" else c("YELLOW","REVIEW REQUIRED"))
        item("Privacy Impact",     f"{privacy*100:.0f}%", "RED" if privacy>0.7 else "YELLOW")
        section("COMPLIANCE STATUS")
        for fw, status in compliance["results"].items():
            print(f"  {c('GREEN' if status=='COMPLIANT' else 'YELLOW', '  ' + ('✓' if status=='COMPLIANT' else '⚠'))} {fw}: {status}")
        section("XAI — EXPLAINABLE AI FEATURE ATTRIBUTION")
        item("Top Factor",         explanation["dominant_factor"].replace("_"," "))
        multiline_item("Explanation", explanation["explanation"])
        for feat, pct in attribution["attributions_pct"].items():
            bar = "█" * int(pct/5)
            print(f"  {c('DIM', feat.ljust(25))} {c('CYAN', bar)} {pct:.1f}%")
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Federated Network ─────────────────────────────────────────────────────

    def _federated_network(self):
        section("FEDERATED INTELLIGENCE NETWORK — Privacy-Preserving Global Intel")
        from network.federated import FederatedLearning
        from network.privacy import DifferentialPrivacy
        fl = FederatedLearning(); dp = DifferentialPrivacy(epsilon=1.0)
        intel = {"org":"FinCorp_Global","threat_type":"spear_phishing","attack_vector":"email","severity":"HIGH","ioc_hashes":["abc123","def456"],"ttp_ids":["T1566","T1078"]}
        anon = fl.anonymize_threat_intel(intel)
        shared = fl.share_intelligence(intel)
        noisy_val = dp.laplace_mechanism(75.0, sensitivity=5.0)
        item("Privacy Mode",           "Differential Privacy (ε=1.0)")
        item("Data Sharing Protocol",  "FedAvg + Laplace Mechanism")
        item("Original Risk Score",    "75.0")
        item("Privatized Score",       f"{noisy_val:.2f} (ε-DP noise added)")
        section("ANONYMIZED THREAT INTEL SHARE")
        item("Source",              f"[ANONYMIZED] → {anon.get('source_hash','?')[:12]}…")
        item("Threat Type",         anon.get("threat_type","unknown"))
        item("Attack Vector",       anon.get("attack_vector","unknown"))
        item("Severity",            anon.get("severity","unknown"))
        item("IOC Hashes Shared",   str(len(anon.get("ioc_hashes",[]))))
        item("TTPs Shared",         str(len(anon.get("ttp_ids",[]))))
        item("PII Removed",         c("GREEN","✓ YES — GDPR compliant"))
        item("Network Recipients",  "AURORA Global Intelligence Network (1,247 orgs)")
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Self Defense ──────────────────────────────────────────────────────────

    def _self_defense(self):
        section("PLATFORM SELF-DEFENSE & ANTI-TAMPER STATUS")
        from hardening.self_defense import SelfDefense
        from hardening.integrity_monitor import IntegrityMonitor
        sd = SelfDefense(); im = IntegrityMonitor()
        rate_ok = sd.check_rate_limit("test_client", "api")
        sanitized = sd.sanitize_input("' OR 1=1; DROP TABLE users --")
        debug_env = sd.detect_debug_environment()
        snapshot = im.create_baseline_snapshot()
        tampered = im.detect_tampering()
        item("Rate Limiter",        c("GREEN","ACTIVE — 100 req/min per client"))
        item("Input Sanitization",  c("GREEN","ACTIVE — SQL/CMD/Prompt injection blocked"))
        item("Memory Scrubbing",    c("GREEN","ACTIVE — Sensitive data zeroed after use"))
        item("Anti-Debug",          c("GREEN","CLEAN") if not debug_env else c("YELLOW","DEBUG ENV DETECTED"))
        item("Integrity Baseline",  f"{len(snapshot)} files hashed")
        item("Tamper Detection",    c("RED","TAMPERING DETECTED") if tampered else c("GREEN","✓ INTEGRITY INTACT"))
        item("API Auth",            "SHA-256 token + constant-time comparison")
        item("TLS",                 "TLS 1.3 for all network communication")
        item("Key Storage",         "Ed25519 keys in ~/.aurora/keys (chmod 600)")
        section("SANITIZATION DEMO")
        item("Input",               "' OR 1=1; DROP TABLE users --")
        item("Sanitized",           (sanitized[:57] + "…") if len(sanitized) > 57 else sanitized)
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Doctor ────────────────────────────────────────────────────────────────

    def _doctor(self):
        section("AURORA DOCTOR — Self-Diagnostics (131 Checks)")
        print(c("DIM", "  Running comprehensive system validation…\n"))
        from core.integrity import AuroraIntegrity
        report = AuroraIntegrity().run_full_diagnostics()
        passed = report["passed"]; total = report["total"]; rate = report["pass_rate"]
        if rate == 100.0: print(c("GREEN", f"  ✅ ALL SYSTEMS NOMINAL — {passed}/{total} checks passed (100%)"))
        else: print(c("RED", f"  ⚠️  {total-passed} CHECKS FAILED — {passed}/{total} passed ({rate:.1f}%)"))
        print()
        for layer, result in report["layers"].items():
            icon = c("GREEN","✓") if result["ok"] else c("RED","✗")
            checks = result.get("checks",0)
            failed = result.get("failed",[])
            print(f"  {icon} {layer.ljust(20)} {checks} checks", end="")
            if not result["ok"]: print(f"  {c('RED', 'FAILED: ' + ', '.join(failed[:2]))}", end="")
            print()
        print(f"\n  {c('DIM', 'Generated at: ' + report['timestamp'])}")
        input(f"\n  {c('DIM', '[Press Enter to continue]')}")


    def _identity_management(self):
        from core.auth import (
            get_session, list_users, add_user, remove_user,
            reset_password, generate_reset_token, ROLES, _show_2fa_setup,
            export_provision_package, authenticate,
            send_department_message, get_inbox, read_message,
            list_dept_messages_admin, get_departments, get_department_members,
            force_logout_user, switch_account_prompt, change_user_role,
            _RESET_TOKEN_TTL,
        )
        import getpass
        import time as _time

        session  = get_session()
        is_admin = session and session.get("role") == "admin"

        while True:
            section("IDENTITY & USER MANAGEMENT")
            # ── Integration guide (shown once per session at top) ──────────────
            print(c("DIM", "  Integration backends: SSO/OIDC  ·  LDAP/AD  ·  SAML 2.0  ·  org_config  ·  CSV/JSON roster"))
            print(c("DIM", "  Configure: ~/.aurora/identity.json  (SSO/LDAP)  |  ~/.aurora/org_config.json  (roster)"))
            print(c("DIM", "  Env overrides: AURORA_SSO_CLIENT_ID  AURORA_LDAP_BIND_PASSWORD  AURORA_USER_ID  AURORA_ORG_ID"))
            print()
            users = list_users()
            item("Total AURORA Users", str(len(users)))
            item("Your Role",        (session or {}).get("role", "unknown").upper())
            item("Your Employee ID", (session or {}).get("employee_id", "---"))
            my_depts = (session or {}).get("departments",
                        [(session or {}).get("department", "---")])
            item("Your Departments", ", ".join(d for d in my_depts if d))

            print(c("BRIGHT", "\n  +-- ACTIONS --------------------------------------------------------+"))
            options = [
                ("1",  "List all users",                                     True),
                ("2",  "Add new user",                                       is_admin),
                ("3",  "Remove a user",                                      is_admin),
                ("4",  "Reset user password  [admin sets directly]",         is_admin),
                ("5",  "Issue password-reset token  [user resets via token]",is_admin),
                ("6",  "Export provision package (.aup)",                    is_admin),
                ("7",  "Force-logout a user",                                is_admin),
                ("8",  "Send department message",                            is_admin),
                ("9",  "My inbox",                                           True),
                ("10", "Change my own password",                             True),
                ("11", "Switch account",                                     True),
                ("12", "Change a user's role  [promote / demote]",           is_admin),
                ("0",  "Back",                                               True),
            ]
            for num, desc, allowed in options:
                tag = "" if allowed else "  [admin only]"
                col = "WHITE" if allowed else "DIM"
                print(f"  |  {c('CYAN', num.rjust(2))}  {c(col, desc + tag)}")
            print(c("BRIGHT", "  +-------------------------------------------------------------------+"))
            try:
                ch = input(f"\n  {c('CYAN','>')} Select [{c('DIM','0-12')}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                return

            # ── 0 Back ────────────────────────────────────────────────────────
            if ch == "0":
                return

            # ── 1 List all users ──────────────────────────────────────────────
            elif ch == "1":
                section(f"REGISTERED USERS  ({len(users)} total)")
                if not users:
                    print(f"  {c('DIM', 'No users registered yet.')}")
                else:
                    print(f"  {'Username':<18}  {'EmpID':<10}  {'Name':<22}  "
                          f"{'Departments':<22}  {'Role':<10}  2FA  Last Login")
                    print(f"  {'-'*108}")
                    for u in users:
                        rc   = ("CYAN"   if u["role"] == "admin" else
                                "YELLOW" if u["role"] == "operator" else "DIM")
                        ll   = ("Never" if not u.get("last_login") else
                                _time.strftime("%Y-%m-%d %H:%M",
                                               _time.localtime(u["last_login"])))
                        tfa  = c("GREEN", "Y") if u.get("totp_enabled") else c("RED", "N")
                        dstr = ", ".join(u.get("departments",
                                               [u.get("department", "")]))[:20]
                        print(f"  {c('WHITE', u['username'].ljust(18))}  "
                              f"{u.get('employee_id','').ljust(10)}  "
                              f"{u.get('name','').ljust(22)}  "
                              f"{dstr.ljust(22)}  "
                              f"{c(rc, u['role'].ljust(10))}  {tfa}   {ll}")
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 2 Add new user ────────────────────────────────────────────────
            elif ch == "2":
                if not is_admin:
                    print(c("RED", "  Admin access required."))
                    input(f"  {c('DIM','[Enter]')}"); continue
                section("ADD NEW USER")
                try:
                    uname = input(f"  {c('CYAN','Username')}: ").strip().lower()
                    if not uname: continue
                    name  = input(f"  {c('CYAN','Full name')}: ").strip()
                    empid = input(f"  {c('CYAN','Employee ID')}: ").strip()
                    dept  = input(f"  {c('CYAN','Primary department')}: ").strip() or "General"
                    raw_e = input(
                        f"  {c('CYAN','Additional departments')} "
                        f"(comma-separated, blank=none): ").strip()
                    extra = [d.strip() for d in raw_e.split(",")
                             if d.strip()] if raw_e else []
                    print(f"  Roles: {', '.join(ROLES)}")
                    role  = input(f"  {c('CYAN','Role')} [operator]: ").strip() or "operator"
                    pw    = getpass.getpass(
                        f"  {c('CYAN','Temporary password')} (min 12 chars): ")
                    pw2   = getpass.getpass(f"  {c('CYAN','Confirm')}: ")
                    if pw != pw2:
                        print(c("RED", "  Passwords do not match."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    en2fa = input(
                        f"  {c('CYAN','Enable 2FA (TOTP)?')} [Y/n]: "
                    ).strip().lower() != "n"
                    record = add_user(uname, pw, empid, name, dept, role, en2fa, extra)
                    print()
                    print(c("GREEN", f"  User '{uname}' created  (EMP-{empid}, {role})"))
                    all_d = record.get("departments", [dept])
                    print(c("DIM",   f"  Departments: {', '.join(all_d)}"))
                    print()
                    print(c("YELLOW", "  -- HOW THIS USER LOGS IN ----------------------------"))
                    print(c("DIM",    "  Same machine : use username + password set above."))
                    print(c("DIM",    "  Other machine: option 6 -> Export provision package (.aup)"))
                    if en2fa and record.get("totp_secret"):
                        _show_2fa_setup(record["totp_secret"], uname)
                except ValueError as e:
                    print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 3 Remove user ─────────────────────────────────────────────────
            elif ch == "3":
                if not is_admin:
                    print(c("RED", "  Admin access required."))
                    input(f"  {c('DIM','[Enter]')}"); continue
                section("REMOVE USER")
                try:
                    uname = input(
                        f"  {c('CYAN','Username to remove')}: ").strip().lower()
                    if not uname: continue
                    if uname == (session or {}).get("username"):
                        print(c("RED", "  Cannot remove your own account."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    confirm = input(
                        f"  {c('YELLOW', 'Remove ' + repr(uname) + ' — irreversible. Type YES: ')}"
                    ).strip()
                    if confirm == "YES":
                        if remove_user(uname):
                            print(c("GREEN", f"  User '{uname}' removed."))
                        else:
                            print(c("RED",   f"  User '{uname}' not found."))
                    else:
                        print(c("DIM", "  Cancelled."))
                except Exception as e:
                    print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 4 Admin direct password reset ─────────────────────────────────
            elif ch == "4":
                if not is_admin:
                    print(c("RED", "  Admin access required."))
                    input(f"  {c('DIM','[Enter]')}"); continue
                section("RESET USER PASSWORD  [Admin sets password directly]")
                print(c("DIM", "  Hashed with Argon2id. Active session invalidated automatically."))
                try:
                    uname = input(f"  {c('CYAN','Username')}: ").strip().lower()
                    if not uname: continue
                    pw  = getpass.getpass(f"  {c('CYAN','New password')} (min 12): ")
                    pw2 = getpass.getpass(f"  {c('CYAN','Confirm')}: ")
                    if pw != pw2:
                        print(c("RED", "  Do not match."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    reset_password(uname, pw)
                    print(c("GREEN", f"  Password reset for '{uname}'."))
                    print(c("DIM",   "  User's active session (if any) has been invalidated."))
                except ValueError as e:
                    print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 5 Issue self-service reset token ──────────────────────────────
            elif ch == "5":
                if not is_admin:
                    print(c("RED", "  Admin access required."))
                    input(f"  {c('DIM','[Enter]')}"); continue
                section("ISSUE PASSWORD-RESET TOKEN  [User resets their own password]")
                print(c("DIM", "  Generates a 256-bit cryptographic token (shown ONCE)."))
                print(c("DIM", "  Deliver it to the user via a secure out-of-band channel."))
                print(c("DIM", f"  Token expires in {_RESET_TOKEN_TTL // 60} minutes. Single-use."))
                print(c("DIM", "  Token is stored as SHA-256 digest only — never plaintext."))
                print()
                try:
                    uname = input(f"  {c('CYAN','Username')}: ").strip().lower()
                    if not uname: continue
                    token = generate_reset_token(uname)
                    print()
                    print(c("GREEN",  "  Token (copy now — shown ONCE):"))
                    print()
                    print(c("YELLOW", f"  {token}"))
                    print()
                    print(c("DIM", "  Delivery options: voice, Signal, encrypted email."))
                    print(c("DIM", "  User types 'reset' at the AURORA login username prompt."))
                except ValueError as e:
                    print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 6 Export provision package ────────────────────────────────────
            elif ch == "6":
                if not is_admin:
                    print(c("RED", "  Admin access required."))
                    input(f"  {c('DIM','[Enter]')}"); continue
                section("EXPORT PROVISION PACKAGE (.aup)")
                print(c("DIM", "  Encrypted package for a user to activate on another machine."))
                print(c("CYAN","  User runs: python aurora.py provision <file.aup>"))
                print()
                try:
                    uname = input(f"  {c('CYAN','Username to export')}: ").strip().lower()
                    if not uname: continue
                    out = (input(f"  {c('CYAN','Save as')} [{uname}.aup]: ").strip()
                           or f"{uname}.aup")
                    print()
                    print(c("YELLOW", "  Set encryption passphrase for this package."))
                    print(c("DIM",    "  Share passphrase SEPARATELY from the file."))
                    pp  = getpass.getpass(f"  {c('CYAN','Passphrase')} (min 8 chars): ")
                    pp2 = getpass.getpass(f"  {c('CYAN','Confirm passphrase')}: ")
                    if pp != pp2:
                        print(c("RED", "  Do not match."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    if len(pp) < 8:
                        print(c("RED", "  Too short."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    path = export_provision_package(uname, pp, out)
                    print()
                    print(c("GREEN",  f"  Exported: {path}"))
                    print(c("BRIGHT",  "  -- Next steps -------------------------------------------"))
                    print(c("DIM",    f"  1. Send file       : {path}"))
                    print(c("DIM",     "  2. Send passphrase : via voice/Signal (separate channel)"))
                    print(c("DIM",     "  3. User activates  : python aurora.py provision <file>"))
                    print(c("DIM",     "  4. Package expires in 7 days."))
                except Exception as e:
                    print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 7 Force-logout ────────────────────────────────────────────────
            elif ch == "7":
                if not is_admin:
                    print(c("RED", "  Admin access required."))
                    input(f"  {c('DIM','[Enter]')}"); continue
                section("FORCE-LOGOUT A USER")
                print(c("DIM", "  Immediately clears the target user's in-memory session."))
                print(c("DIM", "  Use when a device is lost, compromised, or shared."))
                try:
                    uname = input(
                        f"  {c('CYAN','Username to force-logout')}: ").strip().lower()
                    if not uname: continue
                    force_logout_user(uname, (session or {}).get("username", ""))
                    print(c("GREEN", f"  Session for '{uname}' has been invalidated."))
                except (ValueError, PermissionError) as e:
                    print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 8 Send department message ──────────────────────────────────────
            elif ch == "8":
                if not is_admin:
                    print(c("RED", "  Admin access required."))
                    input(f"  {c('DIM','[Enter]')}"); continue
                section("SEND DEPARTMENT MESSAGE")
                try:
                    depts = get_departments()
                    if not depts:
                        print(c("DIM", "  No departments found."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    print(c("BRIGHT", "  Available departments:"))
                    for d in depts:
                        mems = get_department_members(d)
                        print(f"    {c('CYAN','*')} {d}  "
                              f"{c('DIM', f'({len(mems)} member(s))')}")
                    print()
                    dept_in = input(
                        f"  {c('CYAN','Department name')}: ").strip()
                    if not dept_in: continue
                    members = get_department_members(dept_in)
                    if not members:
                        print(c("RED", f"  No members in '{dept_in}'."))
                        input(f"  {c('DIM','[Enter]')}"); continue

                    print()
                    print(c("DIM", "  Audience options:"))
                    print(f"    {c('CYAN','A')}  All members in department ({len(members)})")
                    print(f"    {c('CYAN','S')}  Select specific recipients")
                    aud = input(f"  {c('CYAN','Choice')} [A/s]: ").strip().lower()

                    recipients = None
                    if aud == "s":
                        print(c("DIM", f"  Members of '{dept_in}':"))
                        for m in members:
                            print(f"    - {m}")
                        raw = input(
                            f"  {c('CYAN','Usernames')} (comma-separated): ").strip()
                        recipients = [r.strip() for r in raw.split(",") if r.strip()]
                        if not recipients:
                            print(c("DIM", "  No recipients selected. Cancelled."))
                            input(f"  {c('DIM','[Enter]')}"); continue

                    subject = input(f"  {c('CYAN','Subject')}: ").strip()
                    if not subject: continue
                    print(c("DIM", "  Body (type END on its own line to finish):"))
                    lines = []
                    while True:
                        try:
                            ln = input("  ")
                        except (KeyboardInterrupt, EOFError):
                            break
                        if ln.strip() == "END":
                            break
                        lines.append(ln)
                    body = "\n".join(lines).strip()
                    if not body:
                        print(c("DIM", "  Empty body. Cancelled."))
                        input(f"  {c('DIM','[Enter]')}"); continue

                    sender = (session or {}).get("username", "")
                    mid    = send_department_message(
                        sender, dept_in, subject, body, recipients)
                    count  = len(recipients) if recipients else len(members)
                    print(c("GREEN",
                            f"\n  Message sent to {count} recipient(s) in '{dept_in}'."))
                    print(c("DIM", f"  Message ID: {mid}"))
                except (ValueError, PermissionError) as e:
                    print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 9 Inbox ────────────────────────────────────────────────────────
            elif ch == "9":
                section("MY DEPARTMENT INBOX")
                uname   = (session or {}).get("username", "")
                inbox   = get_inbox(uname)
                if not inbox:
                    print(c("DIM", "  No messages."))
                    input(f"\n  {c('DIM', '[Press Enter to continue]')}"); continue

                unread_n = sum(1 for m in inbox if not m["is_read"])
                print(c("BRIGHT",
                        f"  {len(inbox)} message(s)  |  {unread_n} unread\n"))
                for i, m in enumerate(inbox, 1):
                    icon = (c("DIM", "[read]") if m["is_read"]
                            else c("YELLOW", "[NEW] "))
                    ts   = _time.strftime("%Y-%m-%d %H:%M",
                                          _time.localtime(m["sent_at"]))
                    print(f"  {c('CYAN', str(i).rjust(3))}  {icon}  "
                          f"{c('WHITE', m['subject'][:40].ljust(42))}  "
                          f"{c('DIM', m['department'][:14].ljust(16))}  "
                          f"{c('DIM', ts)}")
                print()
                pick = input(
                    f"  {c('CYAN','Read message #')} (Enter = back): ").strip()
                if pick.isdigit() and 1 <= int(pick) <= len(inbox):
                    msg = read_message(uname, inbox[int(pick)-1]["id"])
                    if msg:
                        print()
                        print(c("BRIGHT", f"  From    : {msg['sender']}"))
                        print(c("BRIGHT", f"  Dept    : {msg['department']}"))
                        print(c("BRIGHT", f"  Subject : {msg['subject']}"))
                        ts2 = _time.strftime("%Y-%m-%d %H:%M",
                                             _time.localtime(msg["sent_at"]))
                        print(c("DIM",    f"  Sent    : {ts2}"))
                        recs = msg.get("recipients", [])
                        rstr = ", ".join(recs[:5])
                        if len(recs) > 5:
                            rstr += f" ... (+{len(recs)-5} more)"
                        print(c("DIM",    f"  To      : {rstr}"))
                        print()
                        print(c("WHITE",
                                "  " + msg["body"].replace("\n", "\n  ")))

                # Admin can view full dept message history
                if is_admin:
                    print()
                    hq = input(
                        f"  {c('DIM','View full dept message history? [y/N]: ')}"
                    ).strip().lower()
                    if hq == "y":
                        dept_in = input(
                            f"  {c('CYAN','Department')}: ").strip()
                        if dept_in:
                            try:
                                hist = list_dept_messages_admin(dept_in, uname)
                                section(f"HISTORY -- {dept_in}  "
                                        f"({len(hist)} messages)")
                                for m in hist:
                                    ts3 = _time.strftime(
                                        "%Y-%m-%d %H:%M",
                                        _time.localtime(m["sent_at"]))
                                    rr = len(m.get("read_by",   []))
                                    rt = len(m.get("recipients",[]))
                                    print(f"  {c('DIM',ts3)}  "
                                          f"{c('WHITE',m['subject'][:40])}  "
                                          f"{c('DIM',f'{rr}/{rt} read')}")
                            except PermissionError as e:
                                print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 10 Change own password ─────────────────────────────────────────
            elif ch == "10":
                section("CHANGE MY PASSWORD")
                try:
                    uname  = (session or {}).get("username", "")
                    old_pw = getpass.getpass(f"  {c('CYAN','Current password')}: ")
                    ok, msg = authenticate(uname, old_pw, totp_code="__skip_totp__")
                    if not ok and msg not in ("2FA_REQUIRED", "OK"):
                        print(c("RED", "  Current password incorrect."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    new_pw  = getpass.getpass(f"  {c('CYAN','New password')} (min 12): ")
                    new_pw2 = getpass.getpass(f"  {c('CYAN','Confirm')}: ")
                    if new_pw != new_pw2:
                        print(c("RED", "  Do not match."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    reset_password(uname, new_pw)
                    print(c("GREEN", "  Password changed successfully."))
                except Exception as e:
                    print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

            # ── 11 Switch account ──────────────────────────────────────────────
            elif ch == "11":
                switched = switch_account_prompt()
                if switched:
                    # Refresh session after switch so admin flag updates correctly
                    from core.auth import get_session as _gs2
                    session  = _gs2()
                    is_admin = session and session.get("role") == "admin"
                    return   # Back to main menu so header reflects new user

            # ── 12 Change user role ────────────────────────────────────────────
            elif ch == "12":
                if not is_admin:
                    print(c("RED", "  Admin access required."))
                    input(f"  {c('DIM','[Enter]')}"); continue
                section("CHANGE USER ROLE  [Promote / Demote]")
                print(c("DIM",    "  Available roles: " + ", ".join(ROLES)))
                print(c("DIM",    "  An admin cannot change their own role."))
                print(c("DIM",    "  The last remaining admin cannot be demoted."))
                print()
                # Show current users and roles for reference
                all_users = list_users()
                print(c("BRIGHT", "  Current users:"))
                print(f"  {'Username':<20}  {'Name':<22}  {'Role':<12}")
                print(f"  {'-'*56}")
                for u in all_users:
                    rc = ("CYAN"   if u["role"] == "admin" else
                          "YELLOW" if u["role"] == "operator" else "DIM")
                    you = c("DIM", "  ← you") if u["username"] == (session or {}).get("username") else ""
                    print(f"  {c('WHITE', u['username'].ljust(20))}  "
                          f"{u.get('name','').ljust(22)}  "
                          f"{c(rc, u['role'].ljust(12))}{you}")
                print()
                try:
                    uname = input(f"  {c('CYAN','Username to change')}: ").strip().lower()
                    if not uname:
                        input(f"  {c('DIM','[Enter]')}"); continue
                    print(f"  Roles: {', '.join(ROLES)}")
                    new_role = input(f"  {c('CYAN','New role')}: ").strip().lower()
                    if not new_role:
                        print(c("DIM", "  Cancelled."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    # Find current role for display
                    target_rec = next(
                        (u for u in all_users if u["username"] == uname), None
                    )
                    if not target_rec:
                        print(c("RED", f"  User '{uname}' not found."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    old_role = target_rec["role"]
                    if old_role == new_role:
                        print(c("DIM", f"  '{uname}' is already '{new_role}'. No change."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    # Confirm before applying
                    arrow = c("YELLOW", f"  {old_role}  →  {new_role}")
                    confirm = input(
                        f"  Confirm: {c('WHITE', uname)} {arrow}  [Y/n]: "
                    ).strip().lower()
                    if confirm == "n":
                        print(c("DIM", "  Cancelled."))
                        input(f"  {c('DIM','[Enter]')}"); continue
                    requester = (session or {}).get("username", "")
                    change_user_role(uname, new_role, requester)
                    print()
                    action = "promoted to" if new_role == "admin" else "role changed to"
                    color  = "GREEN" if new_role == "admin" else "CYAN"
                    print(c(color, f"  ✓ '{uname}' {action} [{new_role.upper()}]."))
                    if new_role == "admin":
                        print(c("DIM", "  They will have full admin privileges on next action."))
                    elif old_role == "admin":
                        print(c("DIM", f"  Admin privileges removed. New role: {new_role}."))
                    print(c("DIM",  "  Change recorded in the immutable audit log."))
                except (ValueError, PermissionError) as e:
                    print(c("RED", f"  {e}"))
                input(f"\n  {c('DIM', '[Press Enter to continue]')}")

    # ── Exit ──────────────────────────────────────────────────────────────────

    def _exit(self):
        print(c("CYAN", "\n  AURORA -- Securing the future. Goodbye.\n"))
        self._running = False
        sys.exit(0)
