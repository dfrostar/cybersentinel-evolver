"""Tests for augmented threat feed scenarios (BRD §5.1)."""
from __future__ import annotations

from cybersentinel_evolver.attacks import AttackGenerator
from cybersentinel_evolver.database import Database


class TestThreatFeedAugmentation:
    def test_credential_stuffing_10_variants(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        cred = [s for s in scenarios if s["abuse_type"] == "credential_stuffing"]
        assert len(cred) == 10
        db.close()

    def test_agent_impersonation_8_variants(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        imp = [s for s in scenarios if s["abuse_type"] == "agent_impersonation"]
        assert len(imp) == 8
        db.close()

    def test_llm_token_scraping_6_variants(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        scrape = [s for s in scenarios if s["abuse_type"] == "llm_token_scraping"]
        assert len(scrape) == 6
        db.close()

    def test_billing_abuse_5_variants(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        billing = [s for s in scenarios if s["abuse_type"] == "billing_abuse"]
        assert len(billing) == 5
        db.close()

    def test_mcp_server_abuse_4_variants(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        mcp = [s for s in scenarios if s["abuse_type"] == "mcp_server_abuse"]
        assert len(mcp) == 4
        db.close()

    def test_prompt_injection_bypass_4_variants(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        pi = [s for s in scenarios if s["abuse_type"] == "prompt_injection"]
        assert len(pi) == 4
        db.close()

    def test_rate_evasion_4_variants(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        rev = [s for s in scenarios if s["abuse_type"] == "rate_evasion_distributed"]
        assert len(rev) == 4
        db.close()

    def test_total_scenarios_41(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        scenarios = gen.generate()
        # 10 + 8 + 6 + 5 + 4 + 4 + 4 + 4 = 45 total
        assert len(scenarios) >= 41
        db.close()

    def test_source_feeds_are_credible(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        feeds = {s["source_feed"] for s in scenarios}
        expected_feeds = {
            "wallarm-threatstats-2026",
            "salt-security-2025",
            "crowdstrike-2026-ai",
            "cisa-known-exploited",
            "imperva-thales-2025",
            "owasp-api-top-10",
        }
        assert feeds == expected_feeds
        db.close()

    def test_identity_sources_covered(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        identities = {s["identity_source"] for s in scenarios}
        expected_identities = {
            "ip", "jwt_claim", "user_agent", "mcp_agent_name",
            "oauth_client_id", "api_key_header", "composite_identity",
        }
        assert identities == expected_identities
        db.close()

    def test_cost_models_matched(self, tmp_path):
        db = Database(tmp_path / "test.db")
        gen = AttackGenerator(db)
        gen.generate()

        scenarios = db.get_scenarios()
        for s in scenarios:
            abuse = s["abuse_type"]
            cost = s["cost_model_label"]
            if abuse == "credential_stuffing":
                assert cost == "credential-stuffing-default"
            elif abuse == "llm_token_scraping":
                assert cost == "llm-token-scraping-default"
            elif abuse == "billing_abuse":
                assert cost == "billing-abuse-default"
            elif abuse == "mcp_server_abuse":
                assert cost == "mcp-server-abuse-default"
        db.close()
