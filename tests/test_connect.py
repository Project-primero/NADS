"""Tests for Universal Connect System & Multi-Computer Telemetry (pytest & unittest compatible)."""
import os
import shutil
import tempfile
import time
import unittest
from backend.database.db import Database
from backend.capture.packet_capture import PacketCapture


class TestConnectSystem(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.test_dir, "test_alerts.db")
        self.db = Database(self.db_file)
        self.capture = PacketCapture(interface="lo", mode="simulate", intensity="low")

    def tearDown(self):
        self.capture.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_interface_discovery(self):
        """Verify local host interfaces can be inspected."""
        ifaces = PacketCapture.get_host_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertGreater(len(ifaces), 0)
        first = ifaces[0]
        for key in ("name", "status", "is_up", "is_loopback"):
            self.assertIn(key, first, f"Missing key '{key}' in interface metadata")

    def test_agent_token_lifecycle(self):
        """Verify cryptographic token generation, verification, and revocation."""
        # 1. Create agent
        agent_info = self.db.create_agent(name="Test-Node-1", site="CS Lab")
        self.assertIn("token", agent_info)
        self.assertTrue(agent_info["token"].startswith("agt_"))
        token = agent_info["token"]

        # 2. Verify token
        verified = self.db.verify_agent_token(token)
        self.assertIsNotNone(verified)
        self.assertEqual(verified["name"], "Test-Node-1")
        self.assertEqual(verified["site"], "CS Lab")

        # 3. Invalid token returns None
        self.assertIsNone(self.db.verify_agent_token("invalid_token_12345"))

        # 4. Telemetry update
        self.db.update_agent_telemetry(
            agent_id=verified["agent_id"],
            ip="192.168.1.105",
            hostname="lab-desktop-01",
            os_name="Ubuntu 24.04",
            pps=45.2,
            packets_inc=150
        )
        agents = self.db.list_agents()
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["ip"], "192.168.1.105")
        self.assertEqual(agents[0]["total_packets"], 150)
        self.assertEqual(agents[0]["status"], "ONLINE")

        # 5. Revoke agent
        self.assertTrue(self.db.delete_agent(verified["agent_id"]))
        self.assertIsNone(self.db.verify_agent_token(token))
        self.assertEqual(len(self.db.list_agents()), 0)

    def test_allowlist_filtering(self):
        """Verify IP and CIDR allowlist matching suppresses false alarms."""
        self.db.add_allowlist(cidr_or_ip="192.168.1.50", description="Vulnerability Scanner")
        self.db.add_allowlist(cidr_or_ip="10.10.0.0/16", description="Management Subnet")

        self.assertTrue(self.db.is_allowlisted("192.168.1.50"))
        self.assertFalse(self.db.is_allowlisted("192.168.1.51"))

        self.assertTrue(self.db.is_allowlisted("10.10.5.22"))
        self.assertFalse(self.db.is_allowlisted("10.11.5.22"))

    def test_asset_inventory_tracking(self):
        """Verify unique network devices are auto-discovered and tracked."""
        self.db.touch_asset(ip="10.0.0.42", mac="00:11:22:33:44:55", device_type="Workstation")
        assets = self.db.list_assets()
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["ip"], "10.0.0.42")
        self.assertEqual(assets[0]["mac"], "00:11:22:33:44:55")

        # Update metadata
        updated = self.db.update_asset(
            ip="10.0.0.42",
            hostname="Student-PC-42",
            owner="Engineering Faculty",
            department="Robotics Lab"
        )
        self.assertEqual(updated["hostname"], "Student-PC-42")
        self.assertEqual(updated["owner"], "Engineering Faculty")

    def test_dynamic_mode_switching(self):
        """Verify switching ingestion modes dynamically without crashing."""
        self.capture.start()
        self.assertTrue(self.capture.get_status()["running"])

        # Switch intensity
        status = self.capture.switch_mode("simulate", intensity="stress", attacks=["floods", "scans"])
        self.assertEqual(status["intensity"], "stress")
        self.assertIn("floods", status["attacks"])

        # Stop capture
        self.capture.stop()
        self.assertFalse(self.capture.get_status()["running"])


if __name__ == "__main__":
    unittest.main()
