import unittest
from tool import analyze, parse_line

class SSHTests(unittest.TestCase):
    def test_failure_then_success_same_source_is_prioritized(self):
        lines=[f"Nov 05 10:00:0{i} host sshd[1]: Failed password for root from 203.0.113.8 port 22 ssh2" for i in range(1,4)]
        lines.append("Nov 05 10:01:00 host sshd[1]: Accepted publickey for admin from 203.0.113.8 port 22 ssh2")
        self.assertIn("success_after_failure_burst",{x["code"] for x in analyze(lines,2026,3)["findings"]})
    def test_unparseable_line_is_ignored(self): self.assertIsNone(parse_line("kernel: routine",2026))
    def test_ipv6_source_parses(self):
        row=parse_line("Nov 05 10:00:00 host sshd: Failed password for root from 2001:db8::1 port 22 ssh2",2026)
        self.assertEqual("2001:db8::1",row["source_ip"])

if __name__ == "__main__": unittest.main()
