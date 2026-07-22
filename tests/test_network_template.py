from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "infra" / "chapter-2-network.yaml").read_text()


class NetworkTemplateTests(unittest.TestCase):
    def test_deployment_defaults_to_false(self):
        self.assertRegex(TEXT, r"DeployChapter2Network:\s+Type: String\s+Default: 'false'")

    def test_every_resource_is_guarded(self):
        resources = TEXT.split("Resources:\n", 1)[1].split("Outputs:\n", 1)[0]
        blocks = re.split(r"(?m)^(?=  [A-Za-z][A-Za-z0-9]+:\n    Type:)", resources)
        blocks = [b for b in blocks if "Type: AWS::" in b]
        self.assertGreaterEqual(len(blocks), 8)
        self.assertTrue(all("    Condition: Deploy\n" in b for b in blocks))

    def test_no_internet_or_nat_gateway(self):
        self.assertNotIn("AWS::EC2::InternetGateway", TEXT)
        self.assertNotIn("AWS::EC2::NatGateway", TEXT)
        self.assertNotIn("0.0.0.0/0", TEXT)
        self.assertNotIn("::/0", TEXT)

    def test_security_groups_do_not_request_empty_default_egress(self):
        self.assertNotIn("SecurityGroupEgress: []", TEXT)
        self.assertIn("CidrIp: 10.42.21.0/24", TEXT)

    def test_bedrock_endpoint_is_private_and_deny_by_default(self):
        self.assertIn("com.amazonaws.${AWS::Region}.bedrock-runtime", TEXT)
        self.assertIn("PrivateDnsEnabled: true", TEXT)
        self.assertRegex(TEXT, r"Effect: Deny\s+Principal: '\*'\s+Action: '\*'")


if __name__ == "__main__":
    unittest.main()
