import unittest
from pathlib import Path
TEXT=(Path(__file__).resolve().parents[1]/"infra"/"chapter-9-observability.yaml").read_text()
class TemplateTests(unittest.TestCase):
 def test_default_false(self): self.assertIn("Default: 'false'",TEXT)
 def test_condition(self): self.assertIn("DeployChapter9ObservabilityCondition",TEXT)
 def test_kms_logs(self): self.assertIn("KmsKeyId: !Ref SecurityLogKmsKeyArn",TEXT)
 def test_retention(self): self.assertIn("RetentionInDays: 400",TEXT)
 def test_object_lock_archive(self):
  self.assertIn("ObjectLockEnabled: true",TEXT)
  self.assertIn("Mode: COMPLIANCE",TEXT)
  self.assertIn("Days: 400",TEXT)
 def test_archive_is_versioned(self): self.assertIn("VersioningConfiguration:\n        Status: Enabled",TEXT)
 def test_archive_blocks_public_access(self): self.assertIn("RestrictPublicBuckets: true",TEXT)
 def test_delivery_subscription(self):
  self.assertIn("AWS::Logs::SubscriptionFilter",TEXT)
  self.assertIn("DestinationArn: !Ref SecurityDeliveryStreamArn",TEXT)
 def test_firehose_delivery_only(self): self.assertIn("Action: [firehose:PutRecord, firehose:PutRecordBatch]",TEXT)
 def test_no_delete(self): self.assertNotIn("s3:Delete",TEXT)
 def test_source_account(self): self.assertIn("aws:SourceAccount:",TEXT)
 def test_source_arn(self): self.assertIn("aws:SourceArn:",TEXT)
 def test_metric_filter(self): self.assertIn("AWS::Logs::MetricFilter",TEXT)
 def test_alarm(self): self.assertIn("AWS::CloudWatch::Alarm",TEXT)
 def test_missing_data_breaches(self): self.assertIn("TreatMissingData: breaching",TEXT)
 def test_no_allow_star(self): self.assertNotIn("Effect: Allow\n                Action: '*'",TEXT)
if __name__=="__main__": unittest.main()
