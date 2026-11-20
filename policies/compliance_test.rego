package compliance_test

import data.compliance

status_of(resources, rule, id) := s if {
	some r in compliance.report.results with input as {"resources": resources}
	r.rule == rule
	r.resource == id
	s := r.status
}

good_bucket := {"id": "arn:aws:s3:::good-example-com", "type": "aws_s3_bucket", "config": {
	"public_access_block": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true},
	"encryption": {"enabled": true},
	"logging": {"enabled": true},
}}

test_good_bucket_passes_all_three if {
	status_of([good_bucket], "s3_public_access_blocked", good_bucket.id) == "pass"
	status_of([good_bucket], "storage_encrypted", good_bucket.id) == "pass"
	status_of([good_bucket], "s3_access_logging", good_bucket.id) == "pass"
}

test_one_public_setting_off_fails if {
	b := json.patch(good_bucket, [{"op": "replace", "path": "/config/public_access_block/restrict_public_buckets", "value": false}])
	status_of([b], "s3_public_access_blocked", b.id) == "fail"
}

test_missing_config_fails_not_passes if {
	b := {"id": "bare", "type": "aws_s3_bucket", "config": {}}
	status_of([b], "s3_public_access_blocked", "bare") == "fail"
	status_of([b], "storage_encrypted", "bare") == "fail"
	status_of([b], "s3_access_logging", "bare") == "fail"
}

test_unencrypted_volume_and_db_fail if {
	vol := {"id": "vol-0123", "type": "aws_ebs_volume", "config": {"encrypted": false}}
	db := {"id": "db-1", "type": "aws_db_instance", "config": {}}
	status_of([vol, db], "storage_encrypted", "vol-0123") == "fail"
	status_of([vol, db], "storage_encrypted", "db-1") == "fail"
}

test_encrypted_volume_passes if {
	vol := {"id": "vol-0456", "type": "aws_ebs_volume", "config": {"encrypted": true}}
	status_of([vol], "storage_encrypted", "vol-0456") == "pass"
}

test_ssh_open_to_world_fails if {
	sg := {"id": "sg-1", "type": "aws_security_group", "config": {"ingress": [{"from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"]}]}}
	status_of([sg], "sg_no_open_admin_ports", "sg-1") == "fail"
}

test_rdp_in_wide_range_ipv6_fails if {
	sg := {"id": "sg-2", "type": "aws_security_group", "config": {"ingress": [{"from_port": 3000, "to_port": 4000, "cidrs": ["::/0"]}]}}
	status_of([sg], "sg_no_open_admin_ports", "sg-2") == "fail"
}

test_ssh_from_private_range_passes if {
	sg := {"id": "sg-3", "type": "aws_security_group", "config": {"ingress": [
		{"from_port": 22, "to_port": 22, "cidrs": ["10.0.0.0/8"]},
		{"from_port": 443, "to_port": 443, "cidrs": ["0.0.0.0/0"]},
	]}}
	status_of([sg], "sg_no_open_admin_ports", "sg-3") == "pass"
}

test_console_user_without_mfa_fails if {
	u := {"id": "alice", "type": "aws_iam_user", "config": {"console_access": true, "mfa_enabled": false}}
	status_of([u], "iam_console_user_mfa", "alice") == "fail"
}

test_api_only_user_is_not_evaluated if {
	u := {"id": "ci-bot", "type": "aws_iam_user", "config": {"console_access": false}}
	results := compliance.report.results with input as {"resources": [u]}
	count(results) == 0
}

test_single_region_trail_fails if {
	t := {"id": "trail-1", "type": "aws_cloudtrail", "config": {"is_logging": true, "multi_region": false}}
	status_of([t], "cloudtrail_multi_region", "trail-1") == "fail"
}

test_good_trail_passes if {
	t := {"id": "trail-2", "type": "aws_cloudtrail", "config": {"is_logging": true, "multi_region": true}}
	status_of([t], "cloudtrail_multi_region", "trail-2") == "pass"
}

test_unknown_type_produces_nothing if {
	x := {"id": "q-1", "type": "aws_sqs_queue", "config": {}}
	count(compliance.report.results) == 0 with input as {"resources": [x]}
}

test_rule_list_has_six_rules if {
	count(compliance.rules) == 6
}
