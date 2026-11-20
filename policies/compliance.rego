# Compliance rules over a normalised resource list.
# Input: {"resources": [{"id": "...", "type": "aws_s3_bucket", "config": {...}}]}
# Each rule emits one pass or fail result per resource it applies to.
package compliance

rules := {
	"s3_public_access_blocked",
	"s3_access_logging",
	"storage_encrypted",
	"sg_no_open_admin_ports",
	"iam_console_user_mfa",
	"cloudtrail_multi_region",
}

report := {"rules": rules, "results": results}

result(rule, res, ok, msg) := {
	"rule": rule,
	"resource": res.id,
	"status": status(ok),
	"message": msg,
}

status(ok) := "pass" if ok

status(ok) := "fail" if not ok

# --- S3 ------------------------------------------------------------------------

public_block_keys := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

public_blocked(cfg) := count([k |
	some k in public_block_keys
	object.get(cfg, ["public_access_block", k], false) == true
]) == count(public_block_keys)

results contains result("s3_public_access_blocked", res, public_blocked(res.config), "all four public access block settings must be true") if {
	some res in input.resources
	res.type == "aws_s3_bucket"
}

results contains result("s3_access_logging", res, ok, "server access logging must be enabled") if {
	some res in input.resources
	res.type == "aws_s3_bucket"
	ok := object.get(res.config, ["logging", "enabled"], false) == true
}

# --- Encryption at rest -----------------------------------------------------------

encryption_path := {
	"aws_s3_bucket": ["encryption", "enabled"],
	"aws_ebs_volume": ["encrypted"],
	"aws_db_instance": ["storage_encrypted"],
}

results contains result("storage_encrypted", res, ok, "storage must be encrypted at rest") if {
	some res in input.resources
	path := encryption_path[res.type]
	ok := object.get(res.config, path, false) == true
}

# --- Security groups ------------------------------------------------------------------

admin_ports := {22, 3389}

open_admin_ports(cfg) := {port |
	some rule in object.get(cfg, "ingress", [])
	some cidr in rule.cidrs
	cidr in {"0.0.0.0/0", "::/0"}
	some port in admin_ports
	rule.from_port <= port
	port <= rule.to_port
}

results contains result("sg_no_open_admin_ports", res, count(open) == 0, msg) if {
	some res in input.resources
	res.type == "aws_security_group"
	open := open_admin_ports(res.config)
	msg := sprintf("SSH/RDP must not be open to the internet (open: %v)", [sort(open)])
}

# --- IAM ---------------------------------------------------------------------------------

results contains result("iam_console_user_mfa", res, ok, "users with console access must have MFA") if {
	some res in input.resources
	res.type == "aws_iam_user"
	object.get(res.config, "console_access", false) == true
	ok := object.get(res.config, "mfa_enabled", false) == true
}

# --- CloudTrail ------------------------------------------------------------------------

results contains result("cloudtrail_multi_region", res, ok, "trail must be logging and multi-region") if {
	some res in input.resources
	res.type == "aws_cloudtrail"
	ok := count([f |
		some f in ["is_logging", "multi_region"]
		object.get(res.config, f, false) == true
	]) == 2
}
