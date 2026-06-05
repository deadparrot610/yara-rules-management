// Override rules live here. Each rule must be declared in override_manifest.yaml.

rule vendor_override_overridden {
	meta:
		description = "Vendor overriden"
		feature     = "Vendor overriden"
	strings:
		$a = "overriden"
	condition:
		$a
}
