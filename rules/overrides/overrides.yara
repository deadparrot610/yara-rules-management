// Override rules live here. Each rule must be declared in override_manifest.yaml.

rule vendor_override_overridden {
	meta:
		author      = "fritz.s.cheung@gmail.com"
		date        = "2026-06-02"
		description = "Vendor overriden"
		reference   = "n/a"
		severity    = "high"
		feature     = "Vendor overriden"
	strings:
		$a = "overriden"
	condition:
		$a
}
