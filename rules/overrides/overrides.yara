// Override rules live here. Each rule must be declared in override_manifest.yaml.

rule Custom_Override_Placeholder {
    meta:
        author = "fritz"
        date = "2026-06-02"
        description = "Override for the scaffold placeholder vendor rule (Phase 1 test fixture)"
        reference = "internal"
        severity = "low"
    strings:
        $a = "override-marker"
    condition:
        $a
}
