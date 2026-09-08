/*
 * malforge - sample YARA rules
 * These rules are generated from BENIGN fixture samples and are provided
 * as a demonstration of rule output. Authorized lab use only.
 */
rule malforge_sample_hello {
  meta:
    author = "malforge"
    description = "Example rule for a benign hello fixture"
  strings:
    $s0 = "hello_malforge_fixture"
    $s1 = "greeting="
  condition:
    2 of ($s0, $s1)
}

rule malforge_sample_entropy_guard {
  meta:
    author = "malforge"
    description = "Entropy high-band guard (educational example)"
  condition:
    uint32(0) == 0x464C457F and filesize < 4MB
}