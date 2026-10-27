# Bundled Opengrep rules

The 79 Python and JavaScript YAML rules in this directory come from
[`patched-codes/semgrep-rules`](https://github.com/patched-codes/semgrep-rules)
at commit `1118d79823ae756534678378a4aac0cbfa5d3041`. Their upstream MIT
license is copied as [`LICENSE`](LICENSE). [`manifest.json`](manifest.json)
records the SHA-256 of every included rule. The YAML bytes match that pinned
upstream revision; the upstream test scripts are not bundled or executed.

SecRAGraph runs these rules with Opengrep 1.32.0 against a bounded text-only
snapshot. Opengrep's `--taint-intrafile` tracks flows within a file. It does
not establish arbitrary cross-file flows for private member uploads. The
public repository's separate CodeQL workflow supplies cross-file flow
analysis for that public code. Rule matches are leads for review, not proof of
exploitability or a measured real-world detection rate.
