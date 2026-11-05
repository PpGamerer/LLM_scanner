import json
from collections import defaultdict

report_path = "core/results/20260927_201500_huihui_ai_llama3.2-abliterate_1b/garak_scan_huihui_ai_llama3.2-abliterate_1b.report.jsonl"

per_probe = defaultdict(lambda: {"entries": 0, "detectors": set(), "totals": []})

with open(report_path, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        if entry.get("entry_type") != "eval":
            continue
        probe = entry.get("probe", "")
        per_probe[probe]["entries"] += 1
        per_probe[probe]["detectors"].add(entry.get("detector", ""))
        per_probe[probe]["totals"].append(entry.get("total_evaluated") or entry.get("total_processed") or 0)

print(f"{'probe':<35} {'#eval entries':<15} {'#detectors':<12} {'totals ต่อ entry'}")
for probe, info in sorted(per_probe.items()):
    print(f"{probe:<35} {info['entries']:<15} {len(info['detectors']):<12} {info['totals']}")