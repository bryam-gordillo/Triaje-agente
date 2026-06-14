# Test plan

## Automated (pytest)
- test_classifier.py: malicious alerts flagged (recall), benign mostly filtered, blocked threats benign.
- test_correlation.py: incidents form; benign noise excluded.
- test_end_to_end.py: a critical incident on a crown jewel escalates; nothing escalated is auto-resolved; every alert has exactly one result; eval thresholds met (recall-first).
- test_ingest.py: arbitrary-vendor alerts normalize; stable ids; pipeline runs on normalized real alerts.

## Evaluation (eval.py)
Confusion matrix + precision/recall/F1 vs ground truth. Recall-first gate:
recall>=0.85 and a critical incident reaching a human.

## Manual / demo
python main.py -> incidents + auto-resolved; telemetry/*.jsonl shows the reasoning
trace; outputs/oncall_queue.jsonl shows escalations.
