#!/bin/zsh
# End-to-end final run: main suite -> mutation testing -> scope scaling.
# Logs to results_final/run_final.log. Bounded checking only (Alloy 6.2.0).
set -u
cd "${0:A:h}"
mkdir -p results_final
LOG=results_final/run_final.log
stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }
{
  echo "== START $(stamp)  model sha256=$(shasum -a 256 models/blockcap_final.als | cut -d' ' -f1)"
  echo "== MAIN $(stamp)"
  python3 tools/run_suite.py suites/main.json --jobs 4
  echo "== MUTATION $(stamp)"
  python3 tools/mutation_test.py --final --jobs 4 --timeout 1800
  echo "== SCALING $(stamp)"
  python3 tools/run_suite.py suites/scaling.json --jobs 4 --budget 14400
  echo "== END $(stamp)"
} 2>&1 | tee -a $LOG
