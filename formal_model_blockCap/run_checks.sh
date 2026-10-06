#!/bin/zsh
# Run every command of an Alloy model with Alloy 6.2.0 and record the outcome
# of each in <results dir>/summary.txt.
# Usage: ./run_checks.sh [model.als]   (default: models/blockcap_system_model.als)
# Results go to results/ for the default model, results_<model stem>/ otherwise.
#   run   commands: SAT = instance found (scenario reachable), UNSAT = not reachable
#   check commands: UNSAT = no counterexample within scope, SAT = counterexample found
set -u
cd "${0:A:h}"
JAR=tools/org.alloytools.alloy.dist.jar
MODEL=${1:-models/blockcap_system_model.als}
stem=${MODEL:t:r}
if [[ $stem == blockcap_system_model ]]; then RES=results; else RES=results_$stem; fi
mkdir -p $RES
SUMMARY=$RES/summary.txt
{
  echo "Alloy: $(java -jar $JAR version 2>&1 | head -1)"
  echo "Model: $MODEL  sha256=$(shasum -a 256 $MODEL | cut -d' ' -f1)"
  echo "Date:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
} > $SUMMARY
n=$(java -jar $JAR commands $MODEL 2>/dev/null | grep -c '^[0-9]')
for (( i=0; i<n; i++ )); do
  name=$(java -jar $JAR commands $MODEL 2>/dev/null | grep "^$i \." | sed 's/^[0-9]* \. //')
  out=$RES/cmd_$i
  start=$(date +%s)
  java -jar $JAR exec -n -q -f -c $i -o $out -t json $MODEL > $out.log 2>&1
  rc=$?
  secs=$(( $(date +%s) - start ))
  if [[ -n $(find $out -name '*-solution-0.json' 2>/dev/null) ]]; then verdict=SAT; else verdict=UNSAT; fi
  [[ $rc -ne 0 ]] && verdict="ERROR(rc=$rc)"
  printf "%-6s %5ss  [%d] %s\n" "$verdict" "$secs" "$i" "$name" | tee -a $SUMMARY
done
