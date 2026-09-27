from pathlib import Path
import json
source=Path(__file__).resolve().parent.parent/'2026-09-24-native-two-level-frontier/geometry.json'
data=json.loads(source.read_text())
actual=sum(int(row['g_rows']) for row in data['BLAKE3_HASH_METADATA'][-2:])
remaining=sum(int(row['gross_candidate_g_rows']) for row in data['BLAKE3_PATH_SHARING_TOTAL'][-2:])
result=dict(root_actual_g=actual, remaining_duplicate_upper_g=remaining,
            optimistic_floor_g=actual-remaining, next_domain_g=1<<22,
            excess_g=actual-remaining-(1<<22))
assert result['excess_g']>0
print(json.dumps(result,indent=2))
