from pathlib import Path
from collections import Counter
import json,hashlib,statistics
from models import evaluate
N=Path('work/uv310-wireguard/jent-trace-repeat');E=Path('outputs/uv310-wireguard/evidence')
load=lambda n:json.loads((E/n).read_text())
first=load('jent-trace-live.json');second=load('jent-trace-repeat-live.json')
assert first['rollback_complete'] and second['rollback_complete']
provenance=load('jent-trace-repeat-provenance.json');frozen=load('jent-trace-repeat-frozen-model.json')
assert hashlib.sha256((E/'jent-trace-repeat-frozen-model.json').read_bytes()).hexdigest()==provenance['model_frozen_before_second_candidate_deployment']
assert hashlib.sha256((N/'models.py').read_bytes()).hexdigest()==frozen['models_code_sha256']
assert hashlib.sha256((E/'jent-trace-live.json').read_bytes()).hexdigest()==provenance['first_capture_sha256']
capture=second.get('capture',{})
if not capture.get('full_startup_and_capture') or capture.get('trace_error'):
 result={'analysis_completed':False,'reason':'Second capture incomplete or error','second_status':second.get('probe_status'),'secure_entropy_established':False}
else:
 a=first['capture']['raw_deltas'];b=capture['raw_deltas'];assert len(a)==len(b)==512
 predictions=evaluate(frozen['model'],b,frozen['second_boot_evaluation_start_index'])
 for p in predictions:p['accuracy']=p['exact_hits']/p['total']
 same=sum(x==y for x,y in zip(a,b));prefix=0
 for x,y in zip(a,b):
  if x!=y:break
  prefix+=1
 counts=Counter(b)
 result={'analysis_completed':True,'candidate_unchanged':True,'full_second_capture':True,'second_startup_result':capture['probe_status'][3],
         'second_count':512,'second_unique':len(counts),'second_min':min(b),'second_max':max(b),'second_median':statistics.median(b),
         'second_most_common':[[x,n] for x,n in counts.most_common(10)],'same_ordinal_exact_matches':same,'identical_prefix_samples':prefix,
         'shared_unique_values':len(set(a)&set(b)),'frozen_first_boot_predictors':predictions,'test_count':480,'test_indices':[32,511],
         'first32_second_boot_samples_used_only_as_causal_context':True,'new_boot_model_fitting_or_phase_alignment':False,'secure_entropy_established':False,
         'limitations':['Two software-reset Wi-Fi boots under similar quiet conditions; not power-cycle or stress coverage',
                        'The first32 new samples are causal context only, not model training',
                        'A failed predictor does not establish entropy or security; exact-value shifts can reduce accuracy',
                        'Instrumentation and changed resident layout remain part of the measured source',
                        'No entropy lower bound, cryptographic random output, or WireGuard performance claim']}
(E/'jent-trace-repeat-analysis.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
