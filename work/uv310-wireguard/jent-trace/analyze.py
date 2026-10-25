"""Descriptive/held-out predictability diagnostics, never an entropy estimate."""
from collections import Counter,defaultdict
from pathlib import Path
import json,statistics

def mode(xs):
 counts=Counter(xs)
 return min(counts,key=lambda x:(-counts[x],x))

def diagnostics(data):
 assert len(data)==512 and all(type(x)==int and 0<=x<=0xffffffff for x in data)
 cut=256;train=data[:cut];test=data[cut:];counts=Counter(data);base=mode(train)
 rows=[]
 def add(name,predict,details=None):
  hits=sum(predict(i)==data[i] for i in range(cut,len(data)))
  rows.append({'predictor':name,'test_exact_hits':hits,'test_total':len(test),'test_accuracy':hits/len(test),'training':details or 'first256 only; test previous observations may be causal inputs'})
 add('fixed_training_mode',lambda i:base,{'value':base})
 add('previous_value',lambda i:data[i-1],'no fitting; causal previous observed sample')
 lag=max(range(1,33),key=lambda k:(sum(train[i]==train[i-k] for i in range(32,cut)),-k))
 add('training_selected_lag_copy',lambda i:data[i-lag],{'selected_lag':lag,'candidates':list(range(1,33)),'selection_indices':[32,255]})
 difference=mode([train[i]-train[i-1] for i in range(1,cut)])
 add('training_modal_difference',lambda i:data[i-1]+difference,{'difference':difference})
 maps={}
 for width in (1,2):
  buckets=defaultdict(list)
  for i in range(width,cut):buckets[tuple(train[i-width:i])].append(train[i])
  maps[width]={key:mode(values) for key,values in buckets.items()}
  def pred(i,w=width):
   value=maps[w].get(tuple(data[i-w:i]))
   return maps[1].get((data[i-1],),base) if value is None else value
  add('training_transition_order'+str(width),pred,{'contexts':len(maps[width]),'unseen_context_fallback':'order1 then fixed training mode'})
 phase_candidates=[]
 for period in range(1,33):
  phases=[mode(train[p::period]) for p in range(period)]
  correct=sum(train[i]==phases[i%period] for i in range(cut))
  phase_candidates.append((correct,-period,phases))
 _,negative_period,phases=max(phase_candidates,key=lambda x:x[:2]);period=-negative_period
 add('training_selected_phase_mode',lambda i:phases[i%period],{'period':period,'phase_modes':phases,'candidates':list(range(1,33))})
 longest=run=1
 for i in range(1,len(data)):
  run=run+1 if data[i]==data[i-1] else 1;longest=max(longest,run)
 head=Counter(train);tail=Counter(test)
 tv=0.5*sum(abs(head[x]/cut-tail[x]/len(test)) for x in set(head)|set(tail))
 return {'count':len(data),'min':min(data),'max':max(data),'median':statistics.median(data),
         'unique_values':len(counts),'most_common':[[x,n] for x,n in counts.most_common(12)],
         'longest_identical_run':longest,'adjacent_equal_count':sum(data[i]==data[i-1] for i in range(1,len(data))),
         'train_count':cut,'held_out_count':len(test),'train_test_empirical_total_variation':tv,
         'predictors':rows,'entropy_bits_estimated':False,'secure_entropy_established':False,
         'limitations':['512 samples from one instrumented startup are insufficient for source validation',
                        'Prediction success demonstrates predictability; prediction failure does not establish unpredictability',
                        'Held-out samples are a continuation of the same boot, not an independent reboot/run',
                        'Phase and lag choices use training only; model list and offsets are fixed before physical capture',
                        'Timing includes sampling/scheduler/instrumentation work and may include interrupts',
                        'Counts are DWT-cycle deltas, not nanoseconds, output bits, or WireGuard performance']}

if __name__=='__main__':
 E=Path('outputs/uv310-wireguard/evidence');live=json.loads((E/'jent-trace-live.json').read_text())
 assert live['rollback_complete']
 cap=live.get('capture')
 if not cap or not cap['full_startup_and_capture'] or cap['trace_error']:
  result={'analysis_completed':False,'reason':'No complete error-free physical capture','capture_metadata':{k:v for k,v in (cap or {}).items() if k!='raw_deltas'},'secure_entropy_established':False}
 else:
  result=diagnostics(cap['raw_deltas']);result.update(analysis_completed=True,sample_start_index=cap['sample_start_index'],physical_startup_result=cap['probe_status'][3])
 (E/'jent-trace-analysis.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({k:v for k,v in result.items() if k not in ['predictors','most_common','limitations']},indent=2))
