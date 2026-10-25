"""Small diagnostic only: predefined 16-transition fit, 15 held-out transitions.
No entropy estimate and no claims from passing a small-sample statistical check.
"""
from pathlib import Path
import json,hashlib

def linear_fit(xs):
    basis={};consistent=True
    for x,y in zip(xs[:16],xs[1:17]):
        while x:
            b=x.bit_length()-1
            if b not in basis:basis[b]=(x,y);break
            a,v=basis[b];x^=a;y^=v
        if not x and y:consistent=False
    return basis,consistent

def predict(x,basis):
    y=0
    while x:
        b=x.bit_length()-1
        if b not in basis:return None
        a,v=basis[b];x^=a;y^=v
    return y

def analyze(raw):
    assert len(raw)==64
    xs=[int.from_bytes(raw[i:i+2],'big') for i in range(0,64,2)]
    basis,consistent=linear_fit(xs)
    predicted=[predict(xs[i],basis) for i in range(16,31)] if consistent else []
    return {'words':32,'byte_order':'Each helper output pair is big endian',
      'unique_words':len(set(xs)),'zero_words':xs.count(0),'all_ones_words':xs.count(65535),
      'adjacent_equal':sum(a==b for a,b in zip(xs,xs[1:])),
      'ones_per_bit_lsb_first':[sum((x>>b)&1 for x in xs) for b in range(16)],
      'linear_transition_model':{'train_transitions':16,'heldout_transitions':15,'basis_rank':len(basis),
        'training_consistent':consistent,'test_predictions_in_train_span':sum(y is not None for y in predicted),
        'test_exact_hits':sum(y is not None and y==xs[i+17] for i,y in enumerate(predicted)),
        'not_refit_on_test':True},
      'raw_words_hex':[f'{x:04x}' for x in xs],
      'secure_entropy_established':False,
      'limitations':['Only 32 consecutive hardware words from one boot; no entropy bound',
       'Predictability by this one model would be evidence for further investigation; failure to predict does not establish unpredictability',
       'No keys, nonce provisioning, reseeding, conditioned RNG or WireGuard integration in this capture']}

if __name__=='__main__':
    E=Path('outputs/uv310-wireguard/evidence')
    d=json.loads((E/'rng-sample-live.json').read_text())
    assert d['rollback_complete'] and d.get('probe_status',[0])[0]==10
    result=analyze(bytes.fromhex(d['raw_diagnostic_bytes_hex']))
    result['analysis_code_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (E/'rng-sample-analysis.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='raw_words_hex'},indent=2))
