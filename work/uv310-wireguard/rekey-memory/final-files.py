from pathlib import Path
import json,usb.util
import efs_rekey as p
p.fs.d=p.verify_device();usb.util.claim_interface(p.fs.d,3)
try:
 blob,mode=p.read(p.ACTIVE);assert p.sha(blob)==p.ORIGINAL
 files=[]
 for f in [p.BACKUP,p.STAGED]:
  errno,_,_=p.fs.stat(f);assert errno==2
  files.append({'path':f,'errno':errno,'absent':True})
 e={'stock_sha256':p.sha(blob),'stock_bytes':len(blob),'research_files':files,'passed':True}
finally:usb.util.release_interface(p.fs.d,3);usb.util.dispose_resources(p.fs.d)
Path('outputs/uv310-wireguard/evidence/rekey-memory-final-files.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e,indent=2))
