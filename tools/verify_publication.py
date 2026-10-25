"""Verify published file integrity, JSON syntax and local Markdown file links."""
from pathlib import Path
import hashlib,json,re
ROOT=Path(__file__).resolve().parents[1]
errors=[];count=0
for line in (ROOT/'MANIFEST.sha256').read_text().splitlines():
 digest,name=line.split('  ',1);p=ROOT/name
 if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:errors.append(name)
 count+=1
for p in ROOT.rglob('*.json'):
 if '.git' not in p.parts and '.test-results' not in p.parts:json.loads(p.read_text())
for p in ROOT.rglob('*.md'):
 if '.git' in p.parts:continue
 for link in re.findall(r'\]\(([^)]+)\)',p.read_text()):
  if re.match(r'\w+:|#',link):continue
  target=link.split('#',1)[0]
  if target and not (p.parent/target).exists():errors.append(f'{p.relative_to(ROOT)} -> {target}')
assert not errors,errors
print(f'PASS {count} manifest entries, JSON parse, local Markdown file links. Not a secret scanner.')
