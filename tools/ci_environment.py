"""Record explicit build versions and public run IDs, never dump environment."""
from pathlib import Path
import json
import os
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
def version(command):
    return subprocess.check_output([command, '--version'], text=True, timeout=10).splitlines()[0]

result = {
    'scope': 'Build environment only, not a device measurement',
    'system': platform.system(),
    'architecture': platform.machine(),
    'python': sys.version.splitlines()[0],
    'clang': version(os.environ.get('LLVM_CLANG', 'clang')),
    'linker': version(os.environ.get('LLVM_LD', 'ld.lld')),
    'qemu': version(os.environ.get('QEMU_ARM', 'qemu-system-arm')),
    'public_ci_metadata': {key: os.environ[key] for key in (
        'GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
        'RUNNER_OS', 'RUNNER_ARCH', 'ImageOS', 'ImageVersion') if key in os.environ},
}
dest = ROOT/'.test-results'
dest.mkdir(exist_ok=True)
(dest/'ci-environment.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
