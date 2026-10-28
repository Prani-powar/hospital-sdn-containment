"""Run the portable, unprivileged checks used by teammates and CI."""
from pathlib import Path
import subprocess
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
SUITES = [('controller/tests','test*.py'), ('decision/tests','test*.py'),
          ('topology/tests','test*.py'), ('dashboard','test*.py'), ('scripts/tests','test*.py'), ('infra/tests','test*.py'), ('experiments/tests','test*.py')]


def main():
    for folder, pattern in SUITES:
        print(f'Checking {folder}', flush=True)
        result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', folder,
                                 '-p', pattern, '-v'], cwd=ROOT)
        if result.returncode:
            return result.returncode
    node = shutil.which('node')
    if node:
        result = subprocess.run([node, 'dashboard/test_live_ui.js'], cwd=ROOT)
        if result.returncode:
            return result.returncode
    else:
        print('Node unavailable: UI logic check skipped; Python checks remain separate.', flush=True)
    print('Portable checks passed. Ryu image and real OVS checks are separate pending gates.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
