"""Collect three owned normal lab runs and train standalone Isolation Forest.

Run only on the Linux lab with Mininet/Docker/OVS installed, after stopping any
other lab launcher. Does not change defaults or start enforcement automatically.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=ROOT/'artifacts'/('isolation-'+uuid.uuid4().hex))
    args=p.parse_args()
    if not sys.platform.startswith('linux') or os.geteuid()!=0:
        p.error('Run on Linux with sudo using the Python environment containing Mininet and ML dependencies')
    missing=[name for name in ('mininet','sklearn','numpy','joblib') if importlib.util.find_spec(name) is None]
    if missing:p.error('Missing Python packages: '+', '.join(missing)+'; see docs/ISOLATION_FOREST.md')
    from decision.train_isolation import train
    from experiments.dataset import label
    from experiments.run import read_jsonl
    try:
        args.output.mkdir(parents=True,exist_ok=False)
        paths=[]
        for seed in (101,102,103):
            print(f'Collecting controlled normal run, seed {seed}; no attack is launched.',flush=True)
            result=subprocess.run([sys.executable,'-u','-m','experiments.run','--baseline','B0','--normal-only',
                                   '--seed',str(seed),'--duration','60'],cwd=ROOT,capture_output=True,text=True)
            (args.output/f'collection-{seed}.log').write_text(result.stdout+result.stderr)
            # This is the command's own completion record, not an inferred newest directory.
            completions=[]
            for line in result.stdout.splitlines():
                try:row=json.loads(line)
                except ValueError:continue
                if row.get('check')=='research_run_finished':completions.append(row)
            if result.returncode or len(completions)!=1:
                raise ValueError(f'Collection failed; inspect {args.output}/collection-{seed}.log; no retry or cleanup attempted')
            directory=Path(completions[0]['report']).resolve().parent
            if not directory.is_relative_to((ROOT/'artifacts/demo').resolve()):raise ValueError('Unexpected run directory')
            report=json.loads((directory/'research-report.json').read_text())
            if (not report.get('normal_only') or report.get('instrumentation_status')!='COMPLETE'
                    or report.get('error') or report.get('cleanup_errors') or report.get('seed')!=seed):
                raise ValueError('Normal-run provenance/instrumentation incomplete')
            truth=read_jsonl(directory/'ground-truth.jsonl')
            if truth:raise ValueError('Normal run unexpectedly contains attack/infection events')
            rows=label(read_jsonl(directory/'features.jsonl'),[],[],report['warmup_start_ns'],report['end_ns'])
            output=args.output/f'normal-{seed}.jsonl'
            output.write_text(''.join(json.dumps(dict(r,seed=seed,partition='validation',
                    label_provenance='controlled_normal_only_lab_run'))+'\n' for r in rows))
            paths.append(output)
        train(paths[:2],paths[2:],args.output/'model')
        print(json.dumps({'check':'isolation_lab_model_ready','model_directory':str((args.output/'model').resolve()),
                          'next':'Start scripts/lab.py --detector M1 --model-directory MODEL_DIRECTORY',
                          'limits':'Training/calibration complete; held-out attack and OVS enforcement testing still required'}))
        return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'check':'isolation_bootstrap_failed','error':str(exc)}));return 1

if __name__=='__main__':raise SystemExit(main())
