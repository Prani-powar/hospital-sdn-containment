"""Train standalone per-role Isolation Forest from disjoint measured normal runs.

No attack examples, Random Forest, HTTP endpoint or switch access is needed.
Generated joblib files must remain trusted local artifacts.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from decision.model_contract import FEATURE_VERSION, MODEL_FIELDS, ROLES
from decision.features import FEATURE_FIELDS


def read_normal(paths):
    rows=[]; seen=set()
    for path in paths:
        if not path.is_file() or path.stat().st_size > 200_000_000:
            raise ValueError('Normal input missing or larger than 200 MB')
        for line in path.read_text().splitlines():
            if not line.strip(): continue
            row=json.loads(line)
            f=row.get('feature',{});q=row.get('quality',{})
            if (row.get('label') != 'normal' or row.get('partition') != 'validation'
                    or type(row.get('seed')) is not int or row['seed'] not in range(101,111)):
                raise ValueError('Training requires normal-labelled validation-seed records (101..110)')
            if (set(f)!=set(FEATURE_FIELDS) or q.get('valid') is not True
                    or q.get('feature_spec_version')!=FEATURE_VERSION or f.get('role') not in ROLES):
                raise ValueError('Invalid normal feature contract or quality')
            if not all(type(f[k]) is int and 0<=f[k]<2**63 for k in MODEL_FIELDS):
                raise ValueError('Invalid feature number')
            if (not isinstance(row.get('run_id'),str) or not row['run_id']
                    or type(f.get('timestamp_ns')) is not int):
                raise ValueError('Run identity and timestamp required')
            identity=(row['run_id'],f['host'],f['timestamp_ns'])
            if identity in seen: raise ValueError('Duplicate training window')
            seen.add(identity);rows.append(row)
    if not rows: raise ValueError('No normal windows')
    return rows


def train(train_paths, calibration_paths, output, *, seed=42, false_alarm_quantile=.99):
    if not .90<=false_alarm_quantile<1: raise ValueError('Calibration quantile must be .90..<1')
    if output.exists(): raise ValueError('Choose a new output directory; existing models are never overwritten')
    fitting,calibration=read_normal(train_paths),read_normal(calibration_paths)
    fit_runs={r['run_id'] for r in fitting};cal_runs={r['run_id'] for r in calibration}
    fit_seeds={r['seed'] for r in fitting};cal_seeds={r['seed'] for r in calibration}
    if fit_runs & cal_runs or fit_seeds & cal_seeds:
        raise ValueError('Fit and calibration runs AND seeds must be disjoint')
    models={};thresholds={};summary={}
    for role in sorted(ROLES):
        fit=np.array([[r['feature'][k] for k in MODEL_FIELDS] for r in fitting if r['feature']['role']==role])
        cal=np.array([[r['feature'][k] for k in MODEL_FIELDS] for r in calibration if r['feature']['role']==role])
        if len(fit)<20 or len(cal)<20:
            raise ValueError('At least 20 fit and 20 calibration windows needed for role: '+role)
        model=make_pipeline(StandardScaler(),IsolationForest(n_estimators=200,contamination='auto',random_state=seed,n_jobs=1))
        model.fit(fit)
        scores=-model.decision_function(cal)
        threshold=float(np.quantile(scores,false_alarm_quantile,method='higher'))
        if not math.isfinite(threshold): raise ValueError('Non-finite calibration threshold')
        models[role]=model;thresholds[role]=threshold
        summary[role]={'fit_windows':len(fit),'calibration_windows':len(cal),
                       'calibration_alarm_fraction':float(np.mean(scores>threshold)),
                       'constant_fit_fields':[k for k,v in zip(MODEL_FIELDS,np.ptp(fit,axis=0)) if v==0]}
    metadata={'schema_version':1,'artifact_type':'isolation-forest-only-v1',
              'created_at':datetime.now(timezone.utc).isoformat(),'feature_spec_version':FEATURE_VERSION,
              'training_seed':seed,'sklearn_version':sklearn.__version__,
              'model_fields':list(MODEL_FIELDS),'fit_seeds':sorted(fit_seeds),'calibration_seeds':sorted(cal_seeds),
              'split':{'train_runs':sorted(fit_runs),'validation_runs':sorted(cal_runs),'test_runs':[]},
              'calibration':{'normal_quantile':false_alarm_quantile,'comparison':'strictly greater than raw threshold'},
              'roles':summary,'input_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in train_paths+calibration_paths},
              'limits':'Normal-only fit/calibration. Attack accuracy and real OVS containment are not measured by training.'}
    output.mkdir(parents=True,exist_ok=False)
    joblib.dump({'feature_spec_version':FEATURE_VERSION,'model_fields':MODEL_FIELDS,
                 'models':models,'raw_score_thresholds':thresholds},output/'m1_isolation_forest.joblib')
    (output/'metrics.json').write_text(json.dumps(metadata,indent=2,allow_nan=False)+'\n')
    return metadata


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--train',type=Path,action='append',required=True)
    p.add_argument('--calibration',type=Path,action='append',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seed',type=int,default=42)
    p.add_argument('--normal-quantile',type=float,default=.99)
    args=p.parse_args()
    try:
        metadata=train(args.train,args.calibration,args.output,seed=args.seed,false_alarm_quantile=args.normal_quantile)
        print(json.dumps({'check':'isolation_forest_trained','output':str(args.output),'roles':metadata['roles']}))
        return 0
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({'check':'isolation_training_failed','error':str(exc)}));return 1

if __name__=='__main__':raise SystemExit(main())
