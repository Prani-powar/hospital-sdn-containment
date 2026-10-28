"""Explicit fault injection affecting only resources owned by one experiment."""
import re
import subprocess
from topology.restriction_demo import ofctl


def inject(experiment, fault):
    if fault == 'decision-stop':
        process = next(p for name,p in experiment.processes if name=='decision')
        process.terminate()
        process.wait(timeout=5)
    elif fault == 'controller-restart':
        cid=(experiment.directory/'controller.cid').read_text().strip()
        if not re.fullmatch('[0-9a-f]{64}',cid): raise ValueError('Invalid owned controller ID')
        subprocess.run(['docker','restart','--time','2',cid],check=True,capture_output=True,timeout=20)
    elif fault == 'switch-disconnect':
        bridge=experiment.topology['switches'][-1]['name']
        subprocess.run(['ovs-vsctl','--timeout=5','del-controller',bridge],check=True,capture_output=True,timeout=8)
    else:
        raise ValueError('Unknown fault')


def classify(fault, error):
    expected={'decision-stop':('decision exited unexpectedly',),
              'controller-restart':('Controller restarted','controller exited unexpectedly','Controller/switch health degraded'),
              'switch-disconnect':('Controller/switch health degraded',)}
    return any(message in error for message in expected[fault])
