// Exercise actual UI logic with tiny DOM adapters; no browser/rendering claim.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'app.js'),'utf8');
const elements=new Map();
const context={hosts:[{name:'reception1',role:'admin'},{name:'monitor1',role:'iomt'}],roles:{admin:{action:'ISOLATE'}},state:{mode:'live',decision:null},$:(id)=>{if(!elements.has(id))elements.set(id,{textContent:''});return elements.get(id);},Set,Error,Object,Array,Number};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('function counterDelta(previous,current)'),source.indexOf('// ─── Human Override panel')),context);
for(const [start,end] of [['function posture(host)','function renderHost()'],['function renderCriticalEvidence(clinical)','function validateDemoReport(report)'],['function validateDemoReport(report)','function renderDemoEvidence(report)']]){
 vm.runInContext(source.slice(source.indexOf(start),source.indexOf(end)),context);
}
const host={name:'reception1'};
assert.equal(context.posture(host),'UNSCORED');
context.state.decision={quality:'invalid',hosts:{},actions:[{host:'reception1',status:'pending'}]};
assert.equal(context.posture(host),'PENDING');
context.state.decision.actions[0]={host:'reception1',action:'ISOLATE',status:'confirmed'};
assert.equal(context.posture(host),'ISOLATE ACK');
context.state.decision.actions=[];
assert.equal(context.posture(host),'UNSCORED');
context.state.decision.quality='ready';context.state.decision.hosts.reception1={score:{anomalous:true}};
assert.equal(context.posture(host),'SUSPECT');
context.renderCriticalEvidence(null);
assert.equal(elements.get('critical-value').textContent,'Unmeasured');
context.renderCriticalEvidence({measurement:{status:'PASS',services:[{sources:[{attempted:10,received:10}]}]}});
assert.equal(elements.get('critical-foot').textContent,'10 / 10 replies · 1 sources · recent measured interval');
const inventory={C1:['monitor1','monitor2','monitor3'],C2:['pump1','pump2'],C3:['imaging1'],C4:['nurse1','nurse2','nurse3','doctor1','doctor2','doctor3'],C5:['lis']};
const report={check:'hospital_demo_report',schema_version:1,status:'PASS',mode:'enforce',run_id:'a'.repeat(32),phases:{},confirmed_actions:[{host:'reception1',action:'ISOLATE',status:'confirmed',proposal_id:'b'.repeat(64),confirmed_ns:20},{host:'reception1',action:'RELEASE',status:'confirmed',proposal_id:'c'.repeat(64),confirmed_ns:50}]};
for(const [name,start_ns,end_ns] of [['baseline',1,10],['restricted',30,40],['recovered',60,70]])report.phases[name]={start_ns,end_ns,ping:{exit_code:name==='restricted'?1:0,executed:true},clinical:{status:'PASS',services:Object.entries(inventory).map(([flow_id,names])=>({flow_id,sources:names.map(source=>({source,attempted:10,received:10,invalid_records:0,status:'PASS'}))}))}};
assert.equal(context.validateDemoReport(report),report);
for(const mutate of [r=>r.phases.restricted.clinical.services[0].sources[0].received=0,r=>r.confirmed_actions=[],r=>r.phases.restricted.ping.exit_code=2,r=>r.phases.restricted.clinical.services.pop()]){const bad=structuredClone(report);mutate(bad);assert.throws(()=>context.validateDemoReport(bad));}

context.state.mode='demo';context.state.source='reception1';context.state.marked=true;
for(const phase of [0,1,2,3]){context.state.phase=phase;assert.match(context.posture({name:'reception1',role:'admin'}),/COMPROMISED/);}
assert.equal(context.posture({name:'monitor1',role:'iomt'}),'NORMAL');
context.state.marked=false;assert.equal(context.posture({name:'reception1',role:'admin'}),'NORMAL');
context.state.mode='live';context.state.liveMarked='reception1';context.state.decision={quality:'ready',hosts:{reception1:{score:{anomalous:false}}},actions:[{host:'reception1',action:'RELEASE',status:'confirmed'}]};
assert.equal(context.posture({name:'reception1'}),'FLAGGED · NO ALERT');
const varied=structuredClone(report);varied.source_host='monitor1';varied.containment_action='RESTRICT';for(const a of varied.confirmed_actions){a.host='monitor1';if(a.action==='ISOLATE')a.action='RESTRICT';}assert.equal(context.validateDemoReport(varied),varied);
varied.containment_action='ISOLATE';assert.throws(()=>context.validateDemoReport(varied));
const previous={epoch:'e',complete:true,time:1e9,totals:{a:{packets:2,duration:1e9}}};
const current={epoch:'e',complete:true,time:2e9,totals:{a:{packets:7,duration:2e9}}};
assert.equal(context.counterDelta(previous,current).rate,5);
assert.equal(context.counterDelta({...previous,complete:false},current).rate,null);
assert.equal(context.counterDelta(previous,{...current,epoch:'new'}).rate,null);
assert.equal(context.counterDelta(previous,{...current,totals:{}}).rate,null);
assert.equal(context.counterDelta(previous,{...current,totals:{a:{packets:1,duration:2e9}}}).rate,null);
console.log('UI logic passed: evidence visibility, clinical counts, and report validation. Browser rendering is a separate check.');

// Evidence provenance, timing and review gates use the actual shipped functions.
vm.runInContext(source.slice(source.indexOf('// Thresholds mirror'),source.indexOf('initialiseAttackControls();drawFabric();')),context);
assert.equal(context.demoDetection(3,'admin').anomalous,false);
assert.equal(context.demoDetection(9,'admin').streak,0);
assert.equal(context.demoDetection(10,'admin').streak,1);
assert.equal(context.demoDetection(15,'admin').streak,2);
assert.equal(context.demoDetection(20,'critical_server').anomalous,false);
const measured={quality:'ready',timestamp_ns:10e9,detection_policy:{max_feature_age_s:4,anomalous_windows:2},hosts:{reception1:{feature:{timestamp_ns:9e9,window_s:5,unique_dst:10,unique_dst_ports:20,off_allow_list_flows:4},score:{anomalous:true},detection:{anomalous_streak:2,thresholds:{unique_dst:8,unique_dst_ports:12,off_profile_min:1}},evidence_censored:true}}};
assert.equal(context.liveDetection(measured,'reception1').streak,2);
assert.equal(context.liveDetection(measured,'reception1').censored,true);
assert.equal(context.liveDetection({...measured,quality:'invalid'},'reception1'),null);
assert.equal(context.liveDetection({...measured,timestamp_ns:20e9},'reception1'),null);
assert.equal(context.liveDetection(measured,'unknown'),null);
const deliveries=context.deliveryRows({measurement:{services:[{flow_id:'C1',sources:[{source:'monitor1',attempted:10,received:10,invalid_records:0},{source:'monitor2',attempted:10,received:9,invalid_records:0},{source:'monitor3',attempted:0,received:0,invalid_records:0}]}]}});
assert.deepEqual(Array.from(deliveries,r=>r.status),['Replies delivered','Loss / missing replies','Unmeasured']);
for(const name of ['renderDemo','renderHost','renderAttackControls','renderInvestigation','saveScenario'])context[name]=()=>{};
context.state={mode:'demo',source:'reception1',selected:'reception1',phase:2,marked:true,running:false};
context.$('review-ack').checked=false;context.recordReview('remediation_recorded');assert.equal(context.state.marked,true);assert.equal(context.state.phase,2);
context.$('review-ack').checked=true;context.recordReview('still_suspicious');assert.equal(context.state.marked,true);assert.equal(context.state.phase,2);
context.recordReview('remediation_recorded');assert.equal(context.state.marked,false);assert.equal(context.state.phase,3);assert.equal(context.state.review,'remediation_recorded');
context.state={mode:'live',selected:'reception1',liveMarked:'reception1'};context.recordReview('remediation_recorded');assert.equal(context.state.liveMarked,null);assert.equal(context.state.dismissedLive,'reception1');
console.log('Detection timing, stale/censored evidence, per-source delivery and explicit review gates passed.');

vm.runInContext(source.slice(source.indexOf('const graphLocations='),source.indexOf('function drawFabric()')),context);
assert.deepEqual(Array.from(context.networkPosition('billing1')), [12,30]);
assert.deepEqual(Array.from(context.networkPosition('billing1','billing1')), [89,48]);
assert.deepEqual(Array.from(context.networkPosition('monitor1','billing1')), [10,63]);
assert.equal(context.demoPhase(16,12),0);assert.equal(context.demoPhase(17,12),1);assert.equal(context.demoPhase(24,12),2);
assert.equal(context.demoPhase(24,40),0);assert.equal(context.demoDetection(24,'admin',40).streak,0);
context.state={mode:'demo',source:'reception1',reviewHost:'reception1',review:'remediation_recorded',marked:false,phase:3};
assert.equal(context.posture({name:'reception1',role:'admin'}),'NORMAL · USER RESOLVED');
console.log('Spatial containment, delayed probing and explicit green restoration passed.');
