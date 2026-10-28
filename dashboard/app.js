'use strict';
const $ = id => document.getElementById(id);
const inventory = [
 ['admin','ADMINISTRATION','s_admin',['reception1','reception2','billing1','hr1']],
 ['clinical','CLINICAL','s_clinic',['nurse1','nurse2','nurse3','doctor1','doctor2','doctor3']],
 ['servers','CRITICAL SERVERS','s_server',['ehr','pacs','lis','dns_ad','central_mon']],
 ['iomt','MEDICAL DEVICES','s_iomt',['monitor1','monitor2','monitor3','pump1','pump2','imaging1']],
 ['guest','GUEST + VENDOR','s_guest',['guest1','guest2','vendor_gw']]
];
const hosts = []; inventory.forEach(([segment,,sw,names])=>names.forEach((name,i)=>hosts.push({name,segment,sw,port:i+2,ip:`10.20.0.${hosts.length+1}`,role:name==='vendor_gw'?'vendor':segment==='servers'?'critical_server':segment==='guest'?'guest':segment})));
const roles = {
 admin:{label:'Office / admin',action:'ISOLATE',safety:'Permitted by role',note:'Office hosts can be isolated while preserving a defined management exception. This UI only simulates that action.'},
 clinical:{label:'Clinical workstation',action:'RESTRICT',safety:'Never automatically',note:'Keep access to EHR and DNS. Automatic full isolation is prohibited for clinical workstations.'},
 critical_server:{label:'Critical server',action:'PROTECT',safety:'Never automatically',note:'Protect the server from a malicious source. Never quarantine the critical server itself. Critical-allow conflicts still require policy evaluation.'},
 iomt:{label:'Medical device / IoMT',action:'RESTRICT',safety:'Never automatically',note:'Preserve vital peers: central monitoring, EHR or PACS. Never fully isolate a medical device automatically.'},
 guest:{label:'Guest endpoint',action:'ISOLATE',safety:'Permitted by role',note:'Guest hosts can be isolated with a defined management exception. These are logical policy groups, not VLAN enforcement.'},
 vendor:{label:'Vendor gateway',action:'RESTRICT',safety:'Escalation needs confirmation',note:'Restrict vendor access first. Escalation on persistent anomaly is planned; it is not connected to this dashboard.'}
};
function loadScenario(){try{const saved=JSON.parse(localStorage.getItem('medseg-attack-scenario-v1'));if(saved&&hosts.some(h=>h.name===saved.source)&&['random','manual'].includes(saved.selection))return saved;}catch{}return null;}
function saveScenario(){try{localStorage.setItem('medseg-attack-scenario-v1',JSON.stringify({source:state.source,selection:state.selection,marked:state.marked,liveMarked:state.liveMarked,dismissedLive:state.dismissedLive,review:state.review,reviewHost:state.reviewHost,contained:state.mode==='demo'&&state.phase===2,attackDelay:state.attackDelay}));}catch{}}
function differentEndpoint(previous){const eligible=hosts.filter(h=>['admin','guest'].includes(h.role)&&h.name!==previous);return eligible[Math.floor(Math.random()*eligible.length)].name;}
const savedScenario=loadScenario();
const initialSource=savedScenario?.source||differentEndpoint(null);
const stages = ['Baseline and traffic-window collection','Repeated off-profile fan-out observed','Contained · awaiting user review','User assessment recorded'];
const phaseTimes = [0,17,24,24];
const initialTraffic = Array.from({length:31},(_,i)=>25+Math.sin(i*.8)*8+(i%7===0?12:0));
const state={mode:'demo',selected:initialSource,source:initialSource,selection:savedScenario?.selection||'random',marked:savedScenario?.marked===true,liveMarked:hosts.some(h=>h.name===savedScenario?.liveMarked)?savedScenario.liveMarked:null,dismissedLive:savedScenario?.dismissedLive||null,review:['still_suspicious','remediation_recorded'].includes(savedScenario?.review)?savedScenario.review:null,reviewHost:hosts.some(h=>h.name===savedScenario?.reviewHost)?savedScenario.reviewHost:null,clinical:null,phase:savedScenario?.contained?2:0,running:false,elapsed:savedScenario?.contained?((savedScenario.attackDelay||12)+12):0,attackDelay:[12,25,40].includes(savedScenario?.attackDelay)?savedScenario.attackDelay:12,speed:1,traffic:[...initialTraffic],previous:null,decision:null,liveTimer:null,lastTick:performance.now()};
let toastTimer;
function toast(message){$('toast').textContent=message;$('toast').classList.add('visible');clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').classList.remove('visible'),4400);}
function view(name){document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id===`view-${name}`));document.querySelectorAll('.nav-btn').forEach(b=>b.classList.toggle('active',b.dataset.view===name));location.hash=name;}
document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>view(b.dataset.view)));
const graphLocations={
 reception1:[12,17],reception2:[24,17],billing1:[12,30],hr1:[24,30],
 nurse1:[40,16],nurse2:[52,16],nurse3:[64,16],doctor1:[40,29],doctor2:[52,29],doctor3:[64,29],
 ehr:[42,69],pacs:[54,69],lis:[66,69],dns_ad:[46,84],central_mon:[60,84],
 monitor1:[10,63],monitor2:[20,63],monitor3:[30,63],pump1:[10,78],pump2:[20,78],imaging1:[30,78],
 guest1:[12,45],guest2:[25,45],vendor_gw:[38,45]
};
function networkPosition(name,movedSource=null){return name===movedSource?[89,48]:graphLocations[name];}
function pathBetween(a,b){return `M${a[0]*10},${a[1]*6} Q${(a[0]+b[0])*5},${(a[1]+b[1])*3-32} ${b[0]*10},${b[1]*6}`;}
function drawFabric(){
 $('segments').replaceChildren();
 for(const host of hosts){const button=document.createElement('button');button.className='host-node';button.dataset.host=host.name;button.textContent=host.name;button.setAttribute('aria-label',`Inspect ${host.name}`);button.addEventListener('click',()=>{state.selected=host.name;renderHost();if(state.mode==='live'){$('review-details').hidden=true;renderInvestigation();}});$('segments').append(button);}
 $('fabric-links').setAttribute('viewBox','0 0 1000 600');
 $('fabric-links').innerHTML='<defs><marker id="arrow-ok" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#64dba5"/></marker><marker id="arrow-threat" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#ff654b"/></marker></defs><g id="network-routes"></g><path id="attack-route" style="display:none"/>';
 renderHost();
}
function renderNetwork(){
 const live=state.mode==='live',actor=live?(state.lab?.host||state.liveMarked):state.source,host=hosts.find(h=>h.name===actor);
 const confirmed=live?state.decision?.actions?.find(a=>a.host===actor&&a.status==='confirmed'&&a.action!=='RELEASE'):null;
 const proof=state.lab?.containment;
 const moved=live?(proof?.current&&state.decision?.controller_epoch===state.lab?.controller_epoch&&state.previous?.complete&&performance.now()-state.labSeen<3500?proof.host:null):state.phase===2&&host?.role!=='critical_server'?actor:null;
 $('quarantine-zone').classList.toggle('occupied',!!moved);
 $('bay-state').textContent=moved?(host.role==='admin'||host.role==='guest'?'ISOLATED':'RESTRICTED'):live&&confirmed?'ACK RECORDED':'STANDBY';
 for(const button of document.querySelectorAll('.host-node')){const p=networkPosition(button.dataset.host,moved);button.style.left=p[0]+'%';button.style.top=p[1]+'%';button.classList.toggle('in-bay',button.dataset.host===moved);}
 const routes=$('network-routes'),kept=new Set(),existing=new Map(Array.from(routes.querySelectorAll('[data-route]'),p=>[p.dataset.route,p]));
 const ns='http://www.w3.org/2000/svg';
 function edge(from,to,kind,label){const a=networkPosition(from,moved),destination=networkPosition(to,moved);if(!a||!destination)return;const b=kind==='blocked'?[78.5,destination[1]]:destination,key=from+':'+to+':'+kind;kept.add(key);let path=existing.get(key);if(!path){path=document.createElementNS(ns,'path');path.dataset.route=key;path.append(document.createElementNS(ns,'title'));routes.append(path);}path.setAttribute('d',pathBetween(a,b));path.setAttribute('class','device-route '+kind);path.setAttribute('marker-end',kind==='threat'?'url(#arrow-threat)':kind==='blocked'?'':'url(#arrow-ok)');path.setAttribute('marker-start',['clinical','exception'].includes(kind)?'url(#arrow-ok)':'');path.querySelector('title').textContent=label;}
 const deliveries=live?deliveryRows(state.clinical):null;
 for(const [flow,names,target]of servicePaths){for(const source of names){const measured=deliveries?.find(r=>r.flow===flow&&r.source===source);if(!live||measured?.status==='Replies delivered')edge(source,target,(source===moved?'exception':'clinical'),`${source} → ${target}: ${live?'fresh replies observed':'simulated clinical request / reply'}`);}}
 if(!live){
  for(const [from,to]of [['reception2','dns_ad'],['billing1','ehr'],['hr1','dns_ad'],['guest2','dns_ad'],['vendor_gw','imaging1']]){if(from!==actor||!moved)edge(from,to,'ordinary',`${from} → ${to}: illustrative ordinary communication`);}
  if(!moved&&actor!=='dns_ad')edge(actor,'dns_ad','ordinary',`${actor} → dns_ad: normal access restored / illustrative`);
  const evidence=demoDetection(state.elapsed,host.role,state.attackDelay),count=Math.min(15,evidence.feature.unique_dst),peers=hosts.filter(h=>h.name!==actor).slice(0,count);
  if(state.marked&&state.elapsed>state.attackDelay&&state.phase!==3){for(const peer of peers)edge(actor,peer.name,moved?'blocked':'threat',`${actor} → ${peer.name}: ${moved?'blocked probe':'suspicious off-profile contact'}`);}
  if(moved){const pos=networkPosition(actor,moved);let wall=existing.get('wall');if(!wall){wall=document.createElementNS(ns,'path');wall.dataset.route='wall';routes.append(wall);}kept.add('wall');wall.setAttribute('d',`M785,${pos[1]*6-65} v130`);wall.setAttribute('class','quarantine-wall');}
 }
 for(const [key,path]of existing)if(!kept.has(key))path.remove();
 $('graph-live-note').textContent=live&&moved?'Current IPv4 drop rules verified across all six switches. Green paths show fresh clinical replies.':live?'Only paths with fresh application replies are animated. Isolation ACKs are historical; nodes are not moved without current containment proof.':state.phase===2?(host.role==='critical_server'?'Protection needs source attribution. Server stays in place.':`${actor} separated · unrelated traffic blocked · clinical paths continue`):state.review==='remediation_recorded'?'Problem resolved by user · device rejoined · normal paths restored':state.elapsed<state.attackDelay?`Normal traffic · attacker waits ${Math.max(0,Math.ceil(state.attackDelay-state.elapsed))} s`:`Fan-out: ${demoDetection(state.elapsed,host.role,state.attackDelay).feature.unique_dst} devices contacted · animated simulation`;
}
function posture(host){
 if(state.mode==='live'){
  const flag=host.name===state.liveMarked?'FLAGGED · ':'';
  const action=state.decision?.actions?.find(a=>a.host===host.name);
  if(action?.status==='pending')return flag+'PENDING';
  if(action?.status==='failed')return flag+'ACTION FAILED';
  if(action?.status==='confirmed'&&action.action!=='RELEASE')return flag+action.action+' ACK';
  const row=state.decision?.quality==='ready'?state.decision.hosts?.[host.name]:null;
  return flag+(row?.score?(row.score.anomalous?'SUSPECT':'NO ALERT'):'UNSCORED');
 }
 if(host.name===state.source&&state.marked){if(state.phase===2)return host.role==='critical_server'?'COMPROMISED · REVIEW':'COMPROMISED · CONTAINED';if(state.phase===3)return 'COMPROMISED · RELEASED';return 'COMPROMISED · SIMULATED';}
 if(host.name===state.source&&state.reviewHost===host.name&&state.review==='remediation_recorded')return 'NORMAL · USER RESOLVED';
 return 'NORMAL';
}
function renderHost(){const host=hosts.find(h=>h.name===state.selected),role=roles[host.role],status=posture(host);
 $('host-name').textContent=host.name;$('host-address').textContent=host.ip;$('host-role').textContent=role.label;$('host-switch').textContent=`${host.sw} : ${host.port}`;$('host-policy').textContent=role.action;$('host-safety').textContent=role.safety;$('policy-note').textContent=role.note;$('host-symbol').textContent=(state.mode==='demo'&&state.marked&&host.name===state.source)||(state.mode==='live'&&state.liveMarked===host.name)?'☠':host.role==='iomt'?'♡':host.role==='critical_server'?'▥':'▣';$('host-status').textContent=status;$('host-status').classList.toggle('alert',!status.startsWith('NORMAL')&&status!=='NO ALERT');
 if(state.mode==='live'){
  const row=state.decision?.hosts?.[host.name],a=state.decision?.actions?.find(v=>v.host===host.name);
  $('policy-note').textContent=a?`${a.action}: ${a.status}. ${a.confirmed_ns?'Historical rule readback; timed rules may have since expired.':'No confirmed installation yet.'} ${a.error||''}`:'Configured role policy. No confirmed action for this host.';
 }
 $('resolve-device').disabled=state.mode==='demo'?(state.selected!==state.source||!state.marked):state.selected!==state.liveMarked;
 $('source-button').disabled=state.mode==='live'||state.running;$('release-button').disabled=state.mode==='live'||state.phase!==2||state.selected!==state.source;
 const selected=state.decision?.quality==='ready'?state.decision.hosts?.[host.name]:null;
 $('inspector-context').textContent=state.mode==='live'?(state.decision&&selected?`Score ${selected.score?.anomaly_score?.toFixed(2)??'—'} · ${selected.status}${selected.evidence_censored?' · blocked traffic hidden':''}`:'No fresh score for this host'):'Role matrix preview · no enforcement';
 document.querySelectorAll('.host-node').forEach(b=>{const h=hosts.find(h=>h.name===b.dataset.host),s=posture(h);b.classList.toggle('selected',h.name===state.selected);const marked=s.includes('COMPROMISED')||s.includes('FLAGGED');b.classList.toggle('suspect',s.includes('SUSPECT'));b.classList.toggle('contained',s.includes('CONTAINED')||s.includes(' ACK'));b.classList.toggle('compromised',marked);b.classList.toggle('reviewed',s==='NORMAL · USER RESOLVED');b.classList.toggle('unknown',state.mode==='live'&&s.includes('UNSCORED'));b.textContent=h.name;b.title=marked?'Attacker marker persists; containment does not clean the host':s;b.setAttribute('aria-pressed',String(h.name===state.selected));});renderNetwork();
}
function drawChart(){const values=state.traffic.slice(-31),finite=values.filter(Number.isFinite),max=state.mode==='live'?Math.max(60,...finite)*1.15:600;let path='',area='',segment=[];function flush(){if(segment.length){path+='M'+segment.join(' L')+' ';area+='M'+segment[0].split(',')[0]+',118 L'+segment.join(' L')+' L'+segment[segment.length-1].split(',')[0]+',118 Z ';segment=[];}}values.forEach((v,i)=>{if(!Number.isFinite(v)){flush();return;}segment.push(`${i*720/30},${112-Math.min(1,v/max)*102}`);});flush();$('chart-line').setAttribute('d',path);$('chart-area').setAttribute('d',area);document.querySelectorAll('.chart-scale span')[0].textContent=String(Math.ceil(max));document.querySelectorAll('.chart-scale span')[1].textContent=String(Math.ceil(max/2));}
function renderSequence(){const list=$('sequence');list.replaceChildren();stages.forEach((label,i)=>{const li=document.createElement('li');li.className=i===state.phase?'current':i<state.phase?'done':'';const circle=document.createElement('span');circle.className='step-circle';circle.textContent=i<state.phase?'✓':String(i+1);const text=document.createElement('span');text.textContent=state.mode==='live'?(i===0?'Live telemetry connected':i===1?'Detector not connected':i===2?'Action API not connected':'Read-only mode'):(i===3&&!state.review?'Connectivity restored · still flagged':label);const time=document.createElement('time');time.textContent=state.mode==='demo'&&i<=state.phase?`${(i===3?state.elapsed:i===2?state.attackDelay+12:i===1?state.attackDelay+5:0).toFixed(1)} s`:'—';li.append(circle,text,time);list.append(li);});$('scenario-clock').textContent=state.mode==='live'?'READ ONLY':state.running?`T + ${state.elapsed.toFixed(1)} s`:state.phase===2?'AWAITING REVIEW':state.phase===3?(state.review?'REVIEW RECORDED':'ACCESS RESTORED · FLAGGED'):'READY';$('scenario-source').textContent=`Source · ${state.source}`;}
function renderDemo(){$('posture-value').classList.toggle('restored',state.phase===3&&!state.marked);const role=roles[hosts.find(h=>h.name===state.source).role];$('run-button').innerHTML=state.running?'Ⅱ Pause demo':state.phase===2?'Review contained device':state.phase===3?'↺ Replay demo':'▶ Run containment demo';$('posture-value').replaceChildren();$('posture-value').append(document.createTextNode(state.phase===1?'Suspect':state.phase===2?(role.action==='PROTECT'?'Review required':role.action==='ISOLATE'?'Isolated':'Restricted'):state.phase===3?(state.marked?'Still compromised':'Normal'):state.marked?'Compromised':'Normal'));const suffix=document.createElement('span');suffix.textContent=state.phase===0?'baseline':state.source;$('posture-value').append(suffix);$('posture-foot').textContent=state.phase===1?'Illustrative fan-out signal · no ML score':state.phase===2?'Containment held · awaiting your review · simulation':state.phase===3?(state.marked?'Connectivity restored · attacker has not been removed':'User-declared remediation · not independently verified'):state.marked?'Attacker remains until you clear or change the device':'Simulation ready to run';$('topology-caption').textContent=state.phase===1?'Illustrative lateral probing':state.phase===2?(role.action==='PROTECT'?'Critical server: review required · no automatic isolation':'Threat path contained · simulated'):'Select a host to inspect its role';renderHost();renderSequence();renderAttackControls();renderInvestigation();}
function resetDemo(){state.phase=0;state.elapsed=0;state.running=false;state.traffic=[...initialTraffic];renderDemo();drawChart();}
$('run-button').addEventListener('click',()=>{if(state.mode!=='demo')return;if(state.phase===2){openReview();return;}if(state.phase===3){if(state.selection==='random'){state.source=differentEndpoint(state.source);state.selected=state.source;}resetDemo();}state.marked=true;state.review=null;$('review-details').hidden=true;$('review-ack').checked=false;saveScenario();state.running=!state.running;state.lastTick=performance.now();renderDemo();});
$('source-button').addEventListener('click',()=>{state.source=state.selected;state.selection='manual';state.marked=true;state.review=null;$('review-details').hidden=true;$('review-ack').checked=false;saveScenario();resetDemo();toast(`Demo source: ${state.source}. Planned action: ${roles[hosts.find(h=>h.name===state.source).role].action}.`);});
$('release-button').addEventListener('click',()=>{state.phase=3;state.elapsed=Math.max(state.attackDelay+12,state.elapsed);state.running=false;renderDemo();toast('Connectivity restored in the simulation. The attacker marker remains.');});
$('reset-button').addEventListener('click',()=>{if(state.mode==='live'){toast('Live telemetry is read-only. There is no scenario to reset.');return;}resetDemo();});
$('speed-button').addEventListener('click',()=>{state.speed=state.speed===1?2:1;$('speed-button').textContent=`${state.speed}× speed`;});
let chartTick=0;setInterval(()=>{const now=performance.now(),dt=Math.min(1,(now-state.lastTick)/1000);state.lastTick=now;if(state.mode!=='demo')return;if(state.running){state.elapsed+=dt*state.speed;const old=state.phase;state.phase=demoPhase(state.elapsed,state.attackDelay);if(old!==state.phase&&state.phase===2)toast(`${state.source}: ${roles[hosts.find(h=>h.name===state.source).role].action} illustrated; vital paths retained in the simulation.`);if(state.phase===2){state.running=false;saveScenario();}renderDemo();}chartTick++;if(chartTick%5===0){const base=state.phase===1?470:state.phase===2?48:30;state.traffic.push(Math.max(0,base+Math.sin(chartTick*.73)*base*.13));if(state.traffic.length>31)state.traffic.shift();drawChart();}},200);
const clinical=[['C1','Patient monitors → central_mon','Measured: 393 / 393 replies'],['C2','Infusion pumps → EHR','User-supplied C1–C5 run passed · repeat verification pending'],['C3','Imaging device → PACS','User-supplied C1–C5 run passed · repeat verification pending'],['C4','Nurses / doctors → EHR','User-supplied C1–C5 run passed · repeat verification pending'],['C5','LIS ↔ EHR','User-supplied C1–C5 run passed · repeat verification pending']];
clinical.forEach(([id,relationship,status])=>{const tr=document.createElement('tr');const cell=document.createElement('td'),badge=document.createElement('span');badge.className='path-id';badge.textContent=id;cell.append(badge);tr.append(cell);for(const text of [relationship,'50,000 · specific allow',status]){const td=document.createElement('td');td.textContent=text;tr.append(td);}$('clinical-rows').append(tr);});
const recordedReport={run_id:'1606fe9010944d54bf7a727c9556cd25',target:'monitor1',passed:true,phases:[{phase:'before',ping_exit_code:0,monitors:{monitor1:{attempted:40,received:40},monitor2:{attempted:40,received:40},monitor3:{attempted:40,received:40}}},{phase:'restricted',ping_exit_code:1,drop_packets:2,monitors:{monitor1:{attempted:51,received:51},monitor2:{attempted:51,received:51},monitor3:{attempted:51,received:51}}},{phase:'recovered',ping_exit_code:0,monitors:{monitor1:{attempted:40,received:40},monitor2:{attempted:40,received:40},monitor3:{attempted:40,received:40}}}]};
function validateReport(report){if(!report||typeof report.run_id!=='string'||report.run_id.length>100||typeof report.passed!=='boolean'||!Array.isArray(report.phases)||report.phases.length!==3)throw Error('Expected a three-phase restriction-report.json from this project.');for(let i=0;i<3;i++){const p=report.phases[i];if(p.phase!==['before','restricted','recovered'][i]||![0,1,2].includes(p.ping_exit_code)||!p.monitors||Object.keys(p.monitors).length!==3)throw Error('Invalid phase or monitor data.');for(const name of ['monitor1','monitor2','monitor3']){const m=p.monitors[name];if(!m||!Number.isSafeInteger(m.attempted)||!Number.isSafeInteger(m.received)||m.attempted<0||m.received<0||m.received>m.attempted)throw Error('Invalid probe counts.');}}if(report.passed&&(report.phases.some((p,i)=>p.ping_exit_code!==[0,1,0][i]||Object.values(p.monitors).some(m=>m.attempted===0||m.received!==m.attempted))||!Number.isSafeInteger(report.phases[1].drop_packets)||report.phases[1].drop_packets<2))throw Error('PASS is inconsistent with phase evidence.');return report;}
function renderReport(report,imported=false){$('phase-cards').replaceChildren();report.phases.forEach(p=>{const total=Object.values(p.monitors).reduce((a,m)=>({attempted:a.attempted+m.attempted,received:a.received+m.received}),{attempted:0,received:0});const card=document.createElement('article');card.className=`phase-card ${p.phase==='restricted'?'blocked':''}`;const title=document.createElement('h3');title.textContent=p.phase;card.append(title);[['Test ping',p.ping_exit_code===0?'Reachable':p.ping_exit_code===1?'Blocked':'Command error'],['Clinical probes',`${total.received} / ${total.attempted}`]].forEach(([label,value])=>{const row=document.createElement('div'),name=document.createElement('span'),strong=document.createElement('strong');name.textContent=label;strong.textContent=value;if(label==='Test ping')strong.className='ping';row.append(name,strong);card.append(row);});$('phase-cards').append(card);});$('report-title').textContent=report.passed?'Selective restriction, clinical continuity.':'Imported run did not pass.';$('report-meta').textContent=`${imported?'IMPORTED LOCAL REPORT · user-provided, not independently verified':'RECORDED TERMINAL EVIDENCE'} · Run ${report.run_id} · No report leaves this browser` ;}
$('import-button').addEventListener('click',()=>$('report-file').click());$('report-file').addEventListener('change',async e=>{const file=e.target.files[0];if(!file)return;try{if(file.size>1024*1024)throw Error('Report must be smaller than 1 MB.');const report=JSON.parse(await file.text());if(report.check==='hospital_demo_report')renderDemoEvidence(validateDemoReport(report));else renderReport(validateReport(report),true);toast('Report loaded locally. Reference results and live measurements stay separately labelled.');}catch(error){toast(error.message);}e.target.value='';});
function dialog(title,body,eyebrow='PRESENTATION GUIDE'){$('dialog-eyebrow').textContent=eyebrow;$('dialog-body').innerHTML=body;$('info-dialog').showModal();}
$('close-dialog').addEventListener('click',()=>$('info-dialog').close());$('info-dialog').addEventListener('click',e=>{if(e.target===$('info-dialog'))$('info-dialog').close();});
$('tour-button').addEventListener('click',()=>dialog('Present the experiment in two minutes','<h2>Present the experiment in two minutes.</h2><ol><li><strong>The problem:</strong> a compromised office PC can move across a flat hospital network.</li><li><strong>The idea:</strong> contain by role. A patient monitor must retain vital clinical access.</li><li><strong>Click Run containment demo.</strong> Explain the topology, fan-out signal, role-specific action and timed recovery. Say explicitly that this sequence is simulated.</li><li><strong>Open Verified evidence.</strong> Show the real 552/552 ping result and the C1 restriction test with 393/393 replies.</li><li><strong>Explain the remaining integration:</strong> the detector and action pipeline are implemented and locally tested. A supplied lab run passed; broader role/action cases and trained ML remain pending. Local live mode can read detector and clinical probe evidence when those services run.</li></ol><p>To present without internet, run the local dashboard on Mint. The same interface works without external libraries; fonts fall back to system fonts.</p>'));
function connectDialog(){if(state.mode==='live'){dialog('Live connection','<h2>Connected to your local lab.</h2><p>The browser is read-only. It displays fresh telemetry, detector scores, historical action confirmations and measured clinical replies when their local services are running. Missing or stale evidence stays unmeasured.</p><button class="button secondary" id="back-to-demo">Return to simulation</button>','LIVE TELEMETRY');$('back-to-demo').addEventListener('click',()=>{$('info-dialog').close();setDemo();});return;}const local=['127.0.0.1','localhost'].includes(location.hostname);dialog('Connect your Mint lab',`<h2>Bring the real lab into view.</h2><p>The hosted version cannot reach your laptop. On Mint, start the complete persistent lab:</p><code>cd ~/SDN-Microsegmentation\nsudo /usr/bin/python3 scripts/lab.py</code><p>Open <strong>http://127.0.0.1:8088</strong> on that laptop. Live mode reads the controller through a loopback-only bridge; it cannot install or remove rules.</p>${local?'<button class="button primary" id="enable-live">Read local controller</button>':'<p>Until you open the local version, this dashboard stays in clearly labelled simulation mode.</p>'}`,'LAB CONNECTION');if(local)$('enable-live').addEventListener('click',()=>{$('info-dialog').close();startLive();});}
$('connect-button').addEventListener('click',connectDialog);$('mode-button').addEventListener('click',connectDialog);
function setDemo(){clearTimeout(state.liveTimer);state.mode='demo';state.previous=null;state.decision=null;$('mode-name').textContent='Guided simulation';$('mode-notice').innerHTML='<span class="notice-icon">◉</span><span><strong>DEMONSTRATION MODE</strong> Animated traffic and actions are simulated. No network rules are changed.</span><button id="connect-again">Connect your lab →</button>';$('connect-again').addEventListener('click',connectDialog);$('run-button').disabled=false;$('inventory-value').innerHTML='24<span>hosts</span>';$('inventory-foot').innerHTML='<i class="dot"></i> 6 switches · 29 links';$('critical-value').innerHTML='C1<span>preserved</span>';$('critical-foot').textContent='Illustrative monitor → central monitor';$('chart-source').textContent='SIMULATED PACKETS / S';$('chart-description').textContent='Illustrative network activity';resetDemo();}
async function startLive(){state.mode='live';state.running=false;state.previous=null;state.decision=null;state.clinical=null;state.traffic=Array(31).fill(null);$('mode-name').textContent='Live · read only';$('run-button').disabled=true;$('run-button').textContent='Read-only telemetry';$('mode-notice').innerHTML='<span class="notice-icon">◉</span><span><strong>LIVE READ-ONLY TELEMETRY</strong> Connecting to your local controller. Waiting for fresh detector and clinical probe evidence.</span>';$('posture-value').innerHTML='—<span>unscored</span>';$('posture-foot').textContent='Detector not connected';$('critical-value').innerHTML='—<span>unmeasured</span>';$('critical-foot').textContent='Live clinical probes are not connected';$('chart-source').textContent='INGRESS RULE HITS / S';$('chart-description').textContent='Observed IPv4 forwarding counters';$('attack-route').style.display='none';renderHost();renderSequence();renderAttackControls();renderInvestigation();await pollLive();}
async function pollLive(){if(state.mode!=='live')return;try{const response=await fetch('/api/snapshot',{cache:'no-store',signal:AbortSignal.timeout(6500)});if(!response.ok)throw Error('Local bridge unavailable. Start dashboard/serve.py on Mint.');const {health,stats,decision,clinical}=await response.json();if(!health||!stats||!Array.isArray(health.connected_dpids)||!Array.isArray(stats.switches))throw Error('Invalid controller response');if(state.mode!=='live')return;state.decision=decision||null;state.clinical=clinical||null;const n=health.connected_dpids.length;$('inventory-value').innerHTML=`${hosts.length}<span>configured hosts</span>`;$('inventory-foot').textContent=`${n} / 6 switches connected · ${stats.complete?'fresh':'incomplete'} counters`;$('mode-notice').textContent=`LIVE READ-ONLY · ${health.status==='ok'&&stats.complete?'Fresh controller telemetry':'Degraded / incomplete telemetry'} · Detector snapshots are unavailable; clinical health requires fresh probe replies.`;const totals={};for(const sw of stats.switches){for(const row of sw.snapshot?.rows||[]){if(!row.ingress_source_host||![10000,45000,50000].includes(row.priority)||row.match?.eth_type!==2048)continue;const key=JSON.stringify([sw.dpid,sw.snapshot.generation,row.cookie,row.priority,row.match]);totals[key]={packets:row.packets,duration:row.duration_ns};}}const current={epoch:health.controller_epoch,time:stats.timestamp_ns,complete:stats.complete===true,totals};const delta=counterDelta(state.previous,current);state.traffic.push(delta.rate);state.traffic.shift();state.previous=current;$('chart-description').textContent=delta.reason;drawChart();renderLiveDecision(health);renderCriticalEvidence(clinical); }catch(error){if(state.mode!=='live')return;state.previous=null;state.decision=null;state.clinical=null;renderHost();renderCriticalEvidence(null);renderInvestigation();renderAttackControls();state.traffic.push(null);state.traffic.shift();drawChart();$('mode-notice').textContent=`LIVE CONNECTION UNAVAILABLE · ${error.message} · Recorded evidence remains available.`;$('inventory-foot').textContent='Connection unavailable · not a healthy-state claim';$('chart-description').textContent='No current data';}finally{if(state.mode==='live')state.liveTimer=setTimeout(pollLive,1500);}}
// Thresholds mirror configs/detection.yaml; live values come from the decision snapshot.
const previewThresholds={admin:{unique_dst:8,unique_dst_ports:12,off_profile_min:1},clinical:{unique_dst:6,unique_dst_ports:12,off_profile_min:1},iomt:{unique_dst:4,unique_dst_ports:8,off_profile_min:1},guest:{unique_dst:3,unique_dst_ports:8,off_profile_min:1},vendor:{unique_dst:4,unique_dst_ports:8,off_profile_min:1},critical_server:{unique_dst:20,unique_dst_ports:48,off_profile_min:1}};
const servicePaths=[['C1',['monitor1','monitor2','monitor3'],'central_mon'],['C2',['pump1','pump2'],'ehr'],['C3',['imaging1'],'pacs'],['C4',['nurse1','nurse2','nurse3','doctor1','doctor2','doctor3'],'ehr'],['C5',['lis'],'ehr']];
function demoPhase(elapsed,delay){return elapsed>=delay+12?2:elapsed>=delay+5?1:0;}
function demoDetection(elapsed,role,delay=5){
 const thresholds=previewThresholds[role],active=Math.max(0,elapsed-delay),window_s=Math.min(5,active),unique=Math.min(20,Math.floor(active*4));
 const feature={window_s,unique_dst:Math.min(15,unique),unique_dst_ports:unique,off_allow_list_flows:Math.max(0,unique-1)};
 const anomalous=window_s>=5&&feature.off_allow_list_flows>=thresholds.off_profile_min&&(feature.unique_dst>=thresholds.unique_dst||feature.unique_dst_ports>=thresholds.unique_dst_ports);
 const streak=anomalous?(elapsed>=delay+10?2:1):0;
 return {feature,thresholds,anomalous,streak,required:2,warming:window_s<5,illustrative:true};
}
function liveDetection(decision,host){
 const row=decision?.hosts?.[host],feature=row?.feature,policy=decision?.detection_policy;
 const age=feature&&Number.isSafeInteger(feature.timestamp_ns)?(decision.timestamp_ns-feature.timestamp_ns)/1e9:null;
 if(decision?.quality!=='ready'||!feature||age===null||age<0||age>(policy?.max_feature_age_s||4))return null;
 if(!['window_s','unique_dst','unique_dst_ports','off_allow_list_flows'].every(k=>Number.isFinite(feature[k])&&feature[k]>=0))return null;
 return {feature,detector:decision.detector||'M3',mlScores:row.ml_scores||null,thresholds:(decision.detector&&decision.detector!=='M3')?null:row.detection?.thresholds||policy?.thresholds?.[feature.role]||null,anomalous:row.score?.anomalous===true,streak:row.detection?.anomalous_streak??null,required:policy?.anomalous_windows??null,censored:row.evidence_censored===true,warming:false,illustrative:false};
}
function deliveryRows(clinical){
 const result=[];
 for(const service of clinical?.measurement?.services||[]){for(const source of service.sources||[]){const a=source.attempted,r=source.received;
 const valid=Number.isSafeInteger(a)&&Number.isSafeInteger(r)&&a>=0&&r>=0&&r<=a&&source.invalid_records===0;
 result.push({flow:service.flow_id,source:source.source,attempted:valid?a:null,received:valid?r:null,status:!valid||!a?'Unmeasured':r===a?'Replies delivered':'Loss / missing replies'});}}
 return result;
}
function renderInvestigation(){
 const live=state.mode==='live',name=live?state.selected:state.source,host=hosts.find(h=>h.name===name),evidence=live?liveDetection(state.decision,name):demoDetection(state.review==='remediation_recorded'&&!state.marked?0:state.elapsed,host.role,state.attackDelay);
 $('detection-scope').textContent=live?`ACTUAL LOCAL TELEMETRY · ${name} · connection patterns indicate suspicion, not proof of infection.`:`GUIDED SIMULATION · ${name} · paced teaching example, not a measured detection time.`;
 $('detection-counts').replaceChildren();
 const metrics=[['Devices contacted',evidence?.feature.unique_dst,evidence?.thresholds?.unique_dst],['Destination ports',evidence?.feature.unique_dst_ports,evidence?.thresholds?.unique_dst_ports],['Off-profile groups',evidence?.feature.off_allow_list_flows,evidence?.thresholds?.off_profile_min],['Suspicious samples',evidence?.streak,evidence?.required]];
 for(const [label,value,threshold]of metrics){const card=document.createElement('div'),title=document.createElement('span'),strong=document.createElement('strong'),small=document.createElement('small');title.textContent=label;strong.textContent=value??'—';small.textContent=threshold==null?(evidence?.detector&&evidence.detector!=='M3'?'Observed count · ML decides':'Threshold unavailable'):`Trigger ≥ ${threshold}`;card.append(title,strong,small);$('detection-counts').append(card);}
 const reason=!live&&state.review==='remediation_recorded'&&!state.marked?'Resolved by user: simulated attack stopped, normal access restored. Previous observations remain part of your review; the current simulation starts a new normal window.':!evidence?'No fresh, complete feature window. No clean-device conclusion is possible.':evidence.censored?'Containment hides blocked traffic. A low score now cannot prove the device clean.':evidence.warming?`${!live&&state.elapsed<state.attackDelay?'Normal traffic first. The attacker has not started probing. ':''}Collecting traffic (${evidence.feature.window_s.toFixed(1)} / 5 s). Detection has not fired.`:evidence.anomalous?`Off-profile communication plus excessive destination OR port fan-out. ${evidence.streak??'Unknown'} / ${evidence.required??'unknown'} consecutive suspicious samples. ${host.role==='critical_server'?'Critical-server protection additionally requires an attributed source.':''}`:'This window does not meet the configured fan-out rule. This is not proof the device is clean.';
 const ml=live&&evidence&&evidence.detector!=='M3'&&evidence.mlScores;
 $('detection-reason').textContent=ml?`${evidence.detector}: ${evidence.anomalous?'anomalous':'below model threshold'} · ${evidence.detector==='M1'?`score ${ml.m1_raw_anomaly_score}, threshold ${ml.m1_threshold}`:`attack probability ${ml.m2_attack_probability}, threshold ${ml.m2_threshold}`} · ${evidence.streak??'unknown'} / ${evidence.required??'unknown'} suspicious samples. ${evidence.censored?'Blocked traffic is censored; this cannot prove the device clean.':'A model alarm is suspicion, not proof of infection.'}`:reason;
 $('detection-steps').replaceChildren();
 for(const text of ['Observe distinct destinations and service ports over a traffic window.',ml?`Apply the selected ${evidence.detector} trained model and its recorded threshold.`:'Require off-profile traffic AND a destination-count OR port-count threshold.',live&&evidence?`Require ${evidence.required??'configured'} consecutive valid samples; ${evidence.feature.window_s}-second windows may overlap.`:'Require two consecutive valid suspicious samples. Live five-second windows refresh about once per second and can overlap.','Then request the role-specific action and wait for switch readback. Missing telemetry or a queued request is not confirmed containment.']){const li=document.createElement('li');li.textContent=text;$('detection-steps').append(li);}
 $('review-summary').textContent=live?'Review the selected host’s measured traffic and action history. This browser cannot scan, disinfect, or change switch rules. Timed lab rules may expire independently.':state.phase===2?'The teaching scenario is held here until you review it. Other service paths continue. Restoring access and removing the attacker marker require an explicit choice.':'Review traffic evidence before deciding whether to keep the host flagged or record remediation. No automatic clean state is assigned.';
 $('review-heading').textContent=state.reviewHost===name&&state.review==='remediation_recorded'?'Normal · marked resolved by user':state.reviewHost===name&&state.review==='still_suspicious'?'User review: still suspicious':'Investigate before restoring trust.';
 $('review-remediated').textContent=live?'Record remediation assessment':'Problem resolved · restore to normal';
 renderContinuity();
}
function renderContinuity(){
 const live=state.mode==='live';$('continuity-scope').textContent=live?'MEASURED REPLIES · RECENT INTERVAL':'SIMULATED REQUEST / REPLY PATHS';
 const actor=live?(state.liveMarked||state.selected):state.source,host=hosts.find(h=>h.name===actor),action=state.decision?.actions?.find(a=>a.host===actor);
 $('affected-connection').textContent=live?(action?`${actor}: ${action.action} ${action.status}. ${action.status==='confirmed'?'Historical rule readback; current isolation is not inferred after timeout.':'No confirmed containment yet.'}`:`${actor}: no confirmed containment action available.`):state.phase===2?(host.role==='critical_server'?`${actor}: no automatic isolation. Protection requires source attribution and review.`:`${actor} → unrelated peer: BLOCKED (simulation). ${roles[host.role].action==='RESTRICT'?'Required clinical services remain allowed.':'Only the defined management exception remains.'}`):state.phase===3?`${actor}: access restored by user choice; ${state.marked?'attacker still flagged':'remediation is user-declared, not independently verified'}.`:`${actor}: normal access in this simulation until containment is applied.`;
 $('affected-connection').classList.toggle('blocked',!live&&state.phase===2&&host.role!=='critical_server');
 const measured=live?deliveryRows(state.clinical):null;$('continuity-rows').replaceChildren();
 for(const [flow,names,target]of servicePaths){for(const source of names){const row=document.createElement('tr'),r=measured?.find(v=>v.flow===flow&&v.source===source),attempted=Math.floor(state.elapsed*5);const values=[`${flow} · ${source} → ${target}`,live?(r?.attempted==null?'—':`${r.received} / ${r.attempted}`):(state.elapsed?`${attempted} / ${attempted} · illustrative`:'—'),live?(r?.status||'Unmeasured'):(state.elapsed?'Continuing · simulated':'Not started · simulated')];for(const value of values){const td=document.createElement('td');td.textContent=value;row.append(td);}row.className=live?(r?.status==='Replies delivered'?'delivered':r?.status==='Loss / missing replies'?'delivery-loss':'unmeasured'):'illustrative';$('continuity-rows').append(row);}}
 $('continuity-note').textContent=live?'Only fresh application replies establish delivery on these 13 source paths. No claim is made about every other device or connection.':`These 13 paths illustrate ongoing clinical communication while ${actor} is contained. Counts are generated for explanation. Switch to local live mode or import a report for measured results.`;
}
function openReview(){
 $('review-details').hidden=false;$('review-ack').checked=false;
 const live=state.mode==='live',name=live?state.selected:state.source,evidence=live?liveDetection(state.decision,name):demoDetection(state.elapsed,hosts.find(h=>h.name===name).role,state.attackDelay);
 $('review-evidence').textContent=`Reviewing ${name}. ${evidence?`${evidence.feature.unique_dst} destinations; ${evidence.feature.unique_dst_ports} ports; ${evidence.feature.off_allow_list_flows} off-profile groups. ${evidence.censored?'Traffic evidence is censored by containment.':''}`:'No fresh detection evidence is available.'} Check the endpoint separately before declaring remediation. This assessment does not install/remove real network rules.`;
 $('review-record').textContent='Choose an assessment. No automatic verdict will be invented.';
 view('overview');renderInvestigation();$('review-details').scrollIntoView({behavior:'smooth',block:'center'});
}
function recordReview(outcome){
 if(!$('review-ack').checked){$('review-record').textContent='Acknowledge the assessment limits before recording your choice.';return;}
 state.review=outcome;state.reviewHost=state.mode==='live'?state.selected:state.source;
 if(outcome==='remediation_recorded'){
  if(state.mode==='live'){if(state.liveMarked===state.selected){state.dismissedLive=state.liveMarked;state.liveMarked=null;}}else{state.marked=false;state.phase=3;state.running=false;}
 }else if(state.mode==='demo'){state.marked=true;}
 saveScenario();$('review-record').textContent=outcome==='still_suspicious'?'User assessment recorded: still suspicious. The attacker flag remains.':'Problem marked resolved by user. The simulated device is green, rejoins the network and resumes normal communication. This is not an antivirus result.';
 if(state.mode==='demo')renderDemo();else{renderHost();renderAttackControls();renderInvestigation();}
}

initialiseAttackControls();drawFabric();renderDemo();drawChart();renderReport(recordedReport);view(['overview','clinical','evidence'].includes(location.hash.slice(1))?location.hash.slice(1):'overview');

function renderLiveDecision(health){
 const decision=state.decision;
 renderInvestigation();
 $('topology-caption').textContent=`Controller: ${health.status} · ${decision?'live detector attached':'detector unavailable'}`;
 if(!decision){$('posture-value').textContent='Unscored';$('posture-foot').textContent='No fresh decision snapshot';renderHost();return;}
 const candidate=decision.actions?.find(a=>a.action!=='RELEASE'&&a.status==='confirmed')?.host||Object.keys(decision.hosts).find(name=>decision.hosts[name].score?.anomalous);
 if(candidate&&!state.liveMarked&&state.dismissedLive!==candidate){state.liveMarked=candidate;saveScenario();}
 renderAttackControls();renderInvestigation();
 const rows=Object.values(decision.hosts),suspects=rows.filter(r=>r.score?.anomalous).length;
 $('posture-value').textContent=decision.mutation_halted?'Writes halted':decision.quality==='ready'?`${suspects} alerts`:'Awaiting evidence';
 $('posture-foot').textContent=decision.mutation_halted||`${decision.mode} · ${decision.quality} · ${decision.outbox_depth} queued`;
 $('mode-notice').textContent=`LIVE ${decision.mode.toUpperCase()} · Actual detector output · ${decision.mutation_halted||'Only switch readback produces an installation ACK'}. Clinical delivery is shown only from fresh probe replies.`;
 renderHost();
 const list=$('sequence');list.replaceChildren();
 const events=(decision.events||[]).filter(r=>r.event.host===state.selected).slice(-4);
 for(const row of events){const li=document.createElement('li');const span=document.createElement('span');span.textContent=row.event.stage.replaceAll('_',' ');const small=document.createElement('small');small.textContent='Recorded event';li.append(span,small);list.append(li);}
 $('scenario-clock').textContent=decision.mode.toUpperCase();
}

function renderCriticalEvidence(clinical){
 const report=clinical?.measurement;
 if(!report){$('critical-value').textContent='Unmeasured';$('critical-foot').textContent='No fresh clinical probe evidence';return;}
 const rows=report.services.flatMap(v=>v.sources),attempted=rows.reduce((n,r)=>n+r.attempted,0),received=rows.reduce((n,r)=>n+r.received,0);
 $('critical-value').textContent=report.status==='PASS'?'C1–C5 PASS':report.status==='FAIL'?'Probe loss / gap':'Unmeasured';
 $('critical-foot').textContent=`${received} / ${attempted} replies · ${rows.length} sources · recent measured interval`;
}

function validateDemoReport(report){
 if(report.schema_version!==1||!['PASS','FAIL','OBSERVATION_ONLY'].includes(report.status)||!/^([0-9a-f]{32})$/.test(report.run_id)||!report.phases||typeof report.phases!=='object'||Array.isArray(report.phases))throw Error('Invalid finite-demo report.');
 const expected={C1:['monitor1','monitor2','monitor3'],C2:['pump1','pump2'],C3:['imaging1'],C4:['nurse1','nurse2','nurse3','doctor1','doctor2','doctor3'],C5:['lis']};
 const names=['baseline','restricted','recovered'];
 if(Object.keys(report.phases).some(k=>!names.includes(k)))throw Error('Unknown demonstration phase.');
 for(const [name,phase]of Object.entries(report.phases)){
  const services=phase.clinical?.services;
  if(!Array.isArray(services)||services.length>5||!Number.isSafeInteger(phase.ping?.exit_code))throw Error('Malformed phase evidence.');
  const seen=new Set();
  for(const service of services){
   const sources=service.sources;if(!expected[service.flow_id]||seen.has(service.flow_id)||!Array.isArray(sources)||sources.length>8)throw Error('Invalid clinical service.');seen.add(service.flow_id);
   const hosts=new Set();
   for(const row of sources){if(!expected[service.flow_id].includes(row.source)||hosts.has(row.source)||!Number.isSafeInteger(row.attempted)||!Number.isSafeInteger(row.received)||row.attempted<0||row.received<0||row.received>row.attempted)throw Error('Invalid clinical reply counts.');hosts.add(row.source);}
   if(report.status==='PASS'&&(sources.length!==expected[service.flow_id].length||sources.some(r=>r.attempted===0||r.received!==r.attempted||r.invalid_records!==0||r.status!=='PASS')))throw Error('PASS lacks complete clinical evidence.');
  }
  if(report.status==='PASS'&&(services.length!==5||phase.clinical.status!=='PASS'||phase.ping.executed!==true||phase.ping.exit_code!==(name==='restricted'?1:0)))throw Error('PASS contradicts phase outcomes.');
 }
 if(report.status==='PASS'){
  if(report.mode!=='enforce'||names.some(n=>!report.phases[n])||!Array.isArray(report.confirmed_actions))throw Error('PASS requires all measured phases and enforcement.');
  const source=report.source_host||'reception1',kind=report.containment_action||'ISOLATE';
  if(!hosts.some(h=>h.name===source&&h.role!=='critical_server'&&kind===(['admin','guest'].includes(h.role)?'ISOLATE':'RESTRICT')))throw Error('Invalid attack source or containment type.');
  const action=kind=>report.confirmed_actions.find(a=>a.host===source&&a.action===kind&&a.status==='confirmed'&&/^[0-9a-f]{64}$/.test(a.proposal_id)&&Number.isSafeInteger(a.confirmed_ns));
  const isolate=action(kind),release=action('RELEASE');
  if(!isolate||!release||isolate.proposal_id===release.proposal_id||!(report.phases.baseline.end_ns<=isolate.confirmed_ns&&isolate.confirmed_ns<=report.phases.restricted.start_ns&&report.phases.restricted.end_ns<=release.confirmed_ns&&release.confirmed_ns<=report.phases.recovered.start_ns))throw Error('PASS lacks ordered installation and release confirmations.');
 }
 return report;
}
function renderDemoEvidence(report){
 $('phase-cards').replaceChildren();
 for(const [name,phase]of Object.entries(report.phases)){
  const rows=phase.clinical.services.flatMap(s=>s.sources),attempted=rows.reduce((n,r)=>n+r.attempted,0),received=rows.reduce((n,r)=>n+r.received,0);
  const card=document.createElement('article');card.className='phase-card'+(name==='restricted'?' blocked':'');
  const title=document.createElement('h3');title.textContent=name;card.append(title);
  for(const [label,value]of [['Test ping',phase.ping.exit_code===0?'Reachable':phase.ping.exit_code===1?'Blocked':'Command error'],['C1–C5 probes',`${received} / ${attempted}`],['Sources measured',String(rows.length)]]){const row=document.createElement('div'),span=document.createElement('span'),strong=document.createElement('strong');span.textContent=label;strong.textContent=value;row.append(span,strong);card.append(row);}
  $('phase-cards').append(card);
 }
 $('report-title').textContent=report.status==='PASS'?'Automatic containment with measured C1–C5 continuity.':`Finite lab run: ${report.status}`;
 $('report-meta').textContent=`IMPORTED LOCAL REPORT · source ${report.source_host||'reception1'} · ${report.run_id} · user-provided, not independently verified · ${report.error||'No data leaves this browser'}`;
}

function renderAttackControls(){
 const host=hosts.find(h=>h.name===state.source),live=state.mode==='live';
 $('attack-host').value=state.selection==='random'?'random':state.source;
 $('attack-delay').value=String(state.attackDelay);$('attack-delay').disabled=state.running||live;
 $('attack-host').disabled=state.running||live;$('mark-host').disabled=state.running||live;
 $('mark-host').textContent=state.selection==='random'?'Choose another random device':'Place attacker on device';
 const flagged=live?state.liveMarked:state.marked?state.source:null;
 $('attacker-status').textContent=flagged?(live?`☠ ${flagged}: suspicious lab activity was observed. Release/no alert does not prove the device clean. Review the evidence before recording an assessment.`:`☠ ${flagged}: simulated attacker present. ${state.phase===2?(host.role==='critical_server'?'Protection needs an attributed source; no isolation. ':'Network containment illustrated. '):state.phase===3?'Connectivity restored. ':''}The attacker stays until you clear it or change the source.`):(live?'No latched suspicious-host marker. Current telemetry is separate from infection status.':`Next source: ${state.source}. Start or place the attacker to mark this device.`);
 $('attacker-status').classList.toggle('present',!!flagged);
 const supported=host.role!=='critical_server';
 $('lab-command').textContent=supported?`cd ~/SDN-Microsegmentation && sudo /usr/bin/python3 scripts/demo.py --enforce --host=${state.selection==='random'?'random':state.source}`:'Critical server: automatic isolation is prohibited. Choose an endpoint for the real containment demo; this selection is a visual review scenario.';
 $('lab-source-note').textContent=live?'Live view is read-only. Use the terminal command for a new finite experiment after the current run finishes. A marker is not an infection diagnosis.':'The simulation runs on this page. To use the selection in the real lab, stop a separately running dashboard and run this command in Linux. No malware is installed.';
}
function initialiseAttackControls(){
 for(const host of hosts){const option=document.createElement('option');option.value=host.name;option.textContent=`${host.name} · ${roles[host.role].label}`;$('attack-host').append(option);}
 $('attack-host').addEventListener('change',e=>{state.selection=e.target.value==='random'?'random':'manual';state.source=state.selection==='random'?differentEndpoint(state.source):e.target.value;state.selected=state.source;state.marked=false;state.review=null;$('review-details').hidden=true;$('review-ack').checked=false;saveScenario();resetDemo();});
 $('mark-host').addEventListener('click',()=>{if(state.mode!=='demo')return;if(state.selection==='random')state.source=differentEndpoint(state.source);state.selected=state.source;state.marked=true;state.review=null;$('review-details').hidden=true;$('review-ack').checked=false;saveScenario();resetDemo();});
 $('attack-delay').addEventListener('change',e=>{state.attackDelay=Number(e.target.value);resetDemo();saveScenario();});
 $('clear-attacker').addEventListener('click',openReview);
 $('review-device').addEventListener('click',openReview);
 $('resolve-device').addEventListener('click',()=>{openReview();$('review-record').textContent='Confirm that you have resolved the issue, then choose Problem resolved to restore the simulation.';});
 $('review-keep').addEventListener('click',()=>recordReview('still_suspicious'));
 $('review-remediated').addEventListener('click',()=>recordReview('remediation_recorded'));
 renderAttackControls();
}

function counterDelta(previous,current){
 const unknown=reason=>({rate:null,reason});
 if(!previous)return unknown('Collecting counter baseline');
 if(!previous.complete||!current.complete||previous.epoch!==current.epoch)return unknown('Incomplete / restarted interval · no zero-traffic claim');
 const seconds=(current.time-previous.time)/1e9;
 if(!(seconds>0&&seconds<5))return unknown('Counter interval unavailable');
 const keys=Object.keys(current.totals),oldKeys=Object.keys(previous.totals);
 if(keys.length!==oldKeys.length||oldKeys.some(k=>!current.totals[k]))return unknown('Rule set changed · collecting a new baseline');
 let packets=0;
 for(const key of keys){const row=current.totals[key],old=previous.totals[key];
  if(![row.packets,old.packets,row.duration,old.duration].every(v=>Number.isSafeInteger(v)&&v>=0)||row.packets<old.packets||row.duration<old.duration)return unknown('Counters reset or invalid · no zero-traffic claim');
  packets+=row.packets-old.packets;
 }
 return {rate:packets/seconds,reason:'Stable forwarding-rule deltas · excludes PacketOut / delivery proof'};
}

// ─── Human Override panel ───────────────────────────────────────────────────
(function initOverride(){
 for(const h of hosts){const opt=document.createElement('option');opt.value=h.name;opt.textContent=`${h.name} · ${roles[h.role].label}`;$('override-host').append(opt);}
})();
const overrideRoleNotes={
 ISOLATE:'ISOLATE blocks all traffic except the management exception. Permitted for admin/guest only. Use RESTRICT for clinical / IoMT.',
 RESTRICT:'RESTRICT blocks off-profile destinations while preserving vital clinical peers (EHR, PACS, central_mon). Correct for clinical workstations and IoMT devices.',
 PROTECT:'PROTECT installs a drop rule from a specific malicious source toward a critical server. The server itself is never isolated.',
 RELEASE:'RELEASE removes the active containment rule. This restores full access — verify the host is clean before releasing.'
};
function updateOverrideRoleNote(){const a=$('override-action').value,h=hosts.find(h=>h.name===$('override-host').value);$('override-role-note').textContent=`${overrideRoleNotes[a]||''} Configured role action: ${roles[h?.role]?.action||'—'}.`;}
function updateOverrideSubmit(){const hasToken=$('override-token').value.trim().length>=32,acked=$('override-ack').checked;$('override-submit').disabled=!(hasToken&&acked&&state.mode==='live');}
function setOverrideResult(text,cls=''){const el=$('override-result');el.textContent=text;el.className='override-result'+(cls?' '+cls:'');}
$('override-host').addEventListener('change',updateOverrideRoleNote);
$('override-action').addEventListener('change',updateOverrideRoleNote);
$('override-ack').addEventListener('change',updateOverrideSubmit);
$('override-token').addEventListener('input',updateOverrideSubmit);
updateOverrideRoleNote();
$('override-submit').addEventListener('click',async()=>{
 const token=$('override-token').value.trim(),hostName=$('override-host').value,actionName=$('override-action').value;
 if(token.length<32){setOverrideResult('Token must be at least 32 characters.','error');return;}
 if(!$('override-ack').checked){setOverrideResult('Acknowledge the limits before sending.','error');return;}
 if(state.mode!=='live'){setOverrideResult('Connect to the live lab first.','error');return;}
 const epoch=state.decision?.controller_epoch||null;
 if(!epoch){setOverrideResult('No fresh controller epoch — wait for a live snapshot.','error');return;}
 setOverrideResult('⏳ Sending override to controller…','pending');
 $('override-submit').disabled=true;
 try{
  const host=hosts.find(h=>h.name===hostName);
  const pid=Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b=>b.toString(16).padStart(2,'0')).join('');
  const proposal={proposal_id:pid,controller_epoch:epoch,host:hostName,action:{action:actionName,host:hostName,role:host.role,segment:host.segment}};
  const body=JSON.stringify(proposal);
  const resp=await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body,signal:AbortSignal.timeout(10000)});
  const data=await resp.json();
  if(resp.ok){setOverrideResult(`✓ Accepted (HTTP ${resp.status}). Proposal ${pid.slice(0,16)}… queued. Wait for switch readback — queued ≠ installed.`,'success');toast(`Override: ${actionName} ${hostName} — waiting for switch readback.`);}
  else{setOverrideResult(`✗ Rejected (HTTP ${resp.status}): ${data.error||JSON.stringify(data).slice(0,200)}`,'error');}
 }catch(err){setOverrideResult(`✗ Request failed: ${err.message||String(err)}`,'error');}
 finally{updateOverrideSubmit();}
});
$('override-status-btn').addEventListener('click',async()=>{
 setOverrideResult('⏳ Fetching action status…','pending');
 try{
  const resp=await fetch('/api/snapshot',{cache:'no-store',signal:AbortSignal.timeout(6000)});
  if(!resp.ok)throw new Error('Bridge unavailable');
  const actions=state.decision?.actions||[];
  if(!actions.length){setOverrideResult('No recorded actions in the current snapshot.');return;}
  setOverrideResult(actions.slice(-6).map(a=>`${a.host}: ${a.action} — ${a.status}${a.confirmed_ns?' (readback confirmed)':''}`).join('\n'));
 }catch(err){setOverrideResult(`✗ ${err.message}`,'error');}
});
function syncOverridePanel(){const live=state.mode==='live';$('override-panel').classList.toggle('live-active',live);$('override-scope').textContent=live?'LIVE MODE ACTIVE':'LIVE MODE ONLY — connect your lab to enable';updateOverrideSubmit();}
new MutationObserver(syncOverridePanel).observe($('mode-notice'),{childList:true,characterData:true,subtree:true});
syncOverridePanel();
