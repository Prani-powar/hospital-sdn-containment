/* Persistent lab commands are available only from the owned local session. */
(()=>{
 if(!['localhost','127.0.0.1'].includes(location.hostname))return;
 const panel=document.createElement('section');panel.className='panel';panel.style.cssText='padding:24px;margin:24px 0';panel.hidden=true;
 panel.innerHTML='<div class="eyebrow">REAL LOCAL LAB SESSION</div><h2>Choose a device. Watch the evidence.</h2><p id="lab-phase" role="status"></p><label>Probe source <select id="lab-host"></select></label> <button id="lab-launch" class="button primary" disabled>Start harmless probe</button><p>Real Mininet traffic: 4 packets/s for 16 seconds. The detector decides containment. Timed release does not clean a device. Wait for recovery before another scenario.</p><ol id="lab-events"></ol>';
 document.querySelector('main').prepend(panel);
 const phase=panel.querySelector('#lab-phase'), select=panel.querySelector('#lab-host'),button=panel.querySelector('#lab-launch'), events=panel.querySelector('#lab-events');
 let busy=false;
 button.onclick=async()=>{button.disabled=true;busy=true;try{
  const r=await fetch('/api/lab/scenario',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:select.value}),signal:AbortSignal.timeout(5000)});
  const body=await r.json();if(!r.ok)throw Error(body.error||'Scenario rejected');phase.textContent='Queued; waiting for owned probe launch';
  if(state.mode!=='live')await startLive();
 }catch(e){phase.textContent=e.message;}finally{busy=false;}};
 async function poll(){try{
  const r=await fetch('/api/lab',{cache:'no-store',signal:AbortSignal.timeout(4000)});if(!r.ok)throw Error('Session unavailable');
  const lab=await r.json();state.lab=lab;state.labSeen=performance.now();panel.hidden=false;
  if(!select.options.length)for(const name of lab.eligible_hosts){const o=document.createElement('option');o.value=name;o.textContent=name;select.append(o);}
  phase.textContent=lab.phase+(lab.host?' · '+lab.host:'');button.disabled=busy||!lab.ready;
  events.replaceChildren();for(const e of lab.events.slice(-6)){const li=document.createElement('li');li.textContent=e.text;events.append(li);}
  if(state.mode==='live')renderNetwork();
 }catch(e){state.lab=null;button.disabled=true;if(!panel.hidden)phase.textContent='Lab unavailable. Check the launcher terminal.';if(state.mode==='live')renderNetwork();}
 setTimeout(poll,1500);}
 poll();
})();
