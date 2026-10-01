(()=>{'use strict';
let bootstrap="__BOOTSTRAP__";
const relayOrigin='https://__HOST__',relayBase=relayOrigin+'__BASE_PREFIX__',carrierCapabilities='https,https-lanes,websocket,websocket-lanes';
__DIAGNOSTIC_BINDING__;
__DIAGNOSTIC_RUNTIME_STARTED__;
const responseBody=globalThis.TelemtBridgeResponse;if(!responseBody)throw new Error('missing response runtime');
const requestSupport=globalThis.TelemtBridgeRequest;if(!requestSupport)throw new Error('missing request runtime');
const bufferSupport=globalThis.TelemtBridgeBuffers;if(!bufferSupport)throw new Error('missing buffer runtime');
const recoverySupport=globalThis.TelemtBridgeRecovery;if(!recoverySupport)throw new Error('missing recovery runtime');
// Keep the method page-owned so recovery and config rollback cannot change frozen retries.
const carrierMethod='__CARRIER_METHOD__';
let negotiationEnabled=__NEGOTIATION_ENABLED__,candidateCount=__CANDIDATE_COUNT__,candidateDeadlines=[__CARRIER_DEADLINES__];
let longPollMs=__LONG_POLL_SECS__*1000,bridgeRequestMs=__BRIDGE_REQUEST_SECS__*1000,bridgeRetryMs=__BRIDGE_RETRY_SECS__*1000;
let bridgeRecoveryMs=__BRIDGE_RECOVERY_SECS__*1000,websocketOpenMs=__WEBSOCKET_OPEN_SECS__*1000,reconnectGraceMs=__RECONNECT_GRACE_SECS__*1000;
let probeCoalesceMs=__CARRIER_PROBE_COALESCE_MS__;
let negotiatedCandidateCount=candidateCount,negotiatedFinalDeadline=candidateDeadlines[3],negotiatedFrozen=false;
let batchLimit=__BATCH_LIMIT__,queueLimit=__QUEUE_LIMIT__,queueItemLimit=__QUEUE_ITEMS__,maxStreams=__MAX_STREAMS__;
let laneQueueLimit=Math.min(queueLimit,8388608),laneItemLimit=Math.min(queueItemLimit,1024);const closedLaneLimit=4096;
const fragment=location.hash,androidNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1]||'',recoveryPath=location.pathname+location.search;
history.replaceState(null,'',location.pathname);
let initialized=false,closed=false,port=null,sessionToken='',cleanupToken='',createStarted=false,socket=null,socketReady=false,carrier='';
let upSequence=1,downCursor='0',upRunning=false,upLease=null,pollController=null;
let helloFrame=null,helloTimer=null,welcomeSent=false,carrierAttempt=1,carrierFailure='',carrierCommitted=false,terminalFailure='';
let negotiationStartedAt=0,carrierTimer=null,probeTimer=null,attemptController=null,attemptEpoch=1,candidateRunning=false,switching=false,currentAttempt=null;
let recoveryController=null,recoveryCommit=null,recoveryReplaced=false,lastSchedulerWall=Date.now(),lastSchedulerMonotonic=performance.now(),schedulerGapPending=0,schedulerTimer=null;
const pending=[],upPending=[],recoveryPending=[],lanes=new Map(),closedLanes=new Set(),closedLaneOrder=[];
const canonicalFailures=['timeout','network','upgrade','http','protocol'];
const failure=(reason,message)=>Object.assign(new Error(message||reason),{telemtReason:reason});
const failureReason=(error,fallback)=>error&&canonicalFailures.includes(error.telemtReason)?error.telemtReason:fallback;
const status=__STATUS_FUNCTION__;
const socketURL=()=>relayBase.replace(/^https:/,'wss:')+'/api/v1/ws';
const requestClient=requestSupport.create({
 base:()=>relayBase,closed:()=>closed,retryMs:()=>bridgeRetryMs,longPollMs:()=>longPollMs,requestMs:()=>bridgeRequestMs,
 batchLimit:()=>batchLimit,read:(response,limit,exact,signal)=>responseBody.read(response,limit,exact,signal),cancel:responseBody.cancel,
 failure,reason:failureReason,retrying:()=>status('reconnecting')
});
const options=requestClient.options,pause=requestClient.pause,request=requestClient.send;
const buffers=bufferSupport.create({
 limits:()=>({batchBytes:batchLimit,queueBytes:queueLimit,queueItems:queueItemLimit,laneBytes:laneQueueLimit,laneItems:laneItemLimit}),
 buffered:()=>{let total=socket?socket.bufferedAmount:0;for(const value of lanes.values())if(value.socket)total+=value.socket.bufferedAmount;return total},
 pending:()=>pending,laneMode:()=>carrier==='https-lanes'||carrier==='websocket-lanes',maxStreams:()=>maxStreams,failure
});
const {reserve,release,releasePending,frameBound,splitFrames,acceptNativeFrames,observeServerFrames,findProbe,consumeProbe,takeBatch,closeFrame,retireStream,retireAllStreams,clearStreams}=buffers;
function detachLease(lease){if(lease.lane){if(lease.lane.upLease===lease)lease.lane.upLease=null}else if(upLease===lease)upLease=null}
function settleBatch(lease){if(!buffers.settleBatch(lease))return false;detachLease(lease);return true}
function cancelBatch(lease){if(!lease||lease.settled)return;buffers.cancelBatch(lease);detachLease(lease)}
const attemptHeaders=(attempt,failure)=>negotiationEnabled?Object.assign({'X-Carrier-Capabilities':carrierCapabilities,'X-Carrier-Attempt':String(attempt)},failure?{'X-Carrier-Failure':failure}:{}):{};
function finishOldRecovery(){
 recoveryReplaced=false;resetScheduler();status('connected');
 while(recoveryPending.length&&!closed){const data=recoveryPending.shift();release(data.byteLength,1,null);queueCarrier(data)}
}
function rejectRecoveryCommit(error){
 const commit=recoveryCommit;if(!commit)return;recoveryCommit=null;
 commit.signal.removeEventListener('abort',commit.abort);commit.reject(error);
}
function resolveRecoveryCommit(){
 const commit=recoveryCommit;if(!commit)return;recoveryCommit=null;recoveryReplaced=false;
 commit.signal.removeEventListener('abort',commit.abort);commit.resolve();
}
function retireCarrier(policy){
 recoveryReplaced=true;attemptEpoch++;if(carrierTimer)clearTimeout(carrierTimer);carrierTimer=null;clearProbeTimer();
 if(attemptController)attemptController.abort();attemptController=null;if(pollController)pollController.abort();pollController=null;
 if(socket){const previous=socket;socket=null;previous.close()}socketReady=false;cancelBatch(upLease);releasePending(upPending,null);
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();cancelBatch(lane.upLease);releasePending(lane.pending,lane);if(lane.socket)lane.socket.close();
 }
 lanes.clear();closedLanes.clear();closedLaneOrder.length=0;releasePending(pending,null);releasePending(recoveryPending,null);
 for(const id of retireAllStreams())if(port){const frame=closeFrame(id);port.postMessage(frame,[frame])}
 bootstrap=policy.bootstrap;__DIAGNOSTIC_BOOTSTRAP_REPLACED__;batchLimit=policy.limits.carrier_batch_bytes;queueLimit=policy.limits.pending_bytes_per_session;
 queueItemLimit=policy.limits.pending_items_per_session;maxStreams=policy.limits.max_streams_per_session;
 laneQueueLimit=Math.min(queueLimit,8388608);laneItemLimit=Math.min(queueItemLimit,1024);
 longPollMs=policy.timeouts.long_poll_secs*1000;bridgeRequestMs=policy.timeouts.bridge_request_secs*1000;
 bridgeRetryMs=policy.timeouts.bridge_retry_secs*1000;bridgeRecoveryMs=policy.timeouts.bridge_recovery_secs*1000;
 websocketOpenMs=policy.timeouts.websocket_open_secs*1000;reconnectGraceMs=policy.timeouts.reconnect_grace_secs*1000;
 armScheduler();
 negotiationEnabled=policy.negotiation.enabled;candidateCount=policy.negotiation.candidate_count;
 candidateDeadlines=policy.negotiation.deadlines_secs;probeCoalesceMs=policy.negotiation.carrier_probe_coalesce_ms;
 negotiatedCandidateCount=candidateCount;negotiatedFinalDeadline=candidateDeadlines[3];negotiatedFrozen=false;
 sessionToken='';cleanupToken='';carrier='';carrierAttempt=1;carrierFailure='';carrierCommitted=false;
 candidateRunning=false;switching=false;currentAttempt=null;upSequence=1;downCursor='0';upRunning=false;
}
function replaceCarrier(policy,signal,remaining){
 if(closed||!helloFrame||!port)throw failure('protocol','missing recovery owner');
 retireCarrier(policy);negotiationStartedAt=Date.now();armCarrierDeadline(attemptEpoch);
 return new Promise((resolve,reject)=>{
  const abort=()=>rejectRecoveryCommit(failure('timeout','recovery deadline'));
  recoveryCommit={resolve,reject,signal,abort};signal.addEventListener('abort',abort,{once:true});
  if(signal.aborted||remaining()<=0){abort();return}createSession(attemptEpoch);
 });
}
function recoverTransport(error,replay){
 if(closed)return Promise.resolve(false);
 const reason=failureReason(error,'network');
 if(reason==='protocol'){fail(reason);return Promise.resolve(false)}
 return recoveryController.recover(reason,replay);
}
function schedulerGap(){
 const wall=Date.now(),monotonic=performance.now();
 const gap=Math.max(0,wall-lastSchedulerWall,monotonic-lastSchedulerMonotonic);
 lastSchedulerWall=wall;lastSchedulerMonotonic=monotonic;return gap;
}
function resetScheduler(){schedulerGapPending=0;schedulerGap()}
function armScheduler(){
 if(schedulerTimer)clearTimeout(schedulerTimer);schedulerTimer=closed?null:setTimeout(sampleScheduler,Math.max(250,Math.min(30000,Math.floor(reconnectGraceMs/4))));
}
function sampleScheduler(){
 schedulerTimer=null;const gap=schedulerGap();if(carrierCommitted&&!recoveryController.active())schedulerGapPending=Math.max(schedulerGapPending,gap);armScheduler();
}
function observeResumeTrigger(){
 const gap=Math.max(schedulerGapPending,schedulerGap());schedulerGapPending=0;if(!carrierCommitted||closed)return;
 if(gap>=2*longPollMs)status('reconnecting');
 if(gap>=reconnectGraceMs&&!recoveryController.active())recoveryController.recover('timeout',null);
}
function fail(reason){
 if(closed)return;reason=reason||'protocol';if(canonicalFailures.includes(reason))terminalFailure=reason;
 rejectRecoveryCommit(failure(reason));
 status('failed');if(port)port.postMessage({t:'close'});close(true);
}
function knownCarrier(value){return value==='https'||value==='https-lanes'||value==='websocket'||value==='websocket-lanes'}
function sessionEcho(response,expectedAttempt,states,exactAttempt){
 const selected=response.headers.get('X-Carrier-Mode')||'',echo=response.headers.get('X-Carrier-Attempt')||'';
 if(!knownCarrier(selected))throw new Error('invalid carrier mode');
 if(!negotiationEnabled){if(echo!=='')throw new Error('unexpected carrier attempt');return {selected,state:''}}
 const count=response.headers.get('X-Carrier-Candidate-Count')||'',deadline=response.headers.get('X-Carrier-Deadline')||'',state=response.headers.get('X-Carrier-State')||'';
 if(!/^[1-4]$/.test(count)||!/^[1-9]\d*$/.test(deadline)||!states.includes(state))throw new Error('invalid carrier state');
 const echoedAttempt=Number(echo),parsedCount=Number(count),parsedDeadline=Number(deadline);
 if(!Number.isInteger(echoedAttempt)||echoedAttempt<1||(exactAttempt?echoedAttempt!==expectedAttempt:echoedAttempt>expectedAttempt))throw new Error('invalid carrier attempt');
 if(parsedCount>candidateCount||parsedDeadline>candidateDeadlines[3])throw new Error('invalid carrier bounds');
 if(!negotiatedFrozen){negotiatedCandidateCount=parsedCount;negotiatedFinalDeadline=parsedDeadline;negotiatedFrozen=true}
 else if(parsedCount!==negotiatedCandidateCount||parsedDeadline!==negotiatedFinalDeadline)throw new Error('changed carrier bounds');
 if(echoedAttempt>negotiatedCandidateCount)throw new Error('carrier attempt exceeds candidates');
 return {selected,state};
}
function armCarrierDeadline(epoch){
 if(!negotiationStartedAt||epoch!==attemptEpoch)return;
 if(carrierTimer)clearTimeout(carrierTimer);
 const deadline=carrierAttempt>=negotiatedCandidateCount?negotiatedFinalDeadline:candidateDeadlines[carrierAttempt-1];
 const remaining=negotiationStartedAt+deadline*1000-Date.now();
 carrierTimer=setTimeout(()=>advanceCarrier('timeout',epoch),Math.max(0,remaining));
}
function clearProbeTimer(){if(probeTimer){clearTimeout(probeTimer.timer);probeTimer=null}}
function resetCandidate(){
 clearProbeTimer();
 if(pollController)pollController.abort();pollController=null;
 if(socket){const previous=socket;socket=null;previous.close()}socketReady=false;
 cancelBatch(upLease);releasePending(upPending,null);
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();cancelBatch(lane.upLease);releasePending(lane.pending,lane);if(lane.socket)lane.socket.close();
 }
 lanes.clear();closedLanes.clear();closedLaneOrder.length=0;upSequence=1;downCursor='0';upRunning=false;
 sessionToken='';carrier='';candidateRunning=false;currentAttempt=null;
}
function advanceConfirmed(reason,epoch){
 if(closed||carrierCommitted||epoch!==attemptEpoch)return;
 resetCandidate();
 if(carrierAttempt>=negotiatedCandidateCount||Date.now()>=negotiationStartedAt+negotiatedFinalDeadline*1000){switching=false;fail(reason);return}
 carrierAttempt++;carrierFailure=reason;attemptEpoch++;const nextEpoch=attemptEpoch;switching=false;
 status('reconnecting');armCarrierDeadline(nextEpoch);createSession(nextEpoch);
}
function advanceCarrier(reason,epoch){
 if(closed||carrierCommitted||epoch!==attemptEpoch||switching)return;
 if(!negotiationEnabled){fail(reason);return}
 switching=true;if(carrierTimer)clearTimeout(carrierTimer);carrierTimer=null;clearProbeTimer();
 const snapshot=currentAttempt;if(attemptController)attemptController.abort();attemptController=null;
 if(!snapshot||snapshot.epoch!==epoch){switching=false;fail('protocol');return}
 if(snapshot.selected){advanceConfirmed(reason,epoch);return}
 resolveAttempt(reason,epoch,snapshot);
}
async function resolveAttempt(reason,epoch,snapshot){
 const controller=new AbortController();attemptController=controller;
 const remaining=negotiationStartedAt+negotiatedFinalDeadline*1000-Date.now();
 if(remaining<=0){switching=false;fail('timeout');return}
 const timer=setTimeout(()=>controller.abort(),remaining);
 try{
  const frozen=options('POST',bootstrap,snapshot.hello,attemptHeaders(snapshot.attempt,snapshot.failure),controller.signal);
  const response=await request('/api/v1/session',frozen);
  if(closed||epoch!==attemptEpoch)return
  if(response.status===409){sessionEcho(response,snapshot.attempt,['committed','healthy'],false);switching=false;fail('protocol');return}
  if(response.status!==200){switching=false;fail('http');return}
  const echo=sessionEcho(response,snapshot.attempt,['provisional','committed','healthy'],true);
  const token=response.headers.get('X-Session-Token')||'',cursor=response.headers.get('X-Down-Cursor')||'';
  if(!token||cursor!=='0'||(snapshot.selected&&echo.selected!==snapshot.selected))throw new Error('changed carrier replay');
  const welcome=response.body;if(closed||epoch!==attemptEpoch)return;
  cleanupToken=token;
  if(!welcomeSent){welcomeSent=true;port.postMessage(welcome,[welcome]);status('connecting')}
  if(echo.state!=='provisional'){switching=false;fail('protocol');return}
  advanceConfirmed(reason,epoch);
 }catch(error){if(!closed&&epoch===attemptEpoch){switching=false;fail(failureReason(error,'protocol'))}}
 finally{clearTimeout(timer);if(attemptController===controller)attemptController=null}
}
function startCandidate(probe,epoch){
 if(!probe||closed||carrierCommitted||!sessionToken||candidateRunning||epoch!==attemptEpoch)return;
 clearProbeTimer();candidateRunning=true;
 if(carrier==='https')probeHttp(probe,null,epoch);
 else if(carrier==='https-lanes')probeHttp(probe,probe.id,epoch);
 else if(carrier==='websocket')openCandidateSocket(probe,null,epoch);
 else if(carrier==='websocket-lanes')openCandidateSocket(probe,probe.id,epoch);
 else advanceCarrier('protocol',epoch);
}
function maybeStartCandidate(){
 if(closed||carrierCommitted||!sessionToken||candidateRunning)return;const epoch=attemptEpoch;
 let probe;try{probe=findProbe(probeCoalesceMs>0)}catch(error){fail('protocol');return}if(!probe)return;
 if(!probeCoalesceMs||probe.hasData){startCandidate(probe,epoch);return}
 if(probeTimer)return;const owner={epoch,timer:null};
 owner.timer=setTimeout(()=>{if(probeTimer!==owner||closed||owner.epoch!==attemptEpoch)return;probeTimer=null;let current;try{current=findProbe(false)}catch(error){fail('protocol');return}startCandidate(current,owner.epoch)},probeCoalesceMs);
 probeTimer=owner;
}
async function createSession(epoch){
 const controller=new AbortController(),attempt=carrierAttempt,failure=carrierFailure;
 const snapshot={epoch,attempt,failure,hello:helloFrame,selected:''};currentAttempt=snapshot;attemptController=controller;
 try{
  status('connecting');
  const frozen=options('POST',bootstrap,snapshot.hello,attemptHeaders(attempt,failure),controller.signal);
  const response=await request('/api/v1/session',frozen);
  if(closed||epoch!==attemptEpoch)return
  if(response.status===409){sessionEcho(response,attempt,['committed','healthy'],false);fail('protocol');return}
  if(response.status!==200){advanceCarrier('http',epoch);return}
  const echo=sessionEcho(response,attempt,['provisional'],true),selected=echo.selected;snapshot.selected=selected;
  const token=response.headers.get('X-Session-Token')||'',cursor=response.headers.get('X-Down-Cursor')||'';
  if(!token||cursor!=='0'){advanceCarrier('protocol',epoch);return}
  const welcome=response.body;if(closed||epoch!==attemptEpoch)return;
  carrier=selected;sessionToken=token;cleanupToken=token;downCursor=cursor;
  if(!welcomeSent){welcomeSent=true;port.postMessage(welcome,[welcome]);status('connecting')}
  if(carrier==='websocket')openCandidateSocket(null,null,epoch);
  maybeStartCandidate();
 }catch(error){if(closed||epoch!==attemptEpoch)return;advanceCarrier(failureReason(error,'network'),epoch)}
}
async function probeHttp(probe,laneID,epoch){
 try{
  const headers={'X-Up-Seq':'1'},token=sessionToken,controller=attemptController,body=probe.data;if(laneID!==null)headers['X-Lane-ID']=String(laneID);
  const response=await request('/api/v1/up',options(carrierMethod,token,body,headers,controller.signal));
  if(closed||epoch!==attemptEpoch)return
  if(response.status!==204){advanceCarrier('http',epoch);return}
  if(response.headers.get('X-Up-Ack')!=='1'){advanceCarrier('protocol',epoch);return}
  if(laneID===null)upSequence=2;else ensureLane(laneID).sequence=2;
  commitCarrier(probe,epoch);
 }catch(error){if(!closed&&epoch===attemptEpoch)advanceCarrier(failureReason(error,'network'),epoch)}
}
function commitCarrier(probe,epoch){
 if(closed||carrierCommitted||epoch!==attemptEpoch)return;
 if(switching){fail('protocol');return}
 clearProbeTimer();try{consumeProbe(probe)}catch(error){fail('protocol');return}
 carrierCommitted=true;candidateRunning=false;if(carrierTimer)clearTimeout(carrierTimer);carrierTimer=null;
 resetScheduler();
 attemptController=null;currentAttempt=null;
 status('connected');
 if(carrier==='https')poll();
 else if(carrier==='https-lanes'){const lane=lanes.get(probe.id);if(lane&&!lane.polling)pollLane(lane)}
 while(pending.length&&!closed){const data=pending.shift();release(data.byteLength,1,null);queueCarrier(data)}
 resolveRecoveryCommit();
}
function queueCarrier(data){
 if(closed)return;
 try{
  if(carrier==='https')queueUp(data);
  else if(carrier==='websocket')queueSocket(data);
  else for(const value of splitFrames(data)){if(closed)break;queueLane(value)}
 }catch(error){fail('protocol')}
}
function queueUp(data){if(!reserve(data,null)){fail('capacity');return}upPending.push(data);runUp()}
async function runUp(){
 if(upRunning)return;upRunning=true;const ownerEpoch=attemptEpoch;let lease=null;
 try{
  while(!closed&&sessionToken&&upPending.length){
   lease=takeBatch(upPending,null);upLease=lease;lease.controller=new AbortController();const sequence=String(upSequence),token=sessionToken;
   for(;;){
    try{
     const response=await request('/api/v1/up',options(carrierMethod,token,lease.body,{'X-Up-Seq':sequence},lease.controller.signal),null,1);
     if(response.status!==204)throw failure('http','uplink rejected');
     if(response.headers.get('X-Up-Ack')!==sequence)throw failure('protocol','uplink acknowledgement rejected');
     break;
    }catch(error){
     let replayed=false;
     const recovered=await recoverTransport(error,async(signal,remaining)=>{
      const response=await request('/api/v1/up',options(carrierMethod,token,lease.body,{'X-Up-Seq':sequence},signal),remaining,2);
      if(response.status!==204)throw failure('http','uplink replay rejected');
      if(response.headers.get('X-Up-Ack')!==sequence)throw failure('protocol','uplink replay acknowledgement rejected');
      replayed=true;
     });
     if(!recovered||closed||lease.cancelled||sessionToken!==token)return;
     if(!replayed)continue;
     break;
    }
   }
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});upSequence++;lease=null;
  }
 }catch(error){if(!closed&&!(lease&&lease.cancelled))fail(failureReason(error,'network'))}
 finally{if(ownerEpoch===attemptEpoch){upRunning=false;if(!closed&&sessionToken&&upPending.length)runUp()}}
}
function sendCandidateSocket(next){
 const state=next.telemt;if(!state||state.sent||next.readyState!==WebSocket.OPEN||!state.probe)return;
 let probe=state.probe;
 try{const fresh=findProbe(true);if(fresh&&fresh.id===probe.id)probe=fresh;next.send(probe.data)}catch(error){advanceCarrier('upgrade',state.epoch);return}
 state.probe=probe;state.sent=true;if(!negotiationEnabled){if(state.openTimer)clearTimeout(state.openTimer);state.openTimer=null;commitCarrier(probe,state.epoch)}
}
function openCandidateSocket(probe,laneID,epoch){
 let lane=laneID===null?null:ensureLane(laneID),next=lane?lane.socket:socket;
 if(next){if(!next.telemt||next.telemt.epoch!==epoch){advanceCarrier('protocol',epoch);return}if(probe)next.telemt.probe=probe;sendCandidateSocket(next);return}
 const token=sessionToken,protocol=laneID===null?(negotiationEnabled?'tproxy-auto-v1.':'tproxy-v1.')+token:(negotiationEnabled?'tproxy-auto-lane-v1.':'tproxy-lane-v1.')+token+'.'+String(laneID);
 next=new WebSocket(socketURL(),protocol);next.binaryType='arraybuffer';next.telemt={epoch,lane,probe,opened:false,sent:false,openTimer:null};
 next.telemt.openTimer=setTimeout(()=>{
  const state=next.telemt;if(closed||state.epoch!==attemptEpoch)return;
  next.close();advanceCarrier('timeout',state.epoch);
 },websocketOpenMs);
 if(lane)lane.socket=next;else socket=next;
 next.onopen=()=>{
  const state=next.telemt;if(closed||state.epoch!==attemptEpoch){next.close();return}state.opened=true;
  if(state.lane){state.lane.ready=true}else socketReady=true;sendCandidateSocket(next);
 };
 next.onmessage=event=>{
  const state=next.telemt;if(closed||state.epoch!==attemptEpoch||!(event.data instanceof ArrayBuffer))return;
  if(state.openTimer)clearTimeout(state.openTimer);state.openTimer=null;
  if(!carrierCommitted){if(!state.sent||event.data.byteLength!==0){advanceCarrier('protocol',state.epoch);return}commitCarrier(state.probe,state.epoch);return}
  try{
   if(state.lane){const values=splitFrames(event.data);for(const value of values)if(value.id!==state.lane.id)throw new Error('cross-lane frame');if(values.some(value=>value.type===3))state.lane.remoteClosed=true}
   else{const bound=frameBound(event.data,4096,batchLimit);if(bound.bytes!==event.data.byteLength)throw new Error('invalid frame batch')}
  }catch(error){if(state.lane)finishLane(state.lane,true);else fail('protocol');return}
  observeServerFrames(event.data);port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 next.onerror=()=>{};
 next.onclose=()=>{
  const state=next.telemt;if(state.openTimer)clearTimeout(state.openTimer);state.openTimer=null;if(state.epoch!==attemptEpoch||closed)return;
  if(!carrierCommitted){advanceCarrier(state.opened?'network':'upgrade',state.epoch);return}
  if(state.lane){state.lane.ready=false;state.lane.socket=null;finishLane(state.lane,true)}else{socketReady=false;recoveryController.recover('network',null)}
 };
}
function queueSocket(data){if(!reserve(data,null)){fail('capacity');return}upPending.push(data);runSocketUp()}
async function waitSocket(next,size,limit,signal){
 while(!closed&&next.readyState===WebSocket.OPEN&&next.bufferedAmount>limit-size)await pause(10,signal);
 if(closed||(signal&&signal.aborted)||next.readyState!==WebSocket.OPEN)throw new Error('websocket closed');
}
async function runSocketUp(){
 if(upRunning||!socketReady)return;upRunning=true;const ownerEpoch=attemptEpoch;let lease=null;
 try{
  while(!closed&&socketReady&&upPending.length){
   lease=takeBatch(upPending,null);upLease=lease;lease.controller=new AbortController();
   await waitSocket(socket,lease.total,queueLimit,lease.controller.signal);socket.send(lease.body);
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});lease=null;
  }
 }catch(error){if(!closed&&!(lease&&lease.cancelled))recoverTransport(error,null)}
 finally{if(ownerEpoch===attemptEpoch){upRunning=false;if(!closed&&socketReady&&upPending.length)runSocketUp()}}
}
async function poll(){
 while(!closed&&sessionToken){
  const token=sessionToken,cursor=downCursor;
  try{
   pollController=new AbortController();
   const response=await request('/api/v1/down',options(carrierMethod,token,null,{'X-Down-Cursor':cursor},pollController.signal),null,1);
   if(closed||sessionToken!==token)return;
   if(response.status===204){status('connected');continue}
   if(response.status!==200)throw failure('http','downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=response.body;
   if(!next||!data.byteLength)throw failure('protocol','invalid downlink response');
   if(closed)return;
   observeServerFrames(data);port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);downCursor=next;status('connected');
  }catch(error){
   if(closed)return;
   const recovered=await recoverTransport(error,async(signal,remaining)=>{
    const response=await request('/api/v1/down',options(carrierMethod,token,null,{'X-Down-Cursor':cursor},signal),remaining,2);
    if(response.status===204)return;
    if(response.status!==200||!response.body.byteLength||!response.headers.get('X-Down-Cursor'))throw failure('http','downlink replay rejected');
   });
   if(!recovered||closed||sessionToken!==token)return;
  }
 }
}
function ensureLane(id){
 let lane=lanes.get(id);
 if(!lane){lane={id,sequence:1,cursor:'0',pending:[],bytes:0,items:0,running:false,upLease:null,polling:false,controller:null,socket:null,ready:false,remoteClosed:false};lanes.set(id,lane)}
 return lane;
}
function rememberLaneClosed(id){
 if(!id||closedLanes.has(id))return;
 if(closedLaneOrder.length===closedLaneLimit)closedLanes.delete(closedLaneOrder.shift());
 closedLanes.add(id);closedLaneOrder.push(id);
}
function finishLane(lane,notifyClient){
 if(lanes.get(lane.id)!==lane)return;
 if(lane.controller)lane.controller.abort();lane.controller=null;cancelBatch(lane.upLease);
 if(lane.socket&&lane.socket.readyState<WebSocket.CLOSING)lane.socket.close();
 releasePending(lane.pending,lane);lanes.delete(lane.id);rememberLaneClosed(lane.id);
 if(notifyClient&&!lane.remoteClosed&&port){retireStream(lane.id);const frame=closeFrame(lane.id);port.postMessage(frame,[frame])}
}
function queueLane(value){
 let lane=lanes.get(value.id);
 if(!lane&&(value.type===2||value.type===3||value.type===4))return;
 if(!lane&&closedLanes.has(value.id))throw new Error('closed lane was reused');
 if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');
 lane=lane||ensureLane(value.id);
 if(!reserve(value.data,lane)){fail('capacity');return}
 lane.pending.push(value.data);
 if(carrier==='websocket-lanes'){openLaneSocket(lane);runLaneSocketUp(lane)}else runLaneUp(lane);
}
function openLaneSocket(lane){
 if(lane.socket||closed)return;lane.socket=new WebSocket(socketURL(),'tproxy-lane-v1.'+sessionToken+'.'+String(lane.id));lane.socket.binaryType='arraybuffer';
 const opened=lane.socket;let upgraded=false,settled=false,openTimer=null;const finishSocket=reason=>{if(settled)return;settled=true;if(openTimer)clearTimeout(openTimer);openTimer=null;if(closed||lanes.get(lane.id)!==lane||lane.socket!==opened)return;lane.ready=false;if(!upgraded){lane.socket=null;opened.close();recoveryController.recover(reason,null);return}finishLane(lane,true)};
 openTimer=setTimeout(()=>finishSocket('timeout'),websocketOpenMs);
 lane.socket.onopen=()=>{if(closed||lanes.get(lane.id)!==lane||lane.socket!==opened){opened.close();return}upgraded=true;lane.ready=true;status('connected');runLaneSocketUp(lane)};
 lane.socket.onmessage=event=>{
  if(openTimer)clearTimeout(openTimer);openTimer=null;
  if(closed||lanes.get(lane.id)!==lane||lane.socket!==opened||!(event.data instanceof ArrayBuffer)){finishLane(lane,true);return}
  let values;try{values=splitFrames(event.data);for(const value of values)if(value.id!==lane.id)throw new Error('cross-lane frame')}catch(error){finishLane(lane,true);return}
  if(values.some(value=>value.type===3))lane.remoteClosed=true;
  observeServerFrames(event.data);port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 lane.socket.onerror=()=>{};lane.socket.onclose=()=>finishSocket(upgraded?'network':'upgrade');
}
async function runLaneSocketUp(lane){
 if(lane.running||!lane.ready)return;lane.running=true;let lease=null;
 try{
  while(!closed&&lane.ready&&lanes.get(lane.id)===lane&&lane.pending.length){
   lease=takeBatch(lane.pending,lane);lane.upLease=lease;lease.controller=new AbortController();
   await waitSocket(lane.socket,lease.total,laneQueueLimit,lease.controller.signal);lane.socket.send(lease.body);
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});lease=null;
  }
 }catch(error){if(!closed&&lanes.get(lane.id)===lane&&!(lease&&lease.cancelled))finishLane(lane,true)}
 finally{lane.running=false;if(!closed&&lanes.get(lane.id)===lane&&lane.ready&&lane.pending.length)runLaneSocketUp(lane)}
}
async function runLaneUp(lane){
 if(lane.running)return;lane.running=true;let lease=null;
 try{
  while(!closed&&sessionToken&&lane.pending.length){
   lease=takeBatch(lane.pending,lane);lane.upLease=lease;lease.controller=new AbortController();
   const sequence=String(lane.sequence),laneID=String(lane.id),token=sessionToken;
   for(;;){
    try{
     const response=await request('/api/v1/up',options(carrierMethod,token,lease.body,{'X-Up-Seq':sequence,'X-Lane-ID':laneID},lease.controller.signal),null,1);
     if(response.status!==204)throw failure('http','lane uplink rejected');
     if(response.headers.get('X-Up-Ack')!==sequence)throw failure('protocol','lane uplink acknowledgement rejected');
     break;
    }catch(error){
     let replayed=false;
     const recovered=await recoverTransport(error,async(signal,remaining)=>{
      const response=await request('/api/v1/up',options(carrierMethod,token,lease.body,{'X-Up-Seq':sequence,'X-Lane-ID':laneID},signal),remaining,2);
      if(response.status!==204)throw failure('http','lane uplink replay rejected');
      if(response.headers.get('X-Up-Ack')!==sequence)throw failure('protocol','lane uplink replay acknowledgement rejected');
      replayed=true;
     });
     if(!recovered||closed||lease.cancelled||sessionToken!==token||lanes.get(lane.id)!==lane)return;
     if(!replayed)continue;
     break;
    }
   }
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});lane.sequence++;lease=null;
   if(!lane.polling)pollLane(lane);
  }
 }catch(error){if(!closed&&lanes.get(lane.id)===lane&&!(lease&&lease.cancelled))fail(failureReason(error,'network'))}
 finally{lane.running=false;if(!closed&&lanes.get(lane.id)===lane&&sessionToken&&lane.pending.length)runLaneUp(lane)}
}
async function pollLane(lane){
 if(!lane||lane.polling)return;lane.polling=true;let restart=false,failedToken='',failedCursor='',failedLaneID='';
 try{
  while(!closed&&sessionToken&&lanes.get(lane.id)===lane){
   const controller=new AbortController(),laneID=String(lane.id),token=sessionToken,cursor=lane.cursor;lane.controller=controller;
   failedToken=token;failedCursor=cursor;failedLaneID=laneID;
   const response=await request('/api/v1/down',options(carrierMethod,token,null,{'X-Down-Cursor':cursor,'X-Lane-ID':laneID},controller.signal),null,1);
   if(closed||sessionToken!==token||lanes.get(lane.id)!==lane)return;
   if(response.status===204){
    if(response.headers.get('X-Lane-Closed')==='1'){finishLane(lane,false);return}
    status('connected');continue;
   }
   if(response.status!==200)throw failure('http','lane downlink rejected');
   const next=response.headers.get('X-Down-Cursor')||'',data=response.body;
   if(!next||!data.byteLength)throw failure('protocol','invalid lane downlink response');
   for(const value of splitFrames(data))if(value.id!==lane.id)throw new Error('cross-lane frame');
   if(closed)return;
   observeServerFrames(data);port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);lane.cursor=next;status('connected');
  }
  }catch(error){
   if(!closed&&lanes.get(lane.id)===lane){
    const recovered=await recoverTransport(error,async(signal,remaining)=>{
     const response=await request('/api/v1/down',options(carrierMethod,failedToken,null,{'X-Down-Cursor':failedCursor,'X-Lane-ID':failedLaneID},signal),remaining,2);
     if(response.status===204)return;
     if(response.status!==200||!response.body.byteLength||!response.headers.get('X-Down-Cursor'))throw failure('http','lane downlink replay rejected');
    });
    restart=recovered&&!closed&&sessionToken===failedToken&&lanes.get(lane.id)===lane;
   }
  }
 finally{lane.polling=false;lane.controller=null;if(restart)pollLane(lane)}
}
function deleteSession(){
 const token=cleanupToken||sessionToken,headers=canonicalFailures.includes(terminalFailure)?{'X-Carrier-Failure':terminalFailure}:null;
 if(token)fetch(relayBase+'/api/v1/session',options('DELETE',token,null,headers,undefined,true)).catch(()=>{});
}
function close(notifyServer){
 if(closed)return;closed=true;if(recoveryController)recoveryController.cancel();rejectRecoveryCommit(failure('network','bridge closed'));if(helloTimer)clearTimeout(helloTimer);helloTimer=null;if(carrierTimer)clearTimeout(carrierTimer);clearProbeTimer();if(schedulerTimer)clearTimeout(schedulerTimer);schedulerTimer=null;if(attemptController)attemptController.abort();if(pollController)pollController.abort();
 if(socket)socket.close();cancelBatch(upLease);releasePending(upPending,null);
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();cancelBatch(lane.upLease);releasePending(lane.pending,lane);if(lane.socket)lane.socket.close();
 }
 if(notifyServer)deleteSession();releasePending(pending,null);releasePending(recoveryPending,null);lanes.clear();clearStreams();if(port)port.close();
 buffers.assertEmpty();
}
function activatePort(nextPort){
 initialized=true;port=nextPort;__DIAGNOSTIC_BOUNDARY_ACTIVATED__;
 port.onmessage=message=>{
  observeResumeTrigger();
  if(message.data instanceof ArrayBuffer){
   if(!createStarted){__DIAGNOSTIC_HELLO_RECEIVED__;createStarted=true;if(helloTimer)clearTimeout(helloTimer);helloTimer=null;helloFrame=message.data;if(negotiationEnabled){negotiationStartedAt=Date.now();armCarrierDeadline(attemptEpoch)}createSession(attemptEpoch)}
   else{
    let data;try{data=acceptNativeFrames(message.data)}catch(error){fail(error&&error.telemtReason==='capacity'?'capacity':'protocol');return}if(!data)return;
    if(recoveryController.active()&&!recoveryReplaced){if(!reserve(data,null)){fail('capacity');return}recoveryPending.push(data)}
    else if(!carrierCommitted){if(!reserve(data,null)){fail('capacity');return}pending.push(data);maybeStartCandidate()}
    else queueCarrier(data);
   }
  }else if(message.data&&message.data.t==='close'){__DIAGNOSTIC_CLIENT_CLOSE__;status('failed');close(true)}
 };
 port.start();status('connecting');helloTimer=setTimeout(__HELLO_TIMEOUT_CALLBACK__,bridgeRequestMs);
}
recoveryController=recoverySupport.create({
 budgetMs:()=>bridgeRecoveryMs,requestMs:()=>bridgeRequestMs,url:()=>relayOrigin+recoveryPath,token:()=>cleanupToken||sessionToken,
 read:(response,limit,exact,signal)=>responseBody.read(response,limit,exact,signal),cancel:responseBody.cancel,status:()=>status('reconnecting'),
 restored:finishOldRecovery,replace:replaceCarrier,replaceable:error=>failureReason(error,'network')!=='protocol',
 reason:(error,fallback)=>failureReason(error,fallback),terminal:reason=>fail(recoveryController.remaining()<=0?'timeout':reason)
});
armScheduler();
addEventListener('message',event=>{
 if(event.source!==parent)return;if(initialized){if(event.ports&&event.ports.length===1)event.ports[0].close();return}
 if(event.data===null||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let source;try{source=new URL(event.origin)}catch(error){return}
 if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;
 activatePort(event.ports[0]);
},{once:false});
function activateAndroid(androidBridge){
 const androidPort={onmessage:null,start(){},close(){androidBridge.onmessage=null},postMessage(value){
  if(value instanceof ArrayBuffer){
   let frames;try{frames=splitFrames(value)}catch(error){fail('protocol');return}
   for(const frame of frames)androidBridge.postMessage(frame.data);
  }else androidBridge.postMessage(JSON.stringify(value));
 }};
 androidBridge.onmessage=event=>{let data=event.data;if(typeof data==='string'){try{data=JSON.parse(data)}catch(error){return}}if(androidPort.onmessage)androidPort.onmessage({data})};
 activatePort(androidPort);androidBridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));
}
function discoverAndroid(){
 if(!androidNonce)return;const wall=Date.now()+bridgeRequestMs,monotonic=performance.now()+bridgeRequestMs;
 const probe=()=>{
  if(initialized||closed)return;const androidBridge=globalThis.TelegramWebProxy;
  if(androidBridge&&typeof androidBridge.postMessage==='function'){activateAndroid(androidBridge);return}
  const remaining=Math.min(wall-Date.now(),monotonic-performance.now());if(remaining>0)setTimeout(probe,Math.min(100,remaining));
 };probe();
}
discoverAndroid();
addEventListener('online',observeResumeTrigger);
if(globalThis.document&&typeof globalThis.document.addEventListener==='function')globalThis.document.addEventListener('visibilitychange',()=>{if(globalThis.document.visibilityState==='visible')observeResumeTrigger()});
addEventListener('pagehide',__PAGEHIDE_CALLBACK__,{once:true});
})();
