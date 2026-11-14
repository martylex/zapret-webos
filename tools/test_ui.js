'use strict';
// Verify IPC requests and response ordering without executing a privileged command.
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const ids = ['start','stop','restart','alt3','alt2','autostart','status','status-dot','status-description','message','autostart-label','platform','tls-count','udp-count','fake-count','limits','log','details','log-toggle','refresh','all-strategies','strategy-picker','picker-close','picker-input','strategy-options','current-strategy'];
const elements = {};
const events = {}, buttons = ['start','stop','restart','alt3','alt2','autostart','log-toggle','refresh','all-strategies','picker-close'];
const document = {body: {}, activeElement: null, getElementById: id => elements[id], addEventListener(name, fn) {events[name]=fn;}, querySelectorAll(selector) {return buttons.filter(id=>!selector.startsWith('#strategy-picker ') || id.startsWith('choice-') || id==='picker-close').map(id => elements[id]);}, createElement() {return makeElement('',true);}};
function makeElement(id,button) {return {id, tagName:button?'BUTTON':'DIV', disabled:false, hidden:id==='details'||id==='strategy-picker',textContent:'',className:'',attrs:{},setAttribute(k,v){this.attrs[k]=v;},focus(){document.activeElement=this;},click(){if(!this.disabled&&this.onclick)this.onclick();},scrollIntoView(){},appendChild(child){elements[child.id]=child;buttons.push(child.id);}};}
for (const id of ids) elements[id] = makeElement(id,buttons.includes(id));
const requests = [], intervals = [];
function Bridge() { this.call = (uri, args) => requests.push({bridge:this,uri,payload:JSON.parse(args)}); }
const context = {document, window:{location:{pathname:'/media/developer/apps/usr/palm/applications/org.flowseal.webos/index.html'}}, PalmServiceBridge:Bridge, setTimeout(){return 1;}, clearTimeout(){}, setInterval(fn){intervals.push(fn);}, console};
vm.runInNewContext(fs.readFileSync('app/strategies.js','utf8'),context);
vm.runInNewContext(fs.readFileSync('app/app.js','utf8'),context);
function reply(request, running, strategy='alt3') {
  request.bridge.onservicecallback(JSON.stringify({returnValue:true,stdoutString:JSON.stringify({returnValue:true,running,strategy,autostart:false,architecture:'armv7l',kernel:'4.4.84',engine:{counters:{transformed:3}},limits:[],log:[]})}));
}
assert.strictEqual(requests[0].uri,'luna://org.webosbrew.hbchannel.service/exec');
assert(requests[0].payload.command.endsWith("'status'"));
reply(requests[0],false);
assert.strictEqual(elements.status.textContent,'Stopped');
assert.strictEqual(elements.alt3.attrs['aria-pressed'],'true');
assert.strictEqual(elements.start.disabled,false);
intervals[0](); const stale = requests[1];
elements.start.onclick(); const start = requests[2];
assert(start.payload.command.endsWith("'start'"));
reply(start,true); reply(stale,false);
assert.strictEqual(elements.status.textContent,'Running');
assert.strictEqual(elements.stop.disabled,false);
elements.alt2.onclick(); const alternative = requests[3];
assert(alternative.payload.command.endsWith("'strategy-alt2'"));
reply(alternative,true,'alt2');
assert.strictEqual(elements.alt2.attrs['aria-pressed'],'true');
elements.autostart.onclick();
assert(requests[4].payload.command.endsWith("'autostart-on'"));
requests[4].bridge.onservicecallback(JSON.stringify({returnValue:false,errorText:'Root service unavailable'}));
assert.strictEqual(elements.message.textContent,'Root service unavailable');
assert.strictEqual(elements.message.className,'error');
function key(code, repeat=false) {
  const event = {keyCode:code,repeat,preventDefault(){this.prevented=true;}};
  events.keydown(event); assert(event.prevented);
}
function shortcut(code, action, running, strategy='alt3') {
  const count = requests.length;
  key(code);
  assert.strictEqual(requests.length,count+1);
  assert(requests[count].payload.command.endsWith("'"+action+"'"));
  key(code,true); assert.strictEqual(requests.length,count+1,'Held key should not repeat an action');
  reply(requests[count],running,strategy);
}
shortcut(49,'strategy-alt3',true);
shortcut(50,'strategy-alt2',true,'alt2');
shortcut(52,'stop',false,'alt2');
const stoppedCount=requests.length;
key(52); assert.strictEqual(requests.length,stoppedCount,'Disabled Stop must not run');
shortcut(51,'start',true,'alt2');
shortcut(53,'restart',true,'alt2');
shortcut(97,'strategy-alt3',true); // numeric keypad
shortcut(48,'status',true);
key(54); assert.strictEqual(elements.details.hidden,false);
elements['log-toggle'].focus(); key(13); assert.strictEqual(elements.details.hidden,true);
elements.alt2.onmouseover(); assert.strictEqual(document.activeElement,elements.alt2);
assert.strictEqual(context.window.FlowsealStrategies.length,22);
key(55); assert.strictEqual(elements['strategy-picker'].hidden,false);
key(50); key(50);
assert.strictEqual(elements['strategy-picker'].hidden,true);
assert(requests.at(-1).payload.command.endsWith("'strategy-exp'"));
reply(requests.at(-1),true,'exp');
assert.strictEqual(elements['choice-exp'].attrs['aria-pressed'],'true');
key(55); key(48); key(49);
assert(requests.at(-1).payload.command.endsWith("'strategy-alt3'"));
reply(requests.at(-1),true);
for (const choice of context.window.FlowsealStrategies) {
  elements['all-strategies'].click();
  elements['choice-'+choice.id].click();
  assert(requests.at(-1).payload.command.endsWith("'strategy-"+choice.id+"'"));
  reply(requests.at(-1),true,choice.id);
}
key(55); key(461); assert.strictEqual(elements['strategy-picker'].hidden,true);
console.log('PASS: Homebrew IPC, stale responses, errors, remote numbers/OK, pointer focus, 22 distinct selectable actions, two-digit picker and Back');
