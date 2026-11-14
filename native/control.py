#!/usr/bin/env python
"""Root-only service lifecycle. Called through Homebrew Channel's existing LS2 API."""
from __future__ import print_function
import json, os, signal, subprocess, sys, time
from strategies import catalog

ROOT=os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
RUN='/tmp/flowseal-webos'
DATA='/var/lib/flowseal-webos'
HOOK='/var/lib/webosbrew/init.d/70-flowseal-webos'
STRATEGIES=dict((item['id'],item['label']) for item in catalog())


def read_json(path,default=None):
    try:
        with open(path) as f: return json.load(f)
    except (IOError,ValueError): return default


def save_json(path,value):
    tmp=path+'.tmp.'+str(os.getpid())
    with open(tmp,'w') as f: json.dump(value,f,sort_keys=True)
    os.rename(tmp,path)


def prepare():
    if os.geteuid()!=0: raise RuntimeError('Homebrew Channel root service is required')
    os.umask(0o077)
    for path in (RUN,DATA):
        if os.path.islink(path): raise RuntimeError('Refusing symlink '+path)
        if not os.path.isdir(path): os.mkdir(path,0o700)
        if os.stat(path).st_uid!=0: raise RuntimeError('Runtime directory is not owned by root')


def config():
    value=read_json(DATA+'/config.json',{'strategy':'alt3','autostart':False})
    if value.get('strategy') not in STRATEGIES: raise RuntimeError('Unsupported configured strategy')
    return value


def identity(pid):
    try:
        return open('/proc/%d/stat'%pid).read().split(') ',1)[1].split()[19]
    except (IOError,IndexError): return None


def record(pid): return {'pid':pid,'start':identity(pid),'root':ROOT}


def alive(value,script):
    if not value or value.get('root')!=ROOT or identity(value['pid'])!=value.get('start'): return False
    try:
        cmd=open('/proc/%d/cmdline'%value['pid'],'rb').read().split(b'\0')
        return (ROOT+'/native/'+script).encode() in cmd
    except IOError: return False


def tail():
    try:
        with open(RUN+'/service.log','rb') as f:
            f.seek(0,2); size=f.tell(); f.seek(max(0,size-10000))
            return f.read().decode('utf8','replace').splitlines()[-14:]
    except IOError: return []


def status():
    cfg=config()
    supervisor=read_json(RUN+'/supervisor.json')
    engine=read_json(RUN+'/engine.json')
    state=read_json(RUN+'/state.json',{})
    active=alive(supervisor,'control.py') and alive(engine,'engine.py') and state.get('pid')==engine['pid'] and state.get('running',False) and time.time()-state.get('heartbeat',0)<12
    hook=os.path.islink(HOOK) and os.path.realpath(HOOK)==ROOT+'/native/startup.sh'
    return {'returnValue':True,'running':bool(active),'strategy':cfg['strategy'],'strategyLabel':STRATEGIES[cfg['strategy']],
            'autostart':bool(cfg.get('autostart') and hook),'source':'Flowseal 1.10.4','kernel':os.uname()[2],
            'strategies':[dict((k,item[k]) for k in ['id','label','number','source']) for item in catalog()],
            'architecture':os.uname()[4],'engine':state,'root':ROOT,'log':tail(),
            'limits':['IPv4 only','QUIC v1 wire behavior tested; live HTTP/3 playback unverified','Game filter disabled as supplied','Autostart boot cycle unverified']}


def terminate(value,script):
    if not alive(value,script): return
    os.kill(value['pid'],signal.SIGCONT)
    os.kill(value['pid'],signal.SIGTERM)
    for _ in range(30):
        if not alive(value,script): return
        time.sleep(0.1)
    if alive(value,script): os.kill(value['pid'],signal.SIGKILL)


def stop():
    terminate(read_json(RUN+'/supervisor.json'),'control.py')
    terminate(read_json(RUN+'/engine.json'),'engine.py')
    for _ in range(30):
        if not os.path.exists('/sys/class/net/fszdev'): break
        time.sleep(0.1)
    if os.path.exists('/sys/class/net/fszdev'): raise RuntimeError('TUN still exists after stopping; refusing to delete an unverified interface')
    return status()


def start():
    if status()['running']: return status()
    if os.path.exists('/sys/class/net/fszdev'): stop()
    if os.path.exists(RUN+'/service.log') and os.path.getsize(RUN+'/service.log')>1000000:
        os.rename(RUN+'/service.log',RUN+'/previous.log')
    log=open(RUN+'/service.log','ab'); null=open('/dev/null','r')
    p=subprocess.Popen([sys.executable,'-B',ROOT+'/native/control.py','supervise'],stdin=null,stdout=log,stderr=subprocess.STDOUT,preexec_fn=os.setsid,close_fds=True)
    save_json(RUN+'/supervisor.json',record(p.pid))
    log.close(); null.close()
    for _ in range(60):
        time.sleep(0.1)
        result=status()
        if result['running']: return result
        if p.poll() is not None: break
    stop()
    raise RuntimeError('Engine startup failed: '+'\n'.join(tail()))


def supervise():
    running=[True]
    def handler(signum,frame): running[0]=False
    signal.signal(signal.SIGTERM,handler); signal.signal(signal.SIGINT,handler)
    p=None
    try:
        cfg=config()
        p=subprocess.Popen([sys.executable,'-B',ROOT+'/native/engine.py','--targets','all','--seconds','0','--strategy',cfg['strategy'],
                '--status',RUN+'/state.json','--parent',str(os.getpid())],close_fds=True)
        save_json(RUN+'/engine.json',record(p.pid))
        started=time.time()
        while running[0] and p.poll() is None:
            time.sleep(0.5)
            state=read_json(RUN+'/state.json',{})
            # The watchdog has its own process and never owns a TUN descriptor.
            if time.time()-started>12 and (state.get('pid')!=p.pid or time.time()-state.get('heartbeat',0)>8):
                print('Watchdog: stale engine heartbeat; stopping'); sys.stdout.flush(); break
            if not os.path.isfile(ROOT+'/native/engine.py'): break
    finally:
        if p is not None and p.poll() is None:
            p.terminate()
            for _ in range(10):
                if p.poll() is not None: break
                time.sleep(0.1)
            # SIGKILL also handles a SIGSTOPed or otherwise hung child.
            if p.poll() is None: p.kill()
            p.wait()
        state=read_json(RUN+'/state.json',{})
        if p is not None and state.get('pid')==p.pid:
            state['running']=False; save_json(RUN+'/state.json',state)


def autostart(enabled):
    expected=ROOT+'/native/startup.sh'
    if os.path.lexists(HOOK) and (not os.path.islink(HOOK) or os.readlink(HOOK)!=expected):
        raise RuntimeError('Startup hook belongs to another installation; refusing to overwrite')
    if enabled:
        if not os.path.isdir(os.path.dirname(HOOK)): os.makedirs(os.path.dirname(HOOK))
        os.chmod(expected,0o755)
        if not os.path.lexists(HOOK): os.symlink(expected,HOOK)
    elif os.path.islink(HOOK): os.unlink(HOOK)
    cfg=config(); cfg['autostart']=enabled; save_json(DATA+'/config.json',cfg)
    return status()


def main(action):
    prepare()
    if action=='supervise': supervise(); return None
    if action=='status': return status()
    # Serialize mutations without depending on the reduced Python threading library.
    import fcntl
    with open(RUN+'/control.lock','w') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
        if action=='start': return start()
        if action=='stop': return stop()
        if action=='restart': stop(); return start()
        if action=='boot': return start() if config().get('autostart') else status()
        if action.startswith('strategy-') and action[len('strategy-'):] in STRATEGIES:
            was_running=status()['running']; stop()
            cfg=config(); cfg['strategy']=action.split('-',1)[1]; save_json(DATA+'/config.json',cfg)
            return start() if was_running else status()
        if action=='autostart-on': return autostart(True)
        if action=='autostart-off': return autostart(False)
        raise RuntimeError('Unsupported action')


if __name__=='__main__':
    try:
        result=main(sys.argv[1] if len(sys.argv)==2 else 'status')
        if result is not None: print(json.dumps(result,sort_keys=True))
    except Exception as error:
        print(json.dumps({'returnValue':False,'errorText':str(error)})); sys.exit(1)
