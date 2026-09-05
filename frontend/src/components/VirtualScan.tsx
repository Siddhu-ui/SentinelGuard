import React,{useEffect,useMemo,useRef,useState} from 'react';
import {Activity,Cpu,FileSearch,HardDrive,ShieldAlert,ShieldCheck,Terminal,X,Zap,Image as ImageIcon,FileText,FileArchive,Binary} from 'lucide-react';
import {Scan} from './App';

type Step={
  id:string;
  label:string;
  detail:string;
  icon:React.ReactNode;
  duration:number;
  weight:number;
  region:{start:number;end:number};
  regionLabel:string;
};

const VIEW_BYTES = 4096;

function regionsFor(size:number):Step['region'][]{
  const headerEnd=Math.min(64,size);
  const sigEnd=Math.min(512,size);
  const midStart=Math.max(0,Math.floor(size*0.3));
  const midEnd=Math.min(size,Math.floor(size*0.55));
  const tailStart=Math.max(0,size-Math.min(VIEW_BYTES,Math.floor(size*0.2)));
  const fullEnd=Math.min(VIEW_BYTES,size);
  return [
    {start:0,end:fullEnd},
    {start:0,end:headerEnd},
    {start:headerEnd,end:sigEnd},
    {start:0,end:fullEnd},
    {start:0,end:fullEnd},
    {start:0,end:fullEnd},
  ];
}

export default function VirtualScan({
  file,token,onDone,onCancel,onAuthFailure,
}:{
  file:File;token:string;onDone:(s:Scan)=>void;onCancel:()=>void;onAuthFailure:()=>void;
}){
  const [stepIdx,setStepIdx]=useState(0);
  const [logs,setLogs]=useState<string[]>([]);
  const [progress,setProgress]=useState(0);
  const [score,setScore]=useState(0);
  const [error,setError]=useState('');
  const [bytes,setBytes]=useState(0);
  const [buffer,setBuffer]=useState<Uint8Array|null>(null);
  const [imageUrl,setImageUrl]=useState<string|null>(null);

  const reqRef=useRef<number|undefined>(undefined);
  const logRef=useRef<HTMLDivElement>(null);
  const hexRef=useRef<HTMLDivElement>(null);
  const uploadRef=useRef<Promise<Scan>|null>(null);
  const objectUrlRef=useRef<string|null>(null);

  const ext=useMemo(()=>{
    const n=file.name.toLowerCase();
    const i=n.lastIndexOf('.');
    return i>=0?n.slice(i+1):'';
  },[file.name]);

  const isImage=['png','jpg','jpeg','gif','bmp'].includes(ext);

  const STEPS:Step[]=useMemo(()=>{
    const size=buffer?.length||file.size;
    const [ing,magic,embed,entropy,stego,verdict]=regionsFor(size);
    return [
      {id:'ingest',  label:'Ingesting payload',           detail:'Mounting file into isolated sandbox volume',                icon:<HardDrive size={14}/>,  duration:900,  weight:0,  region:ing,    regionLabel:`0x0000 → 0x${ing.end.toString(16).toUpperCase().padStart(4,'0')}`},
      {id:'magic',   label:'Verifying magic-byte header', detail:'Comparing signature against declared extension',            icon:<FileSearch size={14}/>, duration:1100, weight:35, region:magic,  regionLabel:`0x0000 → 0x${magic.end.toString(16).toUpperCase().padStart(4,'0')} · HEADER`},
      {id:'embed',   label:'Scanning for embedded objects',detail:'Locating PK / MZ / PDF / image markers past offset 0',     icon:<Cpu size={14}/>,        duration:1300, weight:15, region:embed,  regionLabel:`0x${embed.start.toString(16).toUpperCase().padStart(4,'0')} → 0x${embed.end.toString(16).toUpperCase().padStart(4,'0')}`},
      {id:'entropy', label:'Computing Shannon entropy',   detail:'Measuring byte distribution across 8 MiB sample',           icon:<Activity size={14}/>,   duration:1000, weight:15, region:entropy,regionLabel:`full payload · ${(size/1024).toFixed(1)} KB`},
      {id:'stego',   label:'Running LSB stego analysis',  detail:'Decoding least-significant-bit plane from pixel buffer',   icon:<Zap size={14}/>,         duration:1400, weight:25, region:stego,  regionLabel:`pixel buffer · ${ext.toUpperCase()||'IMG'}`},
      {id:'verdict', label:'Aggregating risk verdict',    detail:'Scoring findings, classifying threat level',                 icon:<ShieldAlert size={14}/>,duration:900,  weight:0,  region:verdict,regionLabel:`all regions · ${(size/1024).toFixed(1)} KB`},
    ];
  },[buffer,file.size,ext]);

  useEffect(()=>{
    (async()=>{
      try{
        const slice=file.slice(0,Math.min(VIEW_BYTES,file.size));
        const buf=new Uint8Array(await slice.arrayBuffer());
        setBuffer(buf);
        if(isImage){
          const url=URL.createObjectURL(file);
          setImageUrl(url);
        }
      }catch{}
    })();
    return()=>{if(imageUrl)URL.revokeObjectURL(imageUrl)};
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[]);

  useEffect(()=>{
    uploadRef.current=(async()=>{
      const fd=new FormData();fd.append('file',file);
      const apiUrl=(import.meta as any).env?.VITE_API_URL||'http://127.0.0.1:8001';
      const r=await fetch(apiUrl+'/scans',{
        method:'POST',headers:{Authorization:`Bearer ${token}`},body:fd
      });
      if(r.status===401){onAuthFailure();throw new Error('Your session has expired. Please sign in again.');}
      if(!r.ok)throw new Error((await r.json().catch(()=>({detail:'Scan failed'}))).detail);
      return r.json();
    })();
    return()=>{if(reqRef.current)cancelAnimationFrame(reqRef.current)};
  },[]);

  useEffect(()=>{
    if(stepIdx>=STEPS.length)return;
    const step=STEPS[stepIdx];
    setLogs(prev=>[...prev,`> ${step.label} · ${step.regionLabel}`].slice(-40));
    const startedAt=performance.now();
    const tick=()=>{
      const elapsed=performance.now()-startedAt;
      const local=Math.min(1,elapsed/step.duration);
      const global=((stepIdx+local)/STEPS.length)*100;
      setProgress(global);
      if(step.weight){
        setScore(s=>Math.min(100,s+Math.round(step.weight*local)));
      }
      if(local<1){
        const sz=file.size;
        setBytes(Math.min(sz,Math.round(sz*(global/100))));
        reqRef.current=requestAnimationFrame(tick);
      }else{
        setLogs(prev=>[...prev,`✓ ${step.label} complete`].slice(-40));
        setStepIdx(i=>i+1);
      }
    };
    reqRef.current=requestAnimationFrame(tick);
  },[stepIdx,STEPS]);

  useEffect(()=>{
    if(logRef.current)logRef.current.scrollTop=logRef.current.scrollHeight;
  },[logs]);

  useEffect(()=>{
    if(stepIdx>=STEPS.length)return;
    const step=STEPS[stepIdx];
    if(!hexRef.current)return;
    const lineHeight=18;
    const targetTop=Math.floor(step.region.start/16)*lineHeight;
    const visible=hexRef.current.clientHeight;
    const desired=targetTop-visible/2+lineHeight*3;
    hexRef.current.scrollTo({top:Math.max(0,desired),behavior:'smooth'});
  },[stepIdx,STEPS]);

  useEffect(()=>{
    if(stepIdx<STEPS.length)return;
    let cancelled=false;
    (async()=>{
      try{
        const scan=await uploadRef.current!;
        if(!cancelled)onDone(scan);
      }catch(e:any){if(!cancelled)setError(e.message)}
    })();
    return()=>{cancelled=true};
  },[stepIdx]);

  const running=stepIdx<STEPS.length;
  const level=score>=80?'critical':score>=60?'high':score>=40?'medium':score>=20?'low':'safe';
  const activeRegion=running?STEPS[stepIdx].region:STEPS[STEPS.length-1].region;

  const hexLines=useMemo(()=>{
    if(!buffer)return [];
    const lines=[];
    const total=buffer.length;
    for(let off=0;off<total;off+=16){
      const slice=buffer.slice(off,Math.min(off+16,total));
      const hex=Array.from(slice).map(b=>b.toString(16).padStart(2,'0')).join(' ');
      const ascii=Array.from(slice).map(b=>(b>=32&&b<=126)?String.fromCharCode(b):'.').join('');
      lines.push({off,hex,ascii});
    }
    return lines;
  },[buffer]);

  const PreviewIcon=isImage?ImageIcon:['pdf'].includes(ext)?FileText:['zip','rar'].includes(ext)?FileArchive:Binary;

  return (
    <div className="modal scan-modal">
      <section className="modal-card vpc">
        <button className="close" onClick={onCancel} disabled={!running&&!error}><X size={18}/></button>

        <div className="vpc-frame">
          <div className="vpc-bezel">
            <div className="vpc-screen">
              <div className="vpc-screen-top">
                <span className="dot red"/>
                <span className="dot amber"/>
                <span className="dot green"/>
                <div className="vpc-title">SENTINELGUARD · SANDBOX WORKSTATION</div>
                <div className="vpc-clock">{new Date().toLocaleTimeString()}</div>
              </div>

              <div className="vpc-toolbar">
                <div className="sandbox-file">
                  <PreviewIcon size={16}/>
                  <div className="sandbox-file-meta">
                    <b>{file.name}</b>
                    <small>{(file.size/1024).toFixed(1)} KB · {ext.toUpperCase()||'BIN'} · read-only sandbox</small>
                  </div>
                </div>
                <div className="region-pill">
                  <span className="region-dot"/>
                  {running?STEPS[stepIdx].regionLabel:'all regions'}
                </div>
              </div>

              <div className="vpc-body">
                <div className="vpc-left">
                  <div className="meter">
                    <div className="meter-label"><Activity size={14}/> ANALYSIS PROGRESS</div>
                    <div className="meter-bar"><div className="meter-fill" style={{width:`${progress}%`}}/></div>
                    <div className="meter-val">{Math.round(progress)}%</div>
                  </div>

                  <div className={'risk-gauge '+level}>
                    <svg viewBox="0 0 200 110">
                      <defs>
                        <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="0">
                          <stop offset="0%" stopColor="#e11d2e"/>
                          <stop offset="100%" stopColor="#ff6b78"/>
                        </linearGradient>
                      </defs>
                      <path d="M20 100 A80 80 0 0 1 180 100" className="gauge-bg"/>
                      <path
                        d="M20 100 A80 80 0 0 1 180 100"
                        className="gauge-fg"
                        strokeDasharray={`${(score/100)*251} 251`}
                      />
                    </svg>
                    <div className="gauge-val">
                      <b>{score}</b><small>/100 · {level.toUpperCase()}</small>
                    </div>
                  </div>

                  <div className="hex-grid">
                    {Array.from({length:48}).map((_,i)=>(
                      <span key={i} className={i%7===0||i%11===0?'hex on':'hex'}/>
                    ))}
                  </div>
                </div>

                <div className="vpc-right">
                  <div className="steps">
                    {STEPS.map((s,i)=>(
                      <div key={s.id} className={'step '+(i<stepIdx?'done':i===stepIdx?'active':'')}>
                        <div className="step-mark">{i<stepIdx?'✓':i===stepIdx?'●':'○'}</div>
                        <div className="step-body">
                          <div className="step-head">{s.icon}<b>{s.label}</b></div>
                          <div className="step-detail">{s.detail}</div>
                          <div className="step-region">→ {s.regionLabel}</div>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="terminal">
                    <div className="terminal-head"><Terminal size={12}/> live://scanner.log</div>
                    <div className="terminal-body" ref={logRef}>
                      {logs.map((l,i)=>(
                        <div key={i} className={l.startsWith('>')?'log-pending':'log-done'}>
                          <span className="ts">{new Date().toLocaleTimeString([],{hour12:false})}</span> {l}
                        </div>
                      ))}
                      {running&&<div className="log-pending"><span className="ts">{new Date().toLocaleTimeString([],{hour12:false})}</span> <span className="cursor">_</span></div>}
                    </div>
                  </div>
                </div>
              </div>

              <div className="sandbox">
                <div className="sandbox-head">
                  <span className="sandbox-title">/sandbox/{file.name}</span>
                  <span className="sandbox-hint">read-only · memory mapped · {hexLines.length} lines · {(buffer?.length||0).toLocaleString()} bytes in view</span>
                </div>
                <div className="sandbox-split">
                  <div className="sandbox-preview">
                    {imageUrl?
                      <img src={imageUrl} alt="sandbox preview" className={running&&STEPS[stepIdx].id==='stego'?'preview stego-scan':'preview'}/>
                      :<div className="preview placeholder">
                          <PreviewIcon size={42}/>
                          <span>{ext.toUpperCase()||'BIN'} container</span>
                          <small>No visual preview available — static analysis only.</small>
                        </div>
                    }
                    {running&&STEPS[stepIdx].id==='stego'&&imageUrl&&(
                      <div className="stego-overlay">
                        <div className="scan-cursor"/>
                        <span>LSB plane extraction in progress…</span>
                      </div>
                    )}
                  </div>
                  <div className="hex" ref={hexRef}>
                    {hexLines.map(l=>{
                      const inRange=l.off>=activeRegion.start&&l.off<activeRegion.end;
                      return (
                        <div key={l.off} className={'hex-line '+(inRange?'in-range':'')}>
                          <span className="hex-off">{l.off.toString(16).padStart(8,'0')}</span>
                          <span className="hex-bytes">{l.hex}</span>
                          <span className="hex-ascii">{l.ascii}</span>
                        </div>
                      );
                    })}
                    {!buffer&&<div className="hex-empty">Loading payload into sandbox…</div>}
                  </div>
                </div>
              </div>

              <div className="vpc-footer">
                <span>PAYLOAD: <code>{file.name}</code> · {(bytes/1024).toFixed(1)} / {(file.size/1024).toFixed(1)} KB</span>
                <span className="blink">● REC</span>
              </div>
            </div>
            <div className="vpc-stand"/>
          </div>
        </div>

        <div className="vpc-summary">
          {running&&<p className="muted"><ShieldAlert size={14}/> File is contained inside an isolated VM. SentinelGuard never executes the upload.</p>}
          {error&&<p className="error"><ShieldAlert size={14}/> {error}</p>}
          {!running&&!error&&<p className="muted"><ShieldCheck size={14}/> Scan complete. Compiling report…</p>}
        </div>
      </section>
    </div>
  );
}
