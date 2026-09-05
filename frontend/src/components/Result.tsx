import React,{useState} from 'react';
import {AlertTriangle,Copy,Download,X} from 'lucide-react';
import {Scan} from './App';

export default function Result({scan,token,close}:{scan:Scan;token:string;close:()=>void}){
  const [downloading,setDownloading]=useState(false);
  const [copied,setCopied]=useState(false);

  const download=async()=>{
    setDownloading(true);
    try{
      const apiUrl=(import.meta as any).env?.VITE_API_URL||'http://127.0.0.1:8001';
      const r=await fetch(apiUrl+`/scans/${scan.id}/report.pdf`,{headers:{Authorization:`Bearer ${token}`}});
      const blob=await r.blob();
      const url=URL.createObjectURL(blob);
      const a=document.createElement('a');a.href=url;a.download=`sentinelguard-${scan.id}.pdf`;a.click();
      URL.revokeObjectURL(url);
    }finally{setDownloading(false)}
  };

  const copy=()=>{navigator.clipboard.writeText(scan.sha256);setCopied(true);setTimeout(()=>setCopied(false),1500)};

  return (
    <div className="modal">
      <section className="modal-card">
        <button className="close" onClick={close}><X size={18}/></button>
        <p className="eyebrow">SCAN REPORT</p>
        <h1>{scan.filename}</h1>

        <div className={'score '+scan.risk_level.toLowerCase()}>
          <div className="score-ring">
            <svg viewBox="0 0 120 120">
              <defs>
                <linearGradient id="scoreGrad" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#e11d2e"/>
                  <stop offset="100%" stopColor="#ff6b78"/>
                </linearGradient>
              </defs>
              <circle cx="60" cy="60" r="52" className="ring-bg"/>
              <circle cx="60" cy="60" r="52" className="ring-fg" style={{strokeDasharray:`${(scan.risk_score/100)*326.7} 326.7`}}/>
            </svg>
            <div className="score-num"><b>{scan.risk_score}</b><small>/100</small></div>
          </div>
          <div className="score-meta">
            <span className={'badge lg '+scan.risk_level.toLowerCase()}>{scan.risk_level} risk</span>
            <p className="muted">{scan.details?.recommendation}</p>
          </div>
        </div>

        <div className="details">
          <div className="detail">
            <b>SHA-256</b>
            <code>{scan.sha256}</code>
            <button className="iconbtn" onClick={copy} title="Copy"><Copy size={14}/>{copied?'Copied':'Copy'}</button>
          </div>
          <div className="detail"><b>Detected type</b><span>{scan.mime_type}</span></div>
          <div className="detail"><b>Entropy</b><span>{scan.entropy}/8 <em>({scan.details?.entropy_category})</em></span></div>
        </div>

        <h2>Findings</h2>
        {scan.threats?.length?
          scan.threats.map((t:any,i:number)=>(
            <div className="finding" key={i}>
              <AlertTriangle/>
              <span><b>{t.category}</b><br/>{t.message}</span>
              <em className={'sev '+t.severity}>{t.severity}</em>
            </div>
          ))
          :<div className="finding ok"><AlertTriangle/><span><b>Clean</b><br/>No suspicious indicators detected.</span></div>
        }

        {scan.details?.score_breakdown?.length > 0 && <div className="score-breakdown">
          <h2>Why this score</h2>
          {scan.details.score_breakdown.map((item:any, i:number) => <div className="breakdown-row" key={i}>
            <span><b>+{item.weight}</b> {item.category}</span><small>{item.evidence}</small>
          </div>)}
        </div>}

        <button className="primary" onClick={download} disabled={downloading}>
          <Download size={16}/> {downloading?'Rendering…':'Download PDF report'}
        </button>
      </section>
    </div>
  );
}
