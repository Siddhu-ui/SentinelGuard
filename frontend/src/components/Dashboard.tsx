import React from 'react';
import {AlertTriangle,ShieldCheck} from 'lucide-react';
import {Scan} from './App';
import ScanTable from './ScanTable';

export default function Dashboard({data,open,onDelete}:{data:any;open:(s:Scan)=>void;onDelete?:(id:number)=>Promise<void>}){
  if(!data)return <p className="muted">Loading dashboard…</p>;
  const total=data.total||0;
  const threats=data.threats||0;
  const safe=data.risk_levels?.Safe||0;
  const high=(data.risk_levels?.High||0)+(data.risk_levels?.Critical||0);

  return (
    <>
      <header>
        <p className="eyebrow">SECURITY OVERVIEW</p>
        <h1>Welcome back, analyst.</h1>
        <p className="muted">Your files are dissected by static, explainable heuristics inside an isolated virtual workstation.</p>
      </header>
      <div className="cards">
        <article className="card"><p>Files scanned</p><strong>{total}</strong></article>
        <article className="card danger"><p>Threats detected</p><strong>{threats}</strong></article>
        <article className="card ok"><p>Safe files</p><strong>{safe}</strong></article>
        <article className="card danger"><p>High risk</p><strong>{high}</strong></article>
      </div>

      <div className="risk-bar">
        {['Safe','Low','Medium','High','Critical'].map((lvl)=>{
          const v=data.risk_levels?.[lvl]||0;
          const pct=total?Math.round((v/total)*100):0;
          return (
            <div className="risk-seg" key={lvl}>
              <div className={'fill '+lvl.toLowerCase()} style={{width:`${pct}%`}}/>
              <div className="risk-label"><span>{lvl}</span><b>{v}</b></div>
            </div>
          );
        })}
      </div>

      <h2><ShieldCheck size={18}/> Recent scans</h2>
      <ScanTable scans={data.recent||[]} open={open} onDelete={onDelete}/>
    </>
  );
}
