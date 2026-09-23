import React from 'react';
import {AlertTriangle,ShieldCheck,Lock,Vault,ChevronRight,ScanLine,Database,Cpu,KeyRound} from 'lucide-react';
import {Scan} from './App';
import ScanTable from './ScanTable';

type Tab='dashboard'|'upload'|'history'|'encrypt'|'decrypt'|'encrypt-history'|'vault'|'quarantine';

export default function Dashboard({data,open,onDelete,onNavigate}:{data:any;open:(s:Scan)=>void;onDelete?:(id:number)=>Promise<void>;onNavigate?:(t:Tab)=>void}){
  if(!data)return <p className="muted">Loading security center…</p>;
  const total=data.total||0;
  const threats=data.threats||0;
  const safe=data.risk_levels?.Safe||0;
  const low=(data.risk_levels?.Low||0);
  const medium=(data.risk_levels?.Medium||0);
  const high=(data.risk_levels?.High||0)+(data.risk_levels?.Critical||0);

  const stats=[
    {label:'Files scanned',value:total,tone:'neutral'},
    {label:'Threats detected',value:threats,tone:threats?'danger':'neutral'},
    {label:'Safe files',value:safe+low,tone:(safe+low)?'ok':'neutral'},
    {label:'High risk',value:high,tone:high?'danger':'neutral'},
  ];

  const actions:{icon:React.ReactNode;title:string;desc:string;tab:Tab}[]=[
    {icon:<ScanLine size={20}/>,title:'Scan a file',desc:'Run a full static analysis on any document',tab:'upload'},
    {icon:<Lock size={20}/>,title:'Protect a file',desc:'Encrypt any file with AES-256-GCM',tab:'encrypt'},
    {icon:<Vault size={20}/>,title:'Open Secure Vault',desc:'Store files under your Vault password',tab:'vault'},
  ];

  const systems=[
    {icon:<Cpu size={15}/>,label:'Scanner'},
    {icon:<ScanLine size={15}/>,label:'Analyzer'},
    {icon:<Database size={15}/>,label:'Database'},
    {icon:<KeyRound size={15}/>,label:'Encryption'},
  ];

  return (
    <>
      <header>
        <p className="eyebrow">SECURITY OVERVIEW</p>
        <h1>Welcome back, analyst.</h1>
        <p className="muted">Your files are dissected by static, explainable heuristics inside an isolated virtual workstation.</p>
      </header>

      <div className="stat-grid">
        {stats.map(s=>(
          <article className={`stat-card ${s.tone}`} key={s.label}>
            <p>{s.label}</p>
            <strong>{s.value}</strong>
          </article>
        ))}
      </div>

      <section className="dash-section">
        <h2>Quick actions</h2>
        <div className="qa-grid">
          {actions.map(a=>(
            <button className="qa-card" key={a.title} onClick={()=>onNavigate?.(a.tab)}>
              <span className="qa-icon">{a.icon}</span>
              <span className="qa-copy">
                <b>{a.title}</b>
                <small>{a.desc}</small>
              </span>
              <ChevronRight size={16} className="qa-arrow"/>
            </button>
          ))}
        </div>
      </section>

      <section className="dash-section">
        <h2><ShieldCheck size={16}/> Recent scans</h2>
        <ScanTable scans={data.recent||[]} open={open} onDelete={onDelete}/>
      </section>

      <section className="dash-section">
        <h2><AlertTriangle size={16}/> Security status</h2>
        <div className="status-panel">
          <div className="status-strip">
            <div className="status-engine"><span className="pulse"/><b>Engine online</b></div>
            {systems.map(s=>(
              <div className="status-item" key={s.label}>
                {s.icon}
                <span>{s.label}</span>
                <em className="status-online">Online</em>
              </div>
            ))}
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
          <p className="status-foot muted">Risk distribution across {total} scan{total===1?'':'s'} · medium findings ({medium}) warrant review, high/critical ({high}) require action.</p>
        </div>
      </section>
    </>
  );
}
