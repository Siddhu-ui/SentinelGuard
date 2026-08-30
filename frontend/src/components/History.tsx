import React,{useEffect,useState} from 'react';
import {Search,Trash2} from 'lucide-react';
import {Scan} from './App';
import ScanTable from './ScanTable';

export default function HistoryPage({token,open,onAuthFailure}:{token:string;open:(s:Scan)=>void;onAuthFailure:()=>void}){
  const [scans,setScans]=useState<Scan[]>([]);
  const [q,setQ]=useState('');
  const [clearOpen,setClearOpen]=useState(false); const [message,setMessage]=useState(''); const [busy,setBusy]=useState(false);

  const load=async()=>{
    const apiUrl=(import.meta as any).env?.VITE_API_URL||'http://127.0.0.1:8001';
    const r=await fetch(apiUrl+'/scans?q='+encodeURIComponent(q),{headers:{Authorization:`Bearer ${token}`}});
    if(r.status===401){onAuthFailure();return}
    if(r.ok)setScans(await r.json());
  };
  const deleteScan=async(id:number)=>{const apiUrl=(import.meta as any).env?.VITE_API_URL||'http://127.0.0.1:8001';const r=await fetch(apiUrl+'/scans/'+id,{method:'DELETE',headers:{Authorization:`Bearer ${token}`}});if(r.status===401){onAuthFailure();throw new Error('Your session has expired. Please sign in again.')}if(!r.ok)throw new Error('Unable to delete scan. Please try again.');setScans(xs=>xs.filter(x=>x.id!==id));setMessage('Scan removed from history.');setTimeout(()=>setMessage(''),2500)};
  const clearAll=async()=>{setBusy(true);const apiUrl=(import.meta as any).env?.VITE_API_URL||'http://127.0.0.1:8001';try{const r=await fetch(apiUrl+'/scans',{method:'DELETE',headers:{Authorization:`Bearer ${token}`}});if(r.status===401){onAuthFailure();throw new Error('Your session has expired. Please sign in again.')}if(!r.ok)throw new Error('Unable to clear scan history. Please try again.');setScans([]);setClearOpen(false);setMessage('Scan history cleared.');setTimeout(()=>setMessage(''),2500)}finally{setBusy(false)}};
  useEffect(()=>{const t=setTimeout(load,200);return()=>clearTimeout(t)},[q]);

  return (
    <>
      <header>
        <p className="eyebrow">SCAN HISTORY</p>
        <h1>Past analyses</h1>
        <p className="muted">Search, reopen, or export any prior scan report.</p>
      </header>
      <div className="history-actions"><button className="ghost danger-ghost" onClick={()=>setClearOpen(true)} disabled={!scans.length}><Trash2 size={15}/> Clear history</button>{message&&<span className="success-msg">{message}</span>}</div>
      <div className="search-wrap">
        <Search size={16}/>
        <input className="search" placeholder="Search filename…" value={q} onChange={e=>setQ(e.target.value)}/>
      </div>
      <ScanTable scans={scans} open={open} onDelete={deleteScan}/>
      {clearOpen&&<div className="confirm-backdrop"><section className="confirm-modal"><h2>Clear scan history?</h2><p>This will permanently remove all of your scan records from SentinelGuard history.</p><p className="muted">Encryption and decryption history will not be affected.</p><div className="confirm-actions"><button className="ghost" onClick={()=>setClearOpen(false)} disabled={busy}>Cancel</button><button className="danger-btn" onClick={clearAll} disabled={busy}>{busy?'Clearing…':'Clear history'}</button></div></section></div>}
    </>
  );
}
