import React,{useEffect,useState} from 'react';
import {Search} from 'lucide-react';
import {Scan} from './App';
import ScanTable from './ScanTable';

export default function HistoryPage({token,open}:{token:string;open:(s:Scan)=>void}){
  const [scans,setScans]=useState<Scan[]>([]);
  const [q,setQ]=useState('');

  const load=async()=>{
    const r=await fetch((import.meta as any).env?.VITE_API_URL||'http://localhost:8000'+'/scans?q='+encodeURIComponent(q),{headers:{Authorization:`Bearer ${token}`}});
    if(r.ok)setScans(await r.json());
  };
  useEffect(()=>{const t=setTimeout(load,200);return()=>clearTimeout(t)},[q]);

  return (
    <>
      <header>
        <p className="eyebrow">SCAN HISTORY</p>
        <h1>Past analyses</h1>
        <p className="muted">Search, reopen, or export any prior scan report.</p>
      </header>
      <div className="search-wrap">
        <Search size={16}/>
        <input className="search" placeholder="Search filename…" value={q} onChange={e=>setQ(e.target.value)}/>
      </div>
      <ScanTable scans={scans} open={open}/>
    </>
  );
}
