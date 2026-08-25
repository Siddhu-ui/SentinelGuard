import React from 'react';
import {Scan} from './App';

export default function ScanTable({scans,open}:{scans:Scan[];open:(s:Scan)=>void}){
  if(!scans.length)return <div className="empty">No scans yet. Upload a file to begin.</div>;
  return (
    <div className="table">
      {scans.map(s=>(
        <button className="row" key={s.id} onClick={()=>open(s)}>
          <span>
            <b>{s.filename}</b>
            <small>{s.mime_type} · {(s.size/1024).toFixed(1)} KB</small>
          </span>
          <span className={'badge '+s.risk_level.toLowerCase()}>{s.risk_level} · {s.risk_score}</span>
          <small>{new Date(s.created_at).toLocaleString()}</small>
        </button>
      ))}
    </div>
  );
}
