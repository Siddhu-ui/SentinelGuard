import React,{useState} from 'react';
import {ScanLine} from 'lucide-react';
import {Scan} from './App';
import {EmptyState} from './VaultPage';

export default function ScanTable({scans,open,onDelete,emptyBody="Files you analyze will appear here with their risk score and findings. Start with Analyze file in the sidebar."}:{scans:Scan[];open:(s:Scan)=>void;onDelete?:(id:number)=>Promise<void>;emptyBody?:string}){
  const [pending,setPending]=useState<Scan>();
  const [error,setError]=useState('');
  const [busy,setBusy]=useState(false);
  if(!scans.length)return <EmptyState icon={<ScanLine size={30}/>} title="No scans yet" body={emptyBody}/>;
  const remove=async()=>{
    if(!pending||!onDelete)return;
    setBusy(true);setError('');
    try{await onDelete(pending.id);setPending(undefined)}catch(e:any){setError(e.message||'Unable to delete scan. Please try again.')}finally{setBusy(false)}
  };
  return (
    <>
    <div className="table">
      {scans.map(s=>(
        <div className="row" key={s.id}>
          <span>
            <button className="row-main" onClick={()=>open(s)}><b>{s.filename}</b>
            <small>{s.mime_type} · {(s.size/1024).toFixed(1)} KB</small>
            </button>
          </span>
          <span className={'badge '+s.risk_level.toLowerCase()}>{s.risk_level} · {s.risk_score}</span>
          <small>{new Date(s.created_at).toLocaleString()}</small>
          {onDelete&&<button className="delete-scan" onClick={()=>setPending(s)} aria-label={`Delete ${s.filename}`}>Delete</button>}
        </div>
      ))}
    </div>
    {pending&&<div className="confirm-backdrop"><section className="confirm-modal"><h2>Delete scan history?</h2><p>Are you sure you want to remove <b>{pending.filename}</b> from SentinelGuard history?</p><p className="muted">This removes the scan from your history. It does not change the scanner.</p>{error&&<p className="error">{error}</p>}<div className="confirm-actions"><button className="ghost" onClick={()=>{setPending(undefined);setError('')}} disabled={busy}>Cancel</button><button className="danger-btn" onClick={remove} disabled={busy}>{busy?'Deleting…':'Delete'}</button></div></section></div>}
    </>
  );
}
