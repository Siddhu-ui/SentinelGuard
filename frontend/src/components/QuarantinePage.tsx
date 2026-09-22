import React,{useCallback,useEffect,useState} from 'react';
import {ShieldAlert,Trash2,Undo2,AlertTriangle} from 'lucide-react';

type QuarantineItem={
  id:number; scan_id:number; filename:string; risk_score:number;
  risk_level:string; reason:string; created_at:string;
};

type Props={token:string; api:(p:string,t:string,o?:RequestInit)=>Promise<any>};

export default function QuarantinePage({token,api}:Props){
  const [items,setItems]=useState<QuarantineItem[]>([]);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState('');
  const [message,setMessage]=useState('');
  const [busy,setBusy]=useState(false);
  const [confirmItem,setConfirmItem]=useState<QuarantineItem>();

  const load=useCallback(async()=>{
    setLoading(true);setError('');
    try{setItems(await api('/quarantine',token))}
    catch(e:any){setError(e.message||'Unable to load quarantine.')}
    finally{setLoading(false)}
  },[api,token]);

  useEffect(()=>{load()},[load]);

  const flash=(m:string)=>{setMessage(m);setTimeout(()=>setMessage(''),2500)};

  const restore=async(item:QuarantineItem)=>{
    setBusy(true);setError('');
    try{
      await api(`/quarantine/${item.id}/restore`,token,{method:'POST'});
      await load();
      flash(`"${item.filename}" restored to scan history.`);
    }catch(e:any){setError(e.message||'Restore failed.')}
    finally{setBusy(false)}
  };

  const remove=async()=>{
    const target=confirmItem;
    if(!target)return;
    setBusy(true);setError('');
    setConfirmItem(undefined); // close immediately; retries must hit a fresh row
    try{
      await api(`/quarantine/${target.id}`,token,{method:'DELETE'});
      await load();
      flash('Quarantined file permanently deleted.');
    }catch(e:any){
      await load();
      setError(e.message||'Delete failed.');
    }
    finally{setBusy(false)}
  };

  return (
    <main className="feature-page">
      <header>
        <p className="eyebrow">QUARANTINE</p>
        <h1>Quarantined files</h1>
        <p className="muted">Suspicious files moved out of normal storage. They stay isolated here — never opened or executed — until you restore or permanently delete them.</p>
      </header>
      {message&&<p className="success-msg">{message}</p>}
      {error&&<p className="error">{error}</p>}

      {loading
        ?<p className="muted">Loading quarantine…</p>
        :items.length===0
          ?<div className="empty">Quarantine is empty.<br/><small>Use “Quarantine” on a scan result to isolate a suspicious file.</small></div>
          :<div className="table">
            {items.map(q=>(
              <div className="row quarantine-row" key={q.id}>
                <span>
                  <div className="row-main">
                    <b><AlertTriangle size={14} style={{display:'inline',marginRight:6,color:'#ff6b78'}}/>{q.filename}</b>
                    <small className="q-reason">{q.reason}</small>
                  </div>
                </span>
                <span className={'badge '+q.risk_level.toLowerCase()}>{q.risk_level} · {q.risk_score}</span>
                <small>{new Date(q.created_at).toLocaleString()}</small>
                <button className="ghost q-btn" onClick={()=>restore(q)} disabled={busy} title="Restore to scan storage"><Undo2 size={14}/> Restore</button>
                <button className="delete-scan" onClick={()=>setConfirmItem(q)} disabled={busy} title="Permanently delete"><Trash2 size={15}/></button>
              </div>
            ))}
          </div>}
      <p className="vault-note muted"><ShieldAlert size={14}/> Quarantined content is never executed and only reachable through Restore or Permanently Delete.</p>

      {confirmItem&&<div className="confirm-backdrop"><section className="confirm-modal">
        <h2>Permanently delete?</h2>
        <p>This will destroy <b>{confirmItem.filename}</b> and its quarantined copy. This cannot be undone.</p>
        {error&&<p className="error">{error}</p>}
        <div className="confirm-actions">
          <button className="ghost" onClick={()=>setConfirmItem(undefined)} disabled={busy}>Cancel</button>
          <button className="danger-btn" onClick={remove} disabled={busy}>{busy?'Deleting…':'Delete permanently'}</button>
        </div>
      </section></div>}
    </main>
  );
}
