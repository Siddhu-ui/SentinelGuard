import React,{useCallback,useEffect,useRef,useState} from 'react';
import {Lock,LockOpen,FileUp,Download,Trash2,ShieldCheck,AlertTriangle,Unlock,FolderLock} from 'lucide-react';

type VaultItem={
  id:number; original_filename:string; file_size:number; sha256:string;
  algorithm:string; kdf:string; created_at:string;
};

type Props={token:string; api:(p:string,t:string,o?:RequestInit)=>Promise<any>};

const SESSION_KEY='vault_session';
const API_BASE=(import.meta as any).env?.VITE_API_URL||'http://127.0.0.1:8001';

type StoredSession={vault_token:string; exp:number};

function loadSession():StoredSession|null{
  try{
    const raw=localStorage.getItem(SESSION_KEY);
    if(!raw)return null;
    const s=JSON.parse(raw) as StoredSession;
    if(!s.vault_token||!s.exp||s.exp<=Date.now()){localStorage.removeItem(SESSION_KEY);return null}
    return s;
  }catch{return null}
}

function saveSession(vault_token:string, expires_in:number){
  localStorage.setItem(SESSION_KEY,JSON.stringify({vault_token,exp:Date.now()+expires_in*1000}));
}

function formatSize(bytes:number){
  if(bytes<1024)return bytes+' B';
  if(bytes<1024*1024)return (bytes/1024).toFixed(1)+' KB';
  return (bytes/(1024*1024)).toFixed(2)+' MB';
}

export default function VaultPage({token,api}:Props){
  const [phase,setPhase]=useState<'loading'|'setup'|'locked'|'unlocked'>('loading');
  const [items,setItems]=useState<VaultItem[]>([]);
  const [vaultToken,setVaultToken]=useState<string>('');
  const [password,setPassword]=useState('');
  const [confirm,setConfirm]=useState('');
  const [showPw,setShowPw]=useState(false);
  const [error,setError]=useState('');
  const [message,setMessage]=useState('');
  const [busy,setBusy]=useState(false);
  const [file,setFile]=useState<File>();
  const inputRef=useRef<HTMLInputElement>(null);

  const loadItems=useCallback(async (vt:string)=>{
    try{
      const list=await api('/vault/items?vault_token='+encodeURIComponent(vt),token);
      setItems(list);setPhase('unlocked');
    }catch(e:any){
      localStorage.removeItem(SESSION_KEY);
      setPhase('locked');
    }
  },[api,token]);

  /* On mount: check vault existence; restore session if we have a live token. */
  useEffect(()=>{
    (async()=>{
      try{
        const status=await api('/vault/status',token);
        if(!status.exists){setPhase('setup');return}
        const s=loadSession();
        if(s){setVaultToken(s.vault_token);await loadItems(s.vault_token)}
        else setPhase('locked');
      }catch(e:any){
        setError(e.message||'Unable to reach the Vault.');setPhase('locked');
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[]);

  const flash=(m:string)=>{setMessage(m);setTimeout(()=>setMessage(''),2500)};

  const submitSetup=async(e:React.FormEvent)=>{
    e.preventDefault();setError('');
    if(password!==confirm){setError('Passwords do not match.');return}
    if(password.length<8||!/[A-Za-z]/.test(password)||!/\d/.test(password)){
      setError('Vault password must be 8+ characters and include letters and numbers.');return;
    }
    setBusy(true);
    try{
      const r=await api('/vault/setup',token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password,confirm})});
      saveSession(r.vault_token,r.expires_in);
      setVaultToken(r.vault_token);setPassword('');setConfirm('');
      await loadItems(r.vault_token);
      flash('Vault created. It locks again when you sign out or the session expires.');
    }catch(e:any){setError(e.message||'Vault setup failed.')}
    finally{setBusy(false)}
  };

  const submitUnlock=async(e:React.FormEvent)=>{
    e.preventDefault();setError('');
    setBusy(true);
    try{
      const r=await api('/vault/unlock',token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});
      saveSession(r.vault_token,r.expires_in);
      setVaultToken(r.vault_token);setPassword('');
      await loadItems(r.vault_token);
    }catch(e:any){setError(e.message||'Unlock failed.')}
    finally{setBusy(false)}
  };

  const lock=()=>{
    localStorage.removeItem(SESSION_KEY);
    setVaultToken('');setItems([]);setPassword('');setConfirm('');setError('');
    setPhase('locked');
  };

  const pick=()=>inputRef.current?.click();
  const onFile=(e:React.ChangeEvent<HTMLInputElement>)=>{const f=e.target.files?.[0];if(f)setFile(f)};

  const addItem=async()=>{
    if(!file)return;
    setBusy(true);setError('');
    try{
      const form=new FormData();
      form.append('file',file);
      form.append('vault_token',vaultToken);
      await api('/vault/items',token,{method:'POST',body:form});
      setFile(undefined);
      if(inputRef.current)inputRef.current.value='';
      await loadItems(vaultToken);
      flash('File encrypted and stored in the Vault.');
    }catch(e:any){
      setError(e.message||'Could not protect the file.');
      if(String(e.message).includes('locked'))lock();
    }finally{setBusy(false)}
  };

  const download=async(item:VaultItem)=>{
    setError('');
    try{
      const r=await fetch(API_BASE+`/vault/items/${item.id}/download?vault_token=`+encodeURIComponent(vaultToken),{
        headers:{Authorization:`Bearer ${token}`}});
      if(!r.ok){
        const j=await r.json().catch(()=>({detail:'Download failed'}));
        throw new Error(typeof j.detail==='string'?j.detail:'Download failed');
      }
      const blob=await r.blob();
      const url=URL.createObjectURL(blob);
      const a=document.createElement('a');a.href=url;a.download=item.original_filename;a.click();
      URL.revokeObjectURL(url);
    }catch(e:any){
      setError(e.message||'Download failed.');
      if(String(e.message).includes('locked'))lock();
    }
  };

  const remove=async(item:VaultItem)=>{
    setError('');
    if(!window.confirm(`Permanently delete "${item.original_filename}" from the Vault? This cannot be undone.`))return;
    try{
      await api(`/vault/items/${item.id}?vault_token=`+encodeURIComponent(vaultToken),token,{method:'DELETE'});
      await loadItems(vaultToken);
      flash('Vault item permanently deleted.');
    }catch(e:any){
      setError(e.message||'Delete failed.');
      if(String(e.message).includes('locked'))lock();
    }
  };

  if(phase==='loading')return <header><h1>Secure Vault</h1><p className="muted">Checking Vault status…</p></header>;

  /* ── First-time setup ── */
  if(phase==='setup')return (
    <main className="feature-page">
      <header>
        <p className="eyebrow">SECURE VAULT</p>
        <h1>Create your Vault</h1>
        <p className="muted">Choose a separate Vault password. It protects stored files with AES-256-GCM and is never stored in plain text — if you lose it, the files cannot be recovered.</p>
      </header>
      <form className="auth-card vault-card" onSubmit={submitSetup}>
        <label>Vault password</label>
        <div className="pw-row">
          <input type={showPw?'text':'password'} value={password} onChange={e=>setPassword(e.target.value)} placeholder="8+ characters, letters and numbers" autoComplete="new-password" required/>
          <button type="button" className="iconbtn" onClick={()=>setShowPw(s=>!s)}>{showPw?'Hide':'Show'}</button>
        </div>
        <label>Confirm Vault password</label>
        <input type={showPw?'text':'password'} value={confirm} onChange={e=>setConfirm(e.target.value)} autoComplete="new-password" required/>
        {error&&<p className="error">{error}</p>}
        <button className="primary" disabled={busy||!password||!confirm}><FolderLock size={16}/> {busy?'Creating…':'Create Vault'}</button>
      </form>
    </main>
  );

  /* ── Locked ── */
  if(phase==='locked')return (
    <main className="feature-page">
      <header>
        <p className="eyebrow">SECURE VAULT</p>
        <h1>Vault is locked</h1>
        <p className="muted">Enter your Vault password to unlock. Protected files stay encrypted and invisible until you do.</p>
      </header>
      <form className="auth-card vault-card" onSubmit={submitUnlock}>
        <label>Vault password</label>
        <div className="pw-row">
          <input type={showPw?'text':'password'} value={password} onChange={e=>setPassword(e.target.value)} autoComplete="current-password" required/>
          <button type="button" className="iconbtn" onClick={()=>setShowPw(s=>!s)}>{showPw?'Hide':'Show'}</button>
        </div>
        {error&&<p className="error">{error}</p>}
        <button className="primary" disabled={busy||!password}><Unlock size={16}/> {busy?'Verifying…':'Unlock Vault'}</button>
      </form>
    </main>
  );

  /* ── Unlocked ── */
  return (
    <main className="feature-page">
      <header>
        <p className="eyebrow">SECURE VAULT</p>
        <h1>Secure Vault</h1>
        <p className="muted">Files here are encrypted with AES-256-GCM under your Vault password. The Vault re-locks automatically when the session expires.</p>
      </header>
      {message&&<p className="success-msg">{message}</p>}
      {error&&<p className="error">{error}</p>}

      <div className="vault-actions">
        <div className="vault-add">
          <input ref={inputRef} type="file" className="file-input" onChange={onFile}/>
          <button className="ghost" onClick={pick} disabled={busy}><FileUp size={15}/> {file?file.name:'Choose file to protect'}</button>
          <button className="primary vault-add-btn" onClick={addItem} disabled={busy||!file}><Lock size={15}/> {busy?'Encrypting…':'Protect & store'}</button>
        </div>
        <button className="ghost danger-ghost" onClick={lock}><LockOpen size={15} style={{transform:'rotate(180deg)'}}/> Lock Vault now</button>
      </div>

      {items.length===0
        ?<div className="empty">Vault is empty.<br/><small>Protected files you add will appear here.</small></div>
        :<div className="table">
          {items.map(it=>(
            <div className="row" key={it.id}>
              <span>
                <button className="row-main" onClick={()=>download(it)} title="Decrypt & download">
                  <b>{it.original_filename}</b>
                  <small>{it.algorithm} · {it.kdf} · {formatSize(it.file_size)}</small>
                </button>
              </span>
              <span className={'badge safe'}>Protected</span>
              <small>{new Date(it.created_at).toLocaleString()}</small>
              <button className="delete-scan" onClick={()=>download(it)} aria-label={`Download ${it.original_filename}`}><Download size={15}/></button>
              <button className="delete-scan" onClick={()=>remove(it)} aria-label={`Delete ${it.original_filename}`}><Trash2 size={15}/></button>
            </div>
          ))}
        </div>}
      <p className="vault-note muted"><ShieldCheck size={14}/> The Vault password never leaves your session unencrypted and is never stored. Files are decrypted only while the Vault is unlocked.</p>
      {false&&<AlertTriangle/>}
    </main>
  );
}
