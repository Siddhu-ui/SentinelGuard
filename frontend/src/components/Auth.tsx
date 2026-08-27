import React,{useState} from 'react';
import {ShieldCheck} from 'lucide-react';

export default function Auth({api,onAuth}:{api:(p:string,t:string,o?:RequestInit)=>Promise<any>; onAuth:(t:string)=>void}){
  const [register,setRegister]=useState(false);
  const [email,setEmail]=useState('');
  const [name,setName]=useState('');
  const [password,setPassword]=useState('');
  const [error,setError]=useState('');
  const [busy,setBusy]=useState(false);

  const submit=async(e:React.FormEvent)=>{
    e.preventDefault();
    setBusy(true);setError('');
    try{
      const apiUrl=(import.meta as any).env?.VITE_API_URL||'http://localhost:8000';
      const r=await fetch(`${apiUrl}/auth/${register?'register':'login'}`,{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(register?{email,display_name:name,password}:{email,password})
      });
      const j=await r.json();
      if(!r.ok)throw new Error(j.detail||'Authentication failed');
      onAuth(j.access_token);
    }catch(e:any){setError(e.message)}
    finally{setBusy(false)}
  };

  return (
    <main className="auth">
      <div className="auth-bg">
        <div className="grid-overlay"/>
        <div className="scanline"/>
      </div>
      <section className="auth-hero">
        <div className="brand brand-lg"><ShieldCheck/> SentinelGuard</div>
        <h1>{register?'Create your secure workspace':'File intelligence, before execution.'}</h1>
        <p>Static analysis for hidden content, polyglots, and suspicious file structures. Watch our virtual workstation dissect each byte in real time.</p>
        <ul className="features">
          <li><span className="dot"/> Signature &amp; magic-byte verification</li>
          <li><span className="dot"/> Entropy &amp; polyglot heuristics</li>
          <li><span className="dot"/> LSB steganography detection</li>
          <li><span className="dot"/> Explainable PDF security reports</li>
        </ul>
      </section>
      <form className="auth-card" onSubmit={submit}>
        <h2>{register?'Register':'Welcome back'}</h2>
        <p className="muted">{register?'Spin up your isolated analyst console.':'Sign in to continue your investigation.'}</p>
        {error&&<p className="error">{error}</p>}
        {register&&<input placeholder="Display name" value={name} onChange={e=>setName(e.target.value)} required minLength={2}/>}
        <input type="email" placeholder="Email address" value={email} onChange={e=>setEmail(e.target.value)} required/>
        <input type="password" placeholder="Password (10+ characters)" value={password} onChange={e=>setPassword(e.target.value)} required minLength={10}/>
        <button disabled={busy}>{busy?'Securing channel…':register?'Create account':'Sign in'}</button>
        <a className="switch" onClick={()=>setRegister(!register)}>
          {register?'Already have an account? Sign in':'New to SentinelGuard? Register'}
        </a>
      </form>
    </main>
  );
}
