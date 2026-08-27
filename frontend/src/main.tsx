import React,{useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import Auth from './components/Auth';
import App from './components/App';
import './style.css';

const API=import.meta.env.VITE_API_URL||'http://localhost:8000';

export async function api(path:string, token:string, opts:RequestInit={}){
  const r=await fetch(API+path,{...opts,headers:{Authorization:`Bearer ${token}`,...(opts.headers||{})}});
  if(!r.ok){
    let msg='Request failed';
    try{const j=await r.json();if(j&&j.detail)msg=typeof j.detail==='string'?j.detail:JSON.stringify(j.detail)}catch{}
    if(r.status===401)msg='Your session has expired. Please sign in again.';
    throw new Error(msg);
  }
  return r.headers.get('content-type')?.includes('json')?r.json():r;
}

function Root(){
  const [token,setToken]=useState(localStorage.token||'');
  const [checking,setChecking]=useState(!!token);

  useEffect(()=>{
    if(!token){setChecking(false);return}
    api('/auth/me',token).catch(()=>{
      localStorage.removeItem('token');
      setToken('');
    }).finally(()=>setChecking(false));
  },[token]);

  if(checking)return <main className="auth"><div className="auth-card"><p className="muted">Restoring secure session…</p></div></main>;
  if(!token)return <Auth api={api} onAuth={t=>{localStorage.token=t;setToken(t)}}/>;
  return <App token={token} api={api} signout={()=>{localStorage.removeItem('token');setToken('')}}/>;
}

createRoot(document.getElementById('root')!).render(<Root/>);
