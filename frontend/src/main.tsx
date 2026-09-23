import React,{useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import Auth from './components/Auth';
import App from './components/App';
import Landing from './components/Landing';
import './style.css';

// API base: VITE_API_URL wins; in dev fall back to the local backend, in a
// production build default to same-origin (backend serves the built frontend).
const API=import.meta.env.VITE_API_URL||(import.meta.env.DEV?'http://127.0.0.1:8001':'');

export async function api(path:string, token:string, opts:RequestInit={}){
  const r=await fetch(API+path,{...opts,headers:{Authorization:`Bearer ${token}`,...(opts.headers||{})}});
  if(!r.ok){
    let msg='Request failed';
    try{const j=await r.json();if(j&&j.detail)msg=typeof j.detail==='string'?j.detail:JSON.stringify(j.detail)}catch{}
    if(r.status===401)msg='Your session has expired. Please sign in again.';
    throw new Error(msg);
  }
  if(r.status===204)return null; // empty body: never attempt a JSON parse
  const isJson=r.headers.get('content-type')?.includes('json');
  if(isJson){const text=await r.text();return text?JSON.parse(text):null}
  return r;
}

function Root(){
  const [token,setToken]=useState(localStorage.token||'');
  const [authMode,setAuthMode]=useState<'login'|'register'|null>(null);
  const [checking,setChecking]=useState(!!token);

  useEffect(()=>{
    if(!token){setChecking(false);return}
    api('/auth/me',token).catch(()=>{
      localStorage.removeItem('token');
      setToken('');
    }).finally(()=>setChecking(false));
  },[token]);

  if(checking)return <main className="auth"><div className="auth-card"><p className="muted">Restoring secure session…</p></div></main>;
  if(!token&&!authMode)return <Landing onSignIn={()=>setAuthMode('login')} onRegister={()=>setAuthMode('register')}/>;
  if(!token)return <Auth api={api} initialRegister={authMode==='register'} onBack={()=>setAuthMode(null)} onAuth={t=>{localStorage.token=t;setToken(t);setAuthMode(null)}}/>;
  return <App token={token} api={api} signout={()=>{localStorage.removeItem('token');setToken('')}}/>;
}

createRoot(document.getElementById('root')!).render(<Root/>);
