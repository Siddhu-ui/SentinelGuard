import React,{useCallback,useEffect,useMemo,useRef,useState} from 'react';
import {FileUp,UploadCloud,FileText,FileArchive,Binary,Image as ImageIcon,File,CheckCircle2,XCircle,AlertTriangle,ShieldCheck} from 'lucide-react';
import * as pdfjsLib from 'pdfjs-dist';

pdfjsLib.GlobalWorkerOptions.workerSrc=new URL('pdfjs-dist/build/pdf.worker.min.mjs',import.meta.url).toString();

/* ── Must match backend's ALLOWED set + max_upload_mb ── */
const ALLOWED_EXTS=new Set([
  'pdf','png','jpg','jpeg','gif','bmp',
  'zip','rar','docx','xlsx','pptx','exe',
]);
const ACCEPT_STR=[...ALLOWED_EXTS].map(e=>'.'+e).join(',');
const MAX_SIZE_MB=100;

const IMAGE_EXTS=['png','jpg','jpeg','gif','bmp','webp','svg'];
const PDF_EXTS=['pdf'];
const ARCHIVE_EXTS=['zip','rar','7z','tar','gz'];

function extOf(name:string){
  const n=name.toLowerCase();
  const i=n.lastIndexOf('.');
  return i>=0?n.slice(i+1):'';
}

function formatSize(bytes:number){
  if(bytes<1024) return bytes+' B';
  if(bytes<1024*1024) return (bytes/1024).toFixed(1)+' KB';
  return (bytes/(1024*1024)).toFixed(2)+' MB';
}

type ValidationResult={ok:boolean;label:string;detail:string};

function validateFile(file:File):ValidationResult[]{
  const ext=extOf(file.name);
  const typeOk=ALLOWED_EXTS.has(ext);
  const sizeOk=file.size<=MAX_SIZE_MB*1024*1024;
  return[
    {
      ok:typeOk,
      label:'File type',
      detail:typeOk
        ?`.${ext.toUpperCase()} — supported`
        :`.${ext.toUpperCase()||'?'} — not supported`,
    },
    {
      ok:sizeOk,
      label:'Size limit',
      detail:sizeOk
        ?`${formatSize(file.size)} — OK`
        :`${formatSize(file.size)} exceeds ${MAX_SIZE_MB} MB`,
    },
  ];
}

function toastMessages(results:ValidationResult[]):string[]{
  const msgs:string[]=[];
  for(const r of results){
    if(!r.ok) msgs.push(r.detail);
  }
  return msgs;
}

async function renderPdfFirstPage(
  file:File,
  onProgress:(pct:number)=>void,
):Promise<string|null>{
  try{
    onProgress(5);
    const data=await file.arrayBuffer();
    onProgress(20);
    const doc=await pdfjsLib.getDocument({data}).promise;
    onProgress(40);
    const page=await doc.getPage(1);
    onProgress(55);
    const vp=page.getViewport({scale:1.5});
    onProgress(65);
    const canvas=document.createElement('canvas');
    canvas.width=vp.width;
    canvas.height=vp.height;
    let pct=65;
    const iv=setInterval(()=>{pct=Math.min(pct+6,92);onProgress(pct)},80);
    await page.render({canvas,viewport:vp}).promise;
    clearInterval(iv);
    onProgress(96);
    const result=canvas.toDataURL('image/png');
    onProgress(100);
    return result;
  }catch{
    return null;
  }
}

export default function Upload({onStart}:{onStart:(f:File)=>void}){
  const [file,setFile]=useState<File>();
  const [drag,setDrag]=useState(false);
  const [pdfImg,setPdfImg]=useState<string|null>(null);
  const [pdfLoading,setPdfLoading]=useState(false);
  const [pdfProgress,setPdfProgress]=useState(0);
  const [animating,setAnimating]=useState(false);
  const [toastMsgs,setToastMsgs]=useState<string[]>([]);
  const [toastKey,setToastKey]=useState(0);
  const toastTimer=useRef<ReturnType<typeof setTimeout>>(undefined);
  const inputRef=useRef<HTMLInputElement>(null);
  const previewUrl=useMemo(()=>file?URL.createObjectURL(file):null,[file]);
  const prevFileRef=useRef<File|undefined>(undefined);

  useEffect(()=>()=>{if(previewUrl)URL.revokeObjectURL(previewUrl)},[previewUrl]);

  /* ── Show toast when a new file fails validation ── */
  useEffect(()=>{
    const changed=file!==prevFileRef.current;
    prevFileRef.current=file;
    if(!changed||!file)return;

    const results=validateFile(file);
    const fails=toastMessages(results);
    if(fails.length>0){
      // Clear any pending timer, then show fresh toast
      if(toastTimer.current) clearTimeout(toastTimer.current);
      setToastMsgs(fails);
      setToastKey(k=>k+1);
      toastTimer.current=setTimeout(()=>setToastMsgs([]),4500);
    }
    return()=>{if(toastTimer.current)clearTimeout(toastTimer.current)};
  },[file]);

  /* ── Render PDF first page ── */
  useEffect(()=>{
    if(!file){setPdfImg(null);setPdfLoading(false);return}
    const ext=extOf(file.name);
    if(!PDF_EXTS.includes(ext)){setPdfImg(null);setPdfLoading(false);return}
    let cancelled=false;
    setPdfLoading(true);setPdfImg(null);setPdfProgress(0);
    renderPdfFirstPage(file,pct=>{if(!cancelled)setPdfProgress(pct)}).then(img=>{
      if(!cancelled){setPdfProgress(100);setPdfImg(img);setPdfLoading(false)}
    });
    return()=>{cancelled=true};
  },[file]);

  /* ── Validation (derived) ── */
  const validations=useMemo(()=>file?validateFile(file):[],[file]);
  const allValid=validations.length>0&&validations.every(v=>v.ok);

  /* ── Handlers ── */
  const pick=()=>inputRef.current?.click();
  const onDrop=(e:React.DragEvent)=>{
    e.preventDefault();setDrag(false);
    const f=e.dataTransfer.files?.[0];
    if(f)setFile(f);
  };
  const onChange=(e:React.ChangeEvent<HTMLInputElement>)=>{
    const f=e.target.files?.[0];
    if(f)setFile(f);
  };
  const handleStart=()=>{
    if(!file||!allValid)return;
    setAnimating(true);
    setTimeout(()=>onStart(file),350);
  };
  const dismissToast=()=>{setToastMsgs([]);if(toastTimer.current)clearTimeout(toastTimer.current)};

  const ext=file?extOf(file.name):'';
  const isImage=file&&IMAGE_EXTS.includes(ext);
  const isPdf=file&&PDF_EXTS.includes(ext);

  const FileIcon=isImage?ImageIcon:
    isPdf?FileText:
    ARCHIVE_EXTS.includes(ext)?FileArchive:
    File;

  /* ── Preview renderers ── */
  const renderPreview=useCallback(()=>{
    if(!file)return null;

    if(isPdf){
      return(
        <div className="file-preview-wrap">
          <div className="file-preview-pdf">
            {pdfLoading&&(
              <div className="pdf-rendering">
                <div className="pdf-progress-track">
                  <div className="pdf-progress-fill" style={{width:pdfProgress+'%'}}/>
                </div>
                <div className="pdf-progress-text">
                  <FileText size={16}/>
                  <span>Rendering page 1… {pdfProgress}%</span>
                </div>
              </div>
            )}
            {pdfImg&&<img src={pdfImg} alt="PDF first page" className="file-preview-img pdf-page"/>}
            {!pdfLoading&&!pdfImg&&(
              <div className="file-preview-card">
                <FileText size={48}/>
                <b>{file.name}</b>
                <small>PDF · {formatSize(file.size)}</small>
              </div>
            )}
          </div>
          <div className="file-preview-label">
            <span>{file.name}</span>
            <small>{formatSize(file.size)} · PDF</small>
          </div>
        </div>
      );
    }

    if(isImage&&previewUrl){
      return(
        <div className="file-preview-wrap">
          <img src={previewUrl} alt={file.name} className="file-preview-img"/>
          <div className="file-preview-label">
            <span>{file.name}</span>
            <small>{formatSize(file.size)} · {ext.toUpperCase()}</small>
          </div>
        </div>
      );
    }

    return(
      <div className="file-preview-wrap">
        <div className="file-preview-card">
          <FileIcon size={48}/>
          <b>{file.name}</b>
          <small>{formatSize(file.size)} · {ext.toUpperCase()||'Unknown type'}</small>
        </div>
      </div>
    );
  },[file,isImage,isPdf,previewUrl,pdfImg,pdfLoading,pdfProgress,ext,FileIcon]);

  /* ── Validation indicator row ── */
  const renderValidation=()=>{
    if(!file||validations.length===0)return null;
    return(
      <div className="validation-bar">
        {validations.map((v,i)=>(
          <div key={i} className={'validation-item '+(v.ok?'ok':'fail')}>
            {v.ok?<CheckCircle2 size={14}/>:<XCircle size={14}/>}
            <span className="validation-label">{v.label}</span>
            <span className="validation-detail">{v.detail}</span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <>
      {/* ── Toast notification ── */}
      {toastMsgs.length>0&&(
        <div key={toastKey} className="toast-wrap" onClick={dismissToast}>
          <div className="toast-card">
            <div className="toast-icon"><AlertTriangle size={18}/></div>
            <div className="toast-body">
              <b>File rejected</b>
              {toastMsgs.map((m,i)=>(
                <span key={i} className="toast-msg">{m}</span>
              ))}
            </div>
            <button className="toast-close" onClick={dismissToast}>×</button>
          </div>
        </div>
      )}

      <header>
        <p className="eyebrow">NEW ANALYSIS</p>
        <h1>Inspect a file safely</h1>
        <p className="muted">Files are stored privately in an isolated vault and never executed by SentinelGuard.</p>
      </header>
      <div
        className={'drop '+(drag?'drag':'')+(file?' has-file':'')+(animating?' valid-flash':'')}
        onDragOver={e=>{e.preventDefault();setDrag(true)}}
        onDragEnter={e=>{e.preventDefault();setDrag(true)}}
        onDragLeave={e=>{e.preventDefault();setDrag(false)}}
        onDrop={onDrop}
      >
        {drag&&<div className="drag-scanline"/>}
        <div className="drop-inner" onClick={pick} role="button" tabIndex={0}
             onKeyDown={e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick()}}}>
          {file?renderPreview():(
            <>
              <div className={'drag-icon '+(drag?'bouncing':'')}><UploadCloud size={56}/></div>
              <h2>{drag?'Release to upload':'Drop a file here or click to browse'}</h2>
              <p>PDF · images · archives · Office documents · EXE &nbsp;·&nbsp; maximum 100 MB</p>
            </>
          )}
          <input
            ref={inputRef}
            type="file"
            className="file-input"
            accept={ACCEPT_STR}
            onChange={onChange}
            onClick={e=>e.stopPropagation()}
          />
        </div>

        {renderValidation()}

        {!isImage&&!isPdf&&file&&(
          <div className="file-meta">
            <span>{formatSize(file.size)}</span>
            <span>·</span>
            <span>{file.type||'unknown'}</span>
          </div>
        )}
        <div className="drop-actions">
          {file&&<button type="button" className="ghost" onClick={()=>setFile(undefined)}>Choose different file</button>}
          {allValid&&file&&(
            <span className="valid-badge"><ShieldCheck size={14}/> Ready to scan</span>
          )}
          {!allValid&&file&&(
            <span className="invalid-badge"><AlertTriangle size={14}/> Fix issues above</span>
          )}
          <button type="button" disabled={!file||!allValid} onClick={handleStart}>
            <FileUp size={16}/> Start security analysis
          </button>
        </div>
      </div>
    </>
  );
}
