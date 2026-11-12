import { useEffect, useMemo, useState } from "react";
import { Activity, Boxes, Braces, Cpu, FileSearch, FolderKanban, Gauge, Globe, HardDrive, Layers3, Menu, ShieldCheck, Smartphone, Terminal, UploadCloud, Workflow } from "lucide-react";

const API = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
type Health = { status: string; app: string; version: string };
type Inspection = { filename: string; size_bytes: number; sha256: string; detected_format: string; strings_preview: string[]; warnings: string[] };
const modules = [
  {name:"Static file analysis",detail:"Hashes, file signatures, printable strings",icon:FileSearch,state:"Available"},
  {name:"Web & JavaScript",detail:"Bundle and source inspection adapter",icon:Globe,state:"Planned"},
  {name:"Native binaries",detail:"PE, ELF and Mach-O metadata",icon:Cpu,state:"Starter"},
  {name:"Android packages",detail:"APK container and manifest metadata",icon:Smartphone,state:"Starter"},
  {name:"MCP agent bridge",detail:"Expose safe inspection tools to AI agents",icon:Workflow,state:"Available"},
  {name:"Evidence reports",detail:"Traceable findings and exports",icon:ShieldCheck,state:"Starter"}
];

export default function App() {
  const [health,setHealth]=useState<Health|null>(null);
  const [file,setFile]=useState<File|null>(null);
  const [result,setResult]=useState<Inspection|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [navOpen,setNavOpen]=useState(false);
  useEffect(()=>{fetch(`${API}/health`).then(r=>r.json()).then(setHealth).catch(()=>setHealth(null));},[]);
  const fileSize=useMemo(()=>file?`${(file.size/1024/1024).toFixed(2)} MB`:"No file selected",[file]);
  async function inspect(){
    if(!file)return;
    setBusy(true);setError("");setResult(null);
    try{
      const body=new FormData();body.append("file",file);
      const response=await fetch(`${API}/v1/analysis/static-file`,{method:"POST",body});
      if(!response.ok){const payload=await response.json();throw new Error(payload.detail??"Analysis failed");}
      setResult(await response.json());
    }catch(e){setError(e instanceof Error?e.message:"Could not reach local API.");}
    finally{setBusy(false);}
  }
  return <div className="shell">
    <aside className={`sidebar ${navOpen?"open":""}`}>
      <div className="brand"><div className="brand-mark"><Boxes size={21}/></div><div><b>REVSTUDIO</b><small>INTELLIGENCE WORKSPACE</small></div></div>
      <div className="workspace-label">WORKSPACE</div>
      <nav><a className="active"><Gauge size={17}/> Overview</a><a><FolderKanban size={17}/> Projects</a><a><FileSearch size={17}/> Analysis lab</a><a><Terminal size={17}/> Agent tools</a><a><Layers3 size={17}/> Integrations</a></nav>
      <div className="sidebar-bottom"><div className="secure"><ShieldCheck size={16}/><span><b>Local-first mode</b><small>Your files stay on your machine</small></span></div><small className="version">VERSION 0.1.0 · FOUNDATION</small></div>
    </aside>
    <main className="main">
      <header className="topbar"><button className="icon-btn mobile-menu" onClick={()=>setNavOpen(!navOpen)} aria-label="Toggle menu"><Menu/></button><div className="crumb">Workspace <span>/</span> Overview</div><div className="top-actions"><span className={`api-dot ${health?"online":""}`}></span><span className="api-label">{health?"API connected":"API offline"}</span><button className="avatar">RS</button></div></header>
      <section className="content">
        <div className="eyebrow"><Activity size={14}/> REVERSE ENGINEERING WORKSPACE</div>
        <div className="hero-row"><div><h1>Understand software.<br/><em>Trace every detail.</em></h1><p className="intro">A unified workspace for authorized software inspection, technical discovery, and evidence-backed analysis.</p></div><div className="hero-symbol"><Braces size={54}/><span></span></div></div>
        <div className="stats"><div className="stat"><span>ANALYSIS ENGINE</span><b>Ready</b><small><i className="green-dot"></i> Static inspection enabled</small></div><div className="stat"><span>AI CONNECTION</span><b>Not configured</b><small>Connect a local or cloud model later</small></div><div className="stat"><span>PROJECTS</span><b>01</b><small>Local workspace initialized</small></div></div>
        <div className="section-heading"><div><span className="eyebrow">GET STARTED</span><h2>Start an inspection</h2></div><span className="section-note">Files are analyzed as data — never executed.</span></div>
        <div className="inspect-card"><div className="upload-icon"><UploadCloud size={24}/></div><div className="upload-copy"><h3>Inspect a local file</h3><p>Choose a binary, APK, archive, database, or other file for safe static inspection.</p><small>{file?`${file.name} · ${fileSize}`:"Maximum upload size is configured by the local API."}</small></div><label className="file-button">Choose file<input type="file" onChange={e=>{setFile(e.target.files?.[0]??null);setResult(null);}}/></label><button className="primary" disabled={!file||busy} onClick={inspect}>{busy?"Inspecting…":"Analyze file"}</button></div>
        {error&&<div className="error">{error}</div>}
        {result&&<div className="result-card"><div className="result-head"><div><span className="eyebrow">INSPECTION RESULT</span><h3>{result.filename}</h3></div><span className="pill">{result.detected_format}</span></div><div className="result-grid"><div><small>SIZE</small><b>{(result.size_bytes/1024).toFixed(1)} KB</b></div><div><small>SHA-256</small><code>{result.sha256.slice(0,20)}…</code></div></div><h4>Printable string preview</h4><pre>{result.strings_preview.join("\n")||"No printable strings found."}</pre>{result.warnings.map(w=><p className="warning" key={w}>{w}</p>)}</div>}
        <div className="section-heading modules-heading"><div><span className="eyebrow">CAPABILITIES</span><h2>Analysis modules</h2></div><span className="section-note">Foundation and planned integrations</span></div>
        <div className="module-grid">{modules.map(m=><div className="module" key={m.name}><div className="module-icon"><m.icon size={19}/></div><div className="module-body"><h3>{m.name}</h3><p>{m.detail}</p></div><span className={`module-state ${m.state==="Available"?"ready":""}`}>{m.state}</span></div>)}</div>
        <footer><span>REVSTUDIO © 2026</span><span><HardDrive size={13}/> LOCAL-FIRST · EVIDENCE-DRIVEN</span></footer>
      </section>
    </main>
  </div>;
}
