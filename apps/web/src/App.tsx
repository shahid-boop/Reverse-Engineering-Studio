import { useEffect, useMemo, useState } from "react";
import {
  Activity, Boxes, Braces, Check, Code2, Copy, Cpu, Download, FileCode, FileSearch,
  FileText, FolderKanban, Gauge, Globe, HardDrive, Info, Layers3, Menu, Package, Plus,
  ShieldCheck, Smartphone, Terminal, UploadCloud, Workflow,
} from "lucide-react";

const API = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

type Page = "overview" | "lab" | "code" | "report" | "projects" | "agents";
type Health = { status: string; app: string; version: string };
type Item = { name: string; line: number };

type PeSection = {
  name: string; virtual_address: number; virtual_size: number; raw_size: number;
  entropy: number; characteristics: string[];
};
type PeInfo = {
  machine: string; bits: number; subsystem: string; compile_time: string | null;
  entry_point_rva: number; entry_point_section: string | null; image_base: number;
  is_dll: boolean; is_dotnet: boolean; clr_runtime_version: string | null;
  authenticode_signed: boolean; overlay_size: number; packing_suspected: boolean;
  packing_reasons: string[]; sections: PeSection[];
  imports: { dll: string; function_count: number; functions: string[] }[];
  exports: { name: string; ordinal: number }[]; resource_counts: Record<string, number>;
  resources: { type: string; path: string[]; size: number }[];
  version_info: Record<string, string>;
  debug: { type: string; pdb?: string }[];
};
type ApkInfo = {
  package: string | null; version_name: string | null; version_code: string | null;
  min_sdk: string | null; target_sdk: string | null; application_label: string | null;
  launchable_activity: string | null; permissions: string[]; features: string[];
  activities: string[]; services: string[]; receivers: string[]; providers: string[];
  manifest_xml: string | null; manifest_error: string | null;
  dex: {
    name: string; counts?: Record<string, number>; classes?: {
      name: string; superclass: string | null; access: string;
      methods: { name: string; proto: string; access: string; kind: string }[];
    }[];
  }[];
  entries: { name: string; size: number; method: string }[];
  entries_count: number; assets: { name: string; size: number }[];
  native_libs: { name: string; size: number }[]; signatures: string[];
};
type DeepResult = {
  filename: string; size_bytes: number; sha256: string; format: string;
  warnings: string[]; pe?: PeInfo; apk?: ApkInfo; detected_format?: string;
  strings_preview?: string[]; deep_supported?: boolean; note?: string;
};
type WebResult = {
  filename: string; language: string; size_bytes: number; sha256: string; line_count: number;
  imports: Item[]; functions: Item[]; classes: Item[]; exports: Item[]; urls: Item[];
  api_endpoints: Item[]; secret_findings: { type: string; line: number; value_redacted: string }[];
  suspicious_patterns: { type: string; line: number }[]; warnings: string[];
};
type Target = { id: string; label: string; kind: string };
type CodeResult = {
  view: string; filename: string; target: string | null; content: string;
  line_count: number; truncated: boolean; meta: Record<string, any>; warnings: string[];
};
type Project = { id: string; name: string; created_at: string };

type Finding = {
  id: string; severity: "critical" | "high" | "medium" | "low" | "info";
  category: string; title: string; evidence: string[]; recommendation: string;
};
type EvidenceReport = {
  report_id: string; schema: string; generated_at: string;
  subject: { filename: string; size_bytes: number; sha256: string; format: string; kind: string };
  risk: { score: number; level: string; counts: Record<string, number> };
  findings: Finding[]; summary: string; limitations: string[];
  markdown?: string; html?: string;
};

const NAV: { id: Page; label: string; icon: typeof Gauge }[] = [
  { id: "overview", label: "Overview", icon: Gauge },
  { id: "lab", label: "Analysis lab", icon: FileSearch },
  { id: "code", label: "Code viewer", icon: Code2 },
  { id: "report", label: "Evidence report", icon: FileText },
  { id: "projects", label: "Projects", icon: FolderKanban },
  { id: "agents", label: "Agent tools", icon: Workflow },
];

function fmtBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(2)} MB`;
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const area = document.createElement("textarea");
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
      return true;
    } catch {
      return false;
    }
  }
}

function downloadText(filename: string, content: string, mime = "text/plain;charset=utf-8"): void {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="tool-btn"
      onClick={async () => {
        if (await copyText(text)) {
          setCopied(true);
          setTimeout(() => setCopied(false), 1600);
        }
      }}
    >
      {copied ? <Check size={13} /> : <Copy size={13} />} {copied ? "Copied!" : label}
    </button>
  );
}

function DownloadButton({ filename, content, mime, label = "Download" }: {
  filename: string; content: string; mime?: string; label?: string;
}) {
  return (
    <button className="tool-btn" onClick={() => downloadText(filename, content, mime)}>
      <Download size={13} /> {label}
    </button>
  );
}

function CodeBody({ content }: { content: string }) {
  const lines = useMemo(() => content.split("\n"), [content]);
  const shown = lines.slice(0, 4000);
  if (!content) return <div className="empty">No content.</div>;
  return (
    <div className="code-body">
      {shown.map((line, index) => (
        <div className="code-line" key={index}>
          <span className="ln">{index + 1}</span>
          <span className="lc">{line || " "}</span>
        </div>
      ))}
      {lines.length > shown.length && (
        <div className="code-line muted">
          … {lines.length - shown.length} more lines — download for the full content
        </div>
      )}
    </div>
  );
}

function KV({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="kv">
      <small>{label}</small>
      <b>{value}</b>
    </div>
  );
}

function entropyBadge(entropy: number): string {
  if (entropy >= 7.2) return "badge red";
  if (entropy >= 6.6) return "badge amber";
  return "badge green";
}

/* ------------------------------------------------------------------ Overview */

function OverviewPage() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<DeepResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const fileSize = useMemo(
    () => (file ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : "No file selected"),
    [file],
  );

  async function inspect() {
    if (!file) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const response = await fetch(`${API}/v1/analysis/static-file`, { method: "POST", body });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Analysis failed");
      setResult(payload);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach local API.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="eyebrow"><Activity size={14} /> REVERSE ENGINEERING WORKSPACE</div>
      <div className="hero-row">
        <div>
          <h1>Understand software.<br /><em>Trace every detail.</em></h1>
          <p className="intro">
            A unified workspace for authorized software inspection, technical discovery,
            and evidence-backed analysis.
          </p>
        </div>
        <div className="hero-symbol"><Braces size={54} /><span /></div>
      </div>
      <div className="stats">
        <div className="stat"><span>ANALYSIS ENGINE</span><b>Ready</b>
          <small><i className="green-dot" /> Deep PE + APK inspection enabled</small></div>
        <div className="stat"><span>CODE VIEWS</span><b>6 modes</b>
          <small>Hex · Strings · Disasm · Manifest · DEX · Assets</small></div>
        <div className="stat"><span>AI CONNECTION</span><b>Not configured</b>
          <small>Connect a local or cloud model later</small></div>
      </div>
      <div className="section-heading">
        <div><span className="eyebrow">GET STARTED</span><h2>Quick inspection</h2></div>
        <span className="section-note">Files are analyzed as data — never executed.</span>
      </div>
      <div className="inspect-card">
        <div className="upload-icon"><UploadCloud size={24} /></div>
        <div className="upload-copy">
          <h3>Inspect a local file</h3>
          <p>Fast metadata check: hash, signature, printable strings.</p>
          <small>{file ? `${file.name} · ${fileSize}` : "Maximum upload size is configured by the local API."}</small>
        </div>
        <label className="file-button">
          Choose file
          <input type="file" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setResult(null); }} />
        </label>
        <button className="primary" disabled={!file || busy} onClick={inspect}>
          {busy ? "Inspecting…" : "Analyze file"}
        </button>
      </div>
      {error && <div className="error">{error}</div>}
      {result && (
        <div className="result-card">
          <div className="result-head">
            <div><span className="eyebrow">INSPECTION RESULT</span><h3>{result.filename}</h3></div>
            <span className="pill">{result.detected_format ?? result.format}</span>
          </div>
          <div className="result-grid">
            <div><small>SIZE</small><b>{fmtBytes(result.size_bytes)}</b></div>
            <div><small>SHA-256</small><code>{result.sha256}</code></div>
          </div>
          <h4>Printable string preview</h4>
          <pre>{result.strings_preview?.join("\n") || "No printable strings found."}</pre>
          <div className="tool-row">
            <CopyButton text={result.sha256} label="Copy hash" />
            <DownloadButton
              filename={`${result.filename}.static.json`}
              content={JSON.stringify(result, null, 2)}
              mime="application/json"
              label="Download JSON"
            />
          </div>
          {result.warnings?.map((w) => <p className="warning" key={w}>{w}</p>)}
        </div>
      )}
      <div className="section-heading modules-heading">
        <div><span className="eyebrow">CAPABILITIES</span><h2>Analysis modules</h2></div>
        <span className="section-note">Working features, ready to use</span>
      </div>
      <div className="module-grid">
        {[
          { name: "Static file analysis", detail: "Hashes, file signatures, printable strings", icon: FileSearch, state: "Available" },
          { name: "Deep PE analysis", detail: "Sections, imports, exports, resources, packing heuristics", icon: Cpu, state: "Available" },
          { name: "Deep APK analysis", detail: "Manifest decode, permissions, DEX classes, assets", icon: Smartphone, state: "Available" },
          { name: "Code viewer", detail: "Hex, strings, disassembly, manifest, DEX, asset source", icon: Code2, state: "Available" },
          { name: "Evidence reports", detail: "Scored findings with evidence, Markdown + HTML export", icon: ShieldCheck, state: "Available" },
          { name: "Java decompilation", detail: "JADX Java sources + APKTool resources/smali", icon: Braces, state: "Available" },
          { name: "Web source analysis", detail: "JS/TS/HTML imports, endpoints, secret findings", icon: Globe, state: "Available" },
          { name: "MCP agent bridge", detail: "Expose safe inspection tools to AI agents", icon: Workflow, state: "Available" },
        ].map((m) => (
          <div className="module" key={m.name}>
            <div className="module-icon"><m.icon size={19} /></div>
            <div className="module-body"><h3>{m.name}</h3><p>{m.detail}</p></div>
            <span className={`module-state ${m.state === "Available" ? "ready" : ""}`}>{m.state}</span>
          </div>
        ))}
      </div>
    </>
  );
}

/* --------------------------------------------------------------- Analysis lab */

function LabPage() {
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<"deep" | "web">("deep");
  const [result, setResult] = useState<DeepResult | WebResult | null>(null);
  const [tab, setTab] = useState("summary");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const deep = result && "format" in result && ("pe" in result || "apk" in result || result.deep_supported === false)
    ? result as DeepResult : null;
  const web = result && "language" in result ? result as WebResult : null;

  async function run() {
    if (!file) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const endpoint = mode === "deep" ? "/v1/analysis/deep" : "/v1/analysis/web-source";
      const response = await fetch(`${API}${endpoint}`, { method: "POST", body });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Analysis failed");
      setResult(payload);
      setTab("summary");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach local API.");
    } finally {
      setBusy(false);
    }
  }

  const peTabs = [
    ["summary", "Summary"], ["sections", "Sections"], ["imports", "Imports"],
    ["resources", "Resources"], ["version", "Version & debug"],
  ];
  const apkTabs = [
    ["summary", "Summary"], ["manifest", "Manifest"], ["components", "Components"],
    ["dex", "DEX classes"], ["files", "APK files"],
  ];

  return (
    <>
      <div className="eyebrow"><FileSearch size={14} /> ANALYSIS LAB</div>
      <div className="hero-row">
        <div>
          <h1>Deep structural<br /><em>analysis.</em></h1>
          <p className="intro">
            Upload an EXE/DLL for PE header, section, import and resource analysis —
            or an APK for manifest, permission, DEX and asset inspection.
          </p>
        </div>
      </div>

      <div className="inspect-card">
        <div className="upload-icon"><UploadCloud size={24} /></div>
        <div className="upload-copy">
          <h3>{file ? file.name : "Choose a file to analyze"}</h3>
          <p>{mode === "deep"
            ? "Deep mode: PE (exe/dll) and APK get full structural analysis."
            : "Web mode: JS/TS/HTML source for imports, endpoints and secret findings."}</p>
          <small>{file ? `${fmtBytes(file.size)} selected` : "EXE · DLL · APK · JS · TS · HTML"}</small>
        </div>
        <div className="seg">
          <button className={mode === "deep" ? "active" : ""} onClick={() => setMode("deep")}>Deep</button>
          <button className={mode === "web" ? "active" : ""} onClick={() => setMode("web")}>Web source</button>
        </div>
        <label className="file-button">
          Choose file
          <input type="file" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setResult(null); setError(""); }} />
        </label>
        <button className="primary" disabled={!file || busy} onClick={run}>
          {busy ? "Analyzing…" : "Run analysis"}
        </button>
      </div>
      {error && <div className="error">{error}</div>}

      {deep && (
        <div className="result-card">
          <div className="result-head">
            <div>
              <span className="eyebrow">DEEP ANALYSIS RESULT</span>
              <h3>{deep.filename}</h3>
            </div>
            <span className="pill">{deep.pe ? `PE${deep.pe.bits}` : deep.apk ? "Android APK" : deep.detected_format}</span>
          </div>
          <div className="tool-row">
            <CopyButton text={JSON.stringify(deep, null, 2)} label="Copy JSON" />
            <DownloadButton
              filename={`${deep.filename}.analysis.json`}
              content={JSON.stringify(deep, null, 2)}
              mime="application/json"
              label="Download JSON"
            />
            <span className="badge">{fmtBytes(deep.size_bytes)}</span>
            <span className="badge">sha256 {deep.sha256.slice(0, 12)}…</span>
          </div>

          {deep.pe && (
            <>
              <div className="tabs">
                {peTabs.map(([id, label]) => (
                  <button key={id} className={`tab ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>{label}</button>
                ))}
              </div>
              {tab === "summary" && (
                <>
                  <div className="kv-grid">
                    <KV label="MACHINE" value={`${deep.pe.machine} · ${deep.pe.bits}-bit`} />
                    <KV label="SUBSYSTEM" value={deep.pe.subsystem} />
                    <KV label="ENTRY POINT" value={`0x${deep.pe.entry_point_rva.toString(16)} (${deep.pe.entry_point_section ?? "?"})`} />
                    <KV label="IMAGE BASE" value={`0x${deep.pe.image_base.toString(16)}`} />
                    <KV label="COMPILE TIME" value={deep.pe.compile_time ?? "unknown"} />
                    <KV label="KIND" value={deep.pe.is_dll ? "DLL library" : "Executable"} />
                    <KV label=".NET" value={deep.pe.is_dotnet ? `Yes (${deep.pe.clr_runtime_version ?? "?"})` : "No"} />
                    <KV label="AUTHENTICODE" value={deep.pe.authenticode_signed ? "Signed" : "Not signed"} />
                    <KV label="OVERLAY" value={fmtBytes(deep.pe.overlay_size)} />
                    <KV label="PACKING" value={deep.pe.packing_suspected ? "⚠ Suspected" : "Not detected"} />
                  </div>
                  {deep.pe.packing_suspected && (
                    <div className="list-block">
                      <h4>PACKING INDICATORS</h4>
                      <ul>{deep.pe.packing_reasons.map((r) => <li key={r}>{r}</li>)}</ul>
                    </div>
                  )}
                  {Object.keys(deep.pe.version_info).length > 0 && (
                    <div className="list-block">
                      <h4>VERSION INFO</h4>
                      <ul>
                        {Object.entries(deep.pe.version_info).map(([k, v]) => <li key={k}><b>{k}:</b> {v}</li>)}
                      </ul>
                    </div>
                  )}
                </>
              )}
              {tab === "sections" && (
                <div className="table-wrap">
                  <table className="data">
                    <thead>
                      <tr><th>NAME</th><th className="num">VADDR</th><th className="num">VSIZE</th><th className="num">RAW</th><th className="num">ENTROPY</th><th>FLAGS</th></tr>
                    </thead>
                    <tbody>
                      {deep.pe.sections.map((s) => (
                        <tr key={s.name + s.virtual_address}>
                          <td><code className="inline">{s.name}</code></td>
                          <td className="num">0x{s.virtual_address.toString(16)}</td>
                          <td className="num">{fmtBytes(s.virtual_size)}</td>
                          <td className="num">{fmtBytes(s.raw_size)}</td>
                          <td className="num"><span className={entropyBadge(s.entropy)}>{s.entropy.toFixed(2)}</span></td>
                          <td>{s.characteristics.join(" · ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {tab === "imports" && (
                deep.pe.imports.length === 0
                  ? <div className="empty">No import table found.</div>
                  : deep.pe.imports.map((dll) => (
                    <details className="dll" key={dll.dll} open={deep.pe!.imports.length <= 3}>
                      <summary>{dll.dll}<span>{dll.function_count} functions</span></summary>
                      <div className="chips">
                        {dll.functions.map((fn) => <span className="chip" key={fn}>{fn}</span>)}
                      </div>
                    </details>
                  ))
              )}
              {tab === "resources" && (
                <>
                  <div className="chips">
                    {Object.entries(deep.pe.resource_counts).map(([type, count]) => (
                      <span className="chip" key={type}>{type}: {count}</span>
                    ))}
                    {Object.keys(deep.pe.resource_counts).length === 0 && <span className="chip">No resources</span>}
                  </div>
                  <div className="table-wrap">
                    <table className="data">
                      <thead><tr><th>TYPE</th><th>PATH</th><th className="num">SIZE</th></tr></thead>
                      <tbody>
                        {deep.pe.resources.slice(0, 300).map((r, i) => (
                          <tr key={i}>
                            <td>{r.type}</td>
                            <td>{r.path.join(" / ")}</td>
                            <td className="num">{fmtBytes(r.size)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
              {tab === "version" && (
                <>
                  <div className="list-block">
                    <h4>DEBUG DIRECTORY</h4>
                    {deep.pe.debug.length === 0 ? <ul><li>No debug records</li></ul> : (
                      <ul>
                        {deep.pe.debug.map((d, i) => <li key={i}>type {d.type}{d.pdb ? ` — ${d.pdb}` : ""}</li>)}
                      </ul>
                    )}
                  </div>
                  <div className="list-block">
                    <h4>EXPORTS ({deep.pe.exports.length})</h4>
                    {deep.pe.exports.length === 0 ? <ul><li>No export table</li></ul> : (
                      <div className="chips">
                        {deep.pe.exports.slice(0, 200).map((e) => (
                          <span className="chip" key={`${e.ordinal}-${e.name}`}>#{e.ordinal} {e.name}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </>
              )}
            </>
          )}

          {deep.apk && (
            <>
              <div className="tabs">
                {apkTabs.map(([id, label]) => (
                  <button key={id} className={`tab ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>{label}</button>
                ))}
              </div>
              {tab === "summary" && (
                <div className="kv-grid">
                  <KV label="PACKAGE" value={deep.apk.package ?? "unknown"} />
                  <KV label="VERSION" value={`${deep.apk.version_name ?? "?"} (${deep.apk.version_code ?? "?"})`} />
                  <KV label="MIN / TARGET SDK" value={`${deep.apk.min_sdk ?? "?"} → ${deep.apk.target_sdk ?? "?"}`} />
                  <KV label="LABEL" value={deep.apk.application_label ?? "—"} />
                  <KV label="LAUNCHER" value={deep.apk.launchable_activity ?? "—"} />
                  <KV label="PERMISSIONS" value={String(deep.apk.permissions.length)} />
                  <KV label="ACTIVITIES" value={String(deep.apk.activities.length)} />
                  <KV label="FILES" value={`${deep.apk.entries_count} entries`} />
                  <KV label="DEX FILES" value={String(deep.apk.dex.length)} />
                  <KV label="SIGNATURE" value={deep.apk.signatures.length ? "Present" : "None"} />
                </div>
              )}
              {tab === "manifest" && (
                deep.apk.manifest_error
                  ? <div className="error">Manifest decode failed: {deep.apk.manifest_error}</div>
                  : (
                    <>
                      <div className="tool-row">
                        <CopyButton text={deep.apk.manifest_xml ?? ""} label="Copy XML" />
                        <DownloadButton
                          filename={`${deep.apk.package ?? "app"}.AndroidManifest.xml`}
                          content={deep.apk.manifest_xml ?? ""}
                          mime="application/xml"
                        />
                      </div>
                      <pre className="manifest">{deep.apk.manifest_xml}</pre>
                    </>
                  )
              )}
              {tab === "components" && (
                <>
                  <div className="list-block">
                    <h4>PERMISSIONS ({deep.apk.permissions.length})</h4>
                    <div className="chips">
                      {deep.apk.permissions.map((p) => <span className="chip" key={p}>{p}</span>)}
                    </div>
                  </div>
                  {[
                    ["ACTIVITIES", deep.apk.activities], ["SERVICES", deep.apk.services],
                    ["RECEIVERS", deep.apk.receivers], ["PROVIDERS", deep.apk.providers],
                    ["FEATURES", deep.apk.features],
                  ].map(([label, items]) => (
                    <div className="list-block" key={label as string}>
                      <h4>{label as string} ({(items as string[]).length})</h4>
                      {(items as string[]).length === 0
                        ? <ul><li>None</li></ul>
                        : <ul>{(items as string[]).map((i) => <li key={i}>{i}</li>)}</ul>}
                    </div>
                  ))}
                </>
              )}
              {tab === "dex" && (
                deep.apk.dex.length === 0
                  ? <div className="empty">No .dex files found.</div>
                  : deep.apk.dex.map((dex) => (
                    <div key={dex.name}>
                      <div className="tool-row">
                        <span className="badge green">{dex.name}</span>
                        {dex.counts && Object.entries(dex.counts).map(([k, v]) => (
                          <span className="badge" key={k}>{k}: {String(v)}</span>
                        ))}
                      </div>
                      {(dex.classes ?? []).slice(0, 500).map((cls) => (
                        <details className="dll" key={cls.name}>
                          <summary>
                            {cls.name}
                            <span>{cls.access}{cls.superclass ? ` extends ${cls.superclass}` : ""} · {cls.methods.length} methods</span>
                          </summary>
                          <div className="chips">
                            {cls.methods.map((m) => (
                              <span className="chip" key={`${m.name}${m.proto}${m.kind}`}>
                                {m.name}{m.proto} <i>({m.kind})</i>
                              </span>
                            ))}
                          </div>
                        </details>
                      ))}
                      {(dex.classes ?? []).length > 500 && (
                        <div className="empty">Showing first 500 of {dex.counts?.classes ?? "?"} classes — download the JSON for all.</div>
                      )}
                    </div>
                  ))
              )}
              {tab === "files" && (
                <div className="table-wrap">
                  <table className="data">
                    <thead><tr><th>PATH</th><th className="num">SIZE</th><th>COMPRESSION</th></tr></thead>
                    <tbody>
                      {deep.apk.entries.slice(0, 500).map((entry) => (
                        <tr key={entry.name}>
                          <td>{entry.name}</td>
                          <td className="num">{fmtBytes(entry.size)}</td>
                          <td>{entry.method}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {deep.apk.entries.length > 500 && (
                    <div className="empty">Showing first 500 of {deep.apk.entries_count} entries.</div>
                  )}
                </div>
              )}
            </>
          )}

          {!deep.pe && !deep.apk && (
            <>
              <div className="error" style={{ borderColor: "#36516b", background: "#0d1727", color: "#9fb2c9" }}>
                {deep.note}
              </div>
              <h4>Printable string preview</h4>
              <pre>{deep.strings_preview?.join("\n") || "No printable strings found."}</pre>
            </>
          )}
          {deep.warnings?.map((w) => <p className="warning" key={w}>{w}</p>)}
        </div>
      )}

      {web && (
        <div className="result-card">
          <div className="result-head">
            <div><span className="eyebrow">WEB SOURCE ANALYSIS</span><h3>{web.filename}</h3></div>
            <span className="pill">{web.language}</span>
          </div>
          <div className="tool-row">
            <span className="badge">{web.line_count} lines</span>
            <span className="badge">{fmtBytes(web.size_bytes)}</span>
            <CopyButton text={JSON.stringify(web, null, 2)} label="Copy JSON" />
            <DownloadButton
              filename={`${web.filename}.web.json`}
              content={JSON.stringify(web, null, 2)}
              mime="application/json"
              label="Download JSON"
            />
          </div>
          {[
            ["IMPORTS", web.imports], ["FUNCTIONS", web.functions], ["CLASSES", web.classes],
            ["EXPORTS", web.exports], ["API ENDPOINTS", web.api_endpoints], ["URLS", web.urls],
          ].map(([label, items]) => (
            <div className="list-block" key={label as string}>
              <h4>{label as string} ({(items as Item[]).length})</h4>
              {(items as Item[]).length === 0 ? <ul><li>None found</li></ul> : (
                <div className="chips">
                  {(items as Item[]).slice(0, 200).map((i, idx) => (
                    <span className="chip" key={`${i.name}-${idx}`}>{i.name} <i>L{i.line}</i></span>
                  ))}
                </div>
              )}
            </div>
          ))}
          <div className="list-block">
            <h4>SECRET FINDINGS ({web.secret_findings.length})</h4>
            {web.secret_findings.length === 0 ? <ul><li>None found</li></ul> : (
              <ul>
                {web.secret_findings.map((s, i) => (
                  <li key={i}><b>{s.type}</b> at line {s.line}: <code className="inline">{s.value_redacted}</code> (redacted)</li>
                ))}
              </ul>
            )}
          </div>
          <div className="list-block">
            <h4>SUSPICIOUS PATTERNS ({web.suspicious_patterns.length})</h4>
            {web.suspicious_patterns.length === 0 ? <ul><li>None found</li></ul> : (
              <div className="chips">
                {web.suspicious_patterns.map((s, i) => (
                  <span className="chip" key={i}>{s.type} · line {s.line}</span>
                ))}
              </div>
            )}
          </div>
          {web.warnings?.map((w) => <p className="warning" key={w}>{w}</p>)}
        </div>
      )}
    </>
  );
}

/* --------------------------------------------------------------- Code viewer */

const VIEW_META: Record<string, { label: string; ext: string; mime: string }> = {
  hex: { label: "Hex dump", ext: "hex.txt", mime: "text/plain" },
  strings: { label: "Strings", ext: "strings.txt", mime: "text/plain" },
  disasm: { label: "Disassembly", ext: "asm", mime: "text/plain" },
  manifest: { label: "Manifest", ext: "AndroidManifest.xml", mime: "application/xml" },
  dex: { label: "DEX outline", ext: "dex.txt", mime: "text/plain" },
  asset: { label: "Asset source", ext: "txt", mime: "text/plain" },
  java: { label: "Java (jadx)", ext: "java", mime: "text/x-java-source" },
  smali: { label: "Smali (apktool)", ext: "smali", mime: "text/plain" },
};

function CodePage() {
  const [file, setFile] = useState<File | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [decompTargets, setDecompTargets] = useState<string[]>([]);
  const [view, setView] = useState<string>("hex");
  const [target, setTarget] = useState<string>("");
  const [result, setResult] = useState<CodeResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const kinds = useMemo(() => new Set(targets.map((t) => t.kind)), [targets]);
  const isApk = kinds.has("manifest");
  const viewOptions = [
    { id: "hex", show: true },
    { id: "strings", show: true },
    { id: "disasm", show: kinds.has("section") },
    { id: "manifest", show: kinds.has("manifest") },
    { id: "dex", show: kinds.has("dex") },
    { id: "asset", show: kinds.has("asset") },
    { id: "java", show: isApk },
    { id: "smali", show: isApk },
  ].filter((v) => v.show);

  const targetOptions = view === "java" || view === "smali"
    ? decompTargets.map((t) => ({ id: t, label: t }))
    : targets.filter((t) => {
        if (view === "disasm") return t.kind === "section" && t.id;
        if (view === "dex") return t.kind === "dex";
        if (view === "asset") return t.kind === "asset";
        return false;
      });

  async function fetchDecompile(nextView: string, nextTarget: string, chosenFile: File) {
    const body = new FormData();
    body.append("file", chosenFile);
    body.append("tool", nextView === "java" ? "jadx" : "apktool");
    if (nextTarget) body.append("entry", nextTarget);
    const response = await fetch(`${API}/v1/analysis/decompile`, { method: "POST", body });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail ?? "Decompilation failed");

    const listing: string[] = payload.classes ?? payload.files ?? [];
    const warnings = payload.stderr_tail ? [payload.stderr_tail] : [];

    if (!nextTarget) {
      setDecompTargets(listing);
      if (listing.length > 0) {
        setTarget(listing[0]);
        await fetchDecompile(nextView, listing[0], chosenFile);
        return;
      }
      setResult({
        view: nextView, filename: chosenFile.name, target: null,
        content: "(no decompiled files)", line_count: 1, truncated: false,
        meta: { listing: [] }, warnings,
      });
      return;
    }

    const content: string = payload.source ?? payload.text ?? "(no content)";
    setResult({
      view: nextView, filename: chosenFile.name, target: nextTarget, content,
      line_count: content.split("\n").length,
      truncated: payload.source_truncated ?? payload.text_truncated ?? false,
      meta: { listing, total: payload.classes_total ?? payload.files_total },
      warnings,
    });
  }

  async function fetchView(nextView: string, nextTarget: string, chosenFile: File | null = file) {
    if (!chosenFile) return;
    setBusy(true);
    setError("");
    try {
      if (nextView === "java" || nextView === "smali") {
        await fetchDecompile(nextView, nextTarget, chosenFile);
        return;
      }
      const body = new FormData();
      body.append("file", chosenFile);
      body.append("view", nextView);
      if (nextTarget) body.append("target", nextTarget);
      const response = await fetch(`${API}/v1/analysis/code-view`, { method: "POST", body });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "View failed");
      setResult(payload);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach local API.");
    } finally {
      setBusy(false);
    }
  }

  async function onFileChosen(chosen: File | null) {
    setFile(chosen);
    setResult(null);
    setError("");
    setTargets([]);
    if (!chosen) return;
    setBusy(true);
    try {
      const body = new FormData();
      body.append("file", chosen);
      body.append("view", "targets");
      const response = await fetch(`${API}/v1/analysis/code-view`, { method: "POST", body });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Could not read file targets");
      const list: Target[] = payload.meta?.targets ?? [];
      setTargets(list);
      const listKinds = new Set(list.map((t) => t.kind));
      let initial = "hex";
      let initialTarget = "";
      if (listKinds.has("manifest")) {
        initial = "manifest";
      } else if (listKinds.has("section")) {
        initial = "disasm";
        initialTarget = list.find((t) => t.kind === "section" && t.id)?.id ?? "";
      }
      setView(initial);
      setTarget(initialTarget);
      await fetchView(initial, initialTarget, chosen);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach local API.");
    } finally {
      setBusy(false);
    }
  }

  const downloadName = (() => {
    if (!result) return "content.txt";
    const base = result.filename.replace(/\.[^.]+$/, "");
    if (result.view === "asset" && result.target) {
      return result.target.split("/").pop() ?? "asset.txt";
    }
    if (result.view === "disasm" && result.meta?.section) {
      return `${base}.${String(result.meta.section).replace(/[^\w.-]/g, "_")}.asm`;
    }
    if (result.view === "manifest") return `${result.filename.replace(/\.apk$/i, "")}.AndroidManifest.xml`;
    return `${base}.${VIEW_META[result.view]?.ext ?? "txt"}`;
  })();

  return (
    <>
      <div className="eyebrow"><Code2 size={14} /> CODE VIEWER</div>
      <div className="hero-row">
        <div>
          <h1>See inside.<br /><em>Copy it, keep it.</em></h1>
          <p className="intro">
            Browse hex dumps, printable strings, x86/x64 disassembly, decoded APK manifests,
            DEX class outlines and embedded asset source — copy any view to the clipboard
            or download it as a file.
          </p>
        </div>
      </div>

      <div className="inspect-card">
        <div className="upload-icon"><FileCode size={24} /></div>
        <div className="upload-copy">
          <h3>{file ? file.name : "Choose a file to open"}</h3>
          <p>Views adapt to the file: executables offer sections & disassembly, APKs offer manifest, DEX and assets.</p>
          <small>{file ? `${fmtBytes(file.size)} selected` : "EXE · DLL · APK · any binary"}</small>
        </div>
        <label className="file-button">
          Choose file
          <input type="file" onChange={(e) => onFileChosen(e.target.files?.[0] ?? null)} />
        </label>
      </div>
      {error && <div className="error">{error}</div>}

      {file && (
        <div className="tool-row">
          <div className="seg">
            {viewOptions.map((v) => (
              <button
                key={v.id}
                className={view === v.id ? "active" : ""}
                disabled={busy}
                onClick={() => { setView(v.id); setTarget(""); fetchView(v.id, ""); }}
              >
                {VIEW_META[v.id]?.label ?? v.id}
              </button>
            ))}
          </div>
          {targetOptions.length > 0 && (
            <select
              className="select"
              value={target}
              disabled={busy}
              onChange={(e) => { setTarget(e.target.value); fetchView(view, e.target.value); }}
            >
              <option value="">— select target —</option>
              {targetOptions.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          )}
          {busy && <span className="badge amber">Loading…</span>}
        </div>
      )}

      {result && (
        <div className="code-panel">
          <div className="code-head">
            <div>
              <b>{VIEW_META[result.view]?.label ?? result.view}</b>
              {" — "}<small>{result.filename}{result.target ? ` · ${result.target}` : ""}</small>
            </div>
            <div className="tool-row" style={{ margin: 0 }}>
              <small>{result.line_count} lines{result.truncated ? " · truncated" : ""}</small>
              <CopyButton text={result.content} />
              <DownloadButton filename={downloadName} content={result.content} mime={VIEW_META[result.view]?.mime} />
            </div>
          </div>
          <CodeBody content={result.content} />
          {result.warnings?.map((w) => <p className="warning" key={w} style={{ padding: "0 14px 12px" }}>{w}</p>)}
        </div>
      )}

      {!file && (
        <div className="empty">
          Pick a file above to load its available views — everything stays on your machine.
        </div>
      )}
    </>
  );
}

/* ----------------------------------------------------------------- Projects */

function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    try {
      const response = await fetch(`${API}/v1/projects`);
      setProjects(await response.json());
    } catch {
      setError("Could not reach local API.");
    }
  }

  useEffect(() => { load(); }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`${API}/v1/projects`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim() }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Create failed");
      setName("");
      await load();
    } catch (e2) {
      setError(e2 instanceof Error ? e2.message : "Create failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="eyebrow"><FolderKanban size={14} /> PROJECTS</div>
      <div className="hero-row">
        <div>
          <h1>Local<br /><em>workspaces.</em></h1>
          <p className="intro">Group inspections into projects. Stored in-memory for now — SQLite persistence is on the roadmap.</p>
        </div>
      </div>
      <form className="project-form" onSubmit={create}>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Project name (e.g. Banking APK audit)"
          maxLength={120}
        />
        <button className="primary" type="submit" disabled={busy || !name.trim()}>
          <Plus size={14} /> {busy ? "Creating…" : "Create"}
        </button>
      </form>
      {error && <div className="error">{error}</div>}
      <div className="project-list">
        {projects.length === 0 && <div className="empty">No projects yet — create your first one above.</div>}
        {projects.map((p) => (
          <div className="project-item" key={p.id}>
            <div>
              <b>{p.name}</b>
              <small>{p.id}</small>
            </div>
            <span className="badge green">{new Date(p.created_at).toLocaleString()}</span>
          </div>
        ))}
      </div>
    </>
  );
}

/* -------------------------------------------------------------- Agent tools */

function AgentsPage() {
  const endpoints = [
    ["GET", "/health", "API health check"],
    ["POST", "/v1/analysis/static-file", "Baseline: hash, signature, strings"],
    ["POST", "/v1/analysis/deep", "Deep PE / APK structural analysis"],
    ["POST", "/v1/analysis/web-source", "JS/TS imports, endpoints, secrets"],
    ["POST", "/v1/analysis/code-view", "hex · strings · disasm · manifest · dex · asset"],
    ["POST", "/v1/analysis/report", "Scored evidence report (JSON + MD + HTML)"],
    ["POST", "/v1/analysis/decompile", "JADX Java sources / APKTool resources+smali"],
    ["GET", "/v1/analysis/tools", "Installed decompiler status (jadx/apktool/JRE)"],
    ["GET", "/v1/projects", "List projects"],
    ["POST", "/v1/projects", "Create a project"],
  ];
  const mcpTools = [
    ["inspect_local_file", "Static metadata, SHA-256, signature, strings"],
    ["analyze_deep_file", "PE headers/imports/resources or APK manifest/DEX/assets"],
    ["view_file_code", "hex, strings, disasm, manifest, dex, asset views"],
    ["generate_evidence_report", "Scored findings with evidence, Markdown + HTML"],
    ["decompile_apk", "JADX Java sources or APKTool decoded resources"],
    ["list_capabilities", "What this server can and cannot do"],
  ];
  const cliCommands = [
    "revstudio inspect ./sample.exe",
    "revstudio deep ./sample.apk",
    "revstudio code ./sample.exe --view disasm --target .text",
    "revstudio code ./sample.apk --view asset --target assets/www/app.js",
    "revstudio report ./sample.apk --out report.html",
    "revstudio decompile ./sample.apk --tool jadx --entry MainActivity",
    "revstudio tools",
  ];

  return (
    <>
      <div className="eyebrow"><Terminal size={14} /> AGENT TOOLS</div>
      <div className="hero-row">
        <div>
          <h1>Automate the<br /><em>inspection pipeline.</em></h1>
          <p className="intro">
            Every capability is reachable from REST, the CLI and the MCP server —
            so AI agents can drive the same safe, non-executing analysis.
          </p>
        </div>
      </div>

      <div className="section-heading">
        <div><span className="eyebrow">REST API</span><h2>HTTP endpoints</h2></div>
        <span className="section-note">Base: {API}</span>
      </div>
      <div className="list-block">
        {endpoints.map(([method, path, desc]) => (
          <div className="endpoint" key={`${method} ${path}`}>
            <span className={`method ${method === "POST" ? "post" : ""}`}>{method}</span>
            <code className="inline">{path}</code>
            <span style={{ color: "#8292a9" }}>{desc}</span>
          </div>
        ))}
      </div>

      <div className="section-heading modules-heading">
        <div><span className="eyebrow">MCP SERVER</span><h2>Tools for AI agents</h2></div>
        <span className="section-note">revstudio-mcp</span>
      </div>
      <div className="module-grid">
        {mcpTools.map(([tool, desc]) => (
          <div className="module" key={tool}>
            <div className="module-icon"><Workflow size={19} /></div>
            <div className="module-body">
              <h3><code className="inline">{tool}</code></h3>
              <p>{desc}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="section-heading modules-heading">
        <div><span className="eyebrow">CLI</span><h2>Command line</h2></div>
        <span className="section-note">pip install -e ./services/cli</span>
      </div>
      <div className="list-block">
        <ul>
          {cliCommands.map((cmd) => (
            <li key={cmd} style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center" }}>
              <code className="inline" style={{ flex: 1 }}>{cmd}</code>
              <CopyButton text={cmd} />
            </li>
          ))}
        </ul>
      </div>

      <div className="list-block">
        <h4><Info size={11} style={{ verticalAlign: -2 }} /> SAFETY</h4>
        <ul>
          <li>Files are inspected as data and never executed.</li>
          <li>Only analyze files you own or are authorized to inspect.</li>
          <li>Secrets found in source are redacted in results.</li>
          <li>Never put API keys in frontend source code.</li>
        </ul>
      </div>
    </>
  );
}

/* ------------------------------------------------------------- Evidence report */

const SEV_CLASS: Record<string, string> = {
  critical: "badge red", high: "badge red", medium: "badge amber",
  low: "badge", info: "badge green",
};

function ReportsPage() {
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<EvidenceReport | null>(null);
  const [tab, setTab] = useState("findings");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function run() {
    if (!file) return;
    setBusy(true);
    setError("");
    setReport(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const response = await fetch(`${API}/v1/analysis/report`, { method: "POST", body });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail ?? "Report generation failed");
      setReport(payload);
      setTab("findings");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach local API.");
    } finally {
      setBusy(false);
    }
  }

  const base = report ? report.subject.filename.replace(/\.[^.]+$/, "") : "report";

  return (
    <>
      <div className="eyebrow"><FileText size={14} /> EVIDENCE REPORT</div>
      <div className="hero-row">
        <div>
          <h1>Scored findings,<br /><em>ready to share.</em></h1>
          <p className="intro">
            Turn any EXE or APK into a reviewable evidence report: risk score,
            severity-ranked findings with the exact lines that prove them, and
            Markdown / HTML exports you can copy or download.
          </p>
        </div>
      </div>

      <div className="inspect-card">
        <div className="upload-icon"><UploadCloud size={24} /></div>
        <div className="upload-copy">
          <h3>{file ? file.name : "Choose a file to report on"}</h3>
          <p>The report scores structural evidence — signing, packing, permissions, secrets — never runtime behaviour.</p>
          <small>{file ? `${fmtBytes(file.size)} selected` : "EXE · DLL · APK · any static file"}</small>
        </div>
        <label className="file-button">
          Choose file
          <input type="file" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setReport(null); setError(""); }} />
        </label>
        <button className="primary" disabled={!file || busy} onClick={run}>
          {busy ? "Building report…" : "Generate report"}
        </button>
      </div>
      {error && <div className="error">{error}</div>}

      {report && (
        <div className="result-card">
          <div className="result-head">
            <div>
              <span className="eyebrow">EVIDENCE REPORT · {report.report_id}</span>
              <h3>{report.subject.filename}</h3>
            </div>
            <span className={`pill risk-${report.risk.level}`}>
              RISK {report.risk.level.toUpperCase()} · {report.risk.score}/100
            </span>
          </div>

          <div className="tool-row">
            <CopyButton text={report.markdown ?? ""} label="Copy Markdown" />
            <DownloadButton filename={`${base}.report.md`} content={report.markdown ?? ""} mime="text/markdown" label="Download .md" />
            <DownloadButton filename={`${base}.report.html`} content={report.html ?? ""} mime="text/html" label="Download .html" />
            <DownloadButton filename={`${base}.report.json`} content={JSON.stringify(report, null, 2)} mime="application/json" label="Download .json" />
            <span className="badge">sha256 {report.subject.sha256.slice(0, 12)}…</span>
            <span className="badge">{fmtBytes(report.subject.size_bytes)}</span>
          </div>

          <div className="kv-grid">
            {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
              <div className="kv" key={sev}>
                <small>{sev.toUpperCase()}</small>
                <b>{report.risk.counts[sev] ?? 0}</b>
              </div>
            ))}
          </div>

          <div className="tabs">
            {[["findings", `Findings (${report.findings.length})`], ["markdown", "Markdown"], ["html", "HTML preview"]].map(([id, label]) => (
              <button key={id} className={`tab ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>{label}</button>
            ))}
          </div>

          {tab === "findings" && (
            report.findings.length === 0
              ? <div className="empty">No findings raised by the current rule set.</div>
              : report.findings.map((f) => (
                <details className="dll" key={f.id} open>
                  <summary>
                    <span style={{ display: "flex", gap: 9, alignItems: "center", minWidth: 0 }}>
                      <span className={SEV_CLASS[f.severity]}>{f.severity.toUpperCase()}</span>
                      <b style={{ color: "#e9edf8", fontWeight: 600 }}>{f.id} · {f.title}</b>
                    </span>
                    <span>{f.category}</span>
                  </summary>
                  <div style={{ padding: "0 13px 12px" }}>
                    <ul style={{ margin: 0, paddingLeft: 17, display: "grid", gap: 5, fontSize: 11, color: "#c3cede" }}>
                      {f.evidence.map((ev, i) => <li key={i}>{ev}</li>)}
                    </ul>
                    {f.recommendation && (
                      <p style={{ fontSize: 11, color: "#9be7cd", margin: "9px 0 0" }}>
                        <b>Recommendation:</b> {f.recommendation}
                      </p>
                    )}
                  </div>
                </details>
              ))
          )}

          {tab === "markdown" && (
            <div className="code-panel">
              <div className="code-head">
                <b>{base}.report.md</b>
                <small>{(report.markdown ?? "").split("\n").length} lines</small>
              </div>
              <CodeBody content={report.markdown ?? ""} />
            </div>
          )}

          {tab === "html" && report.html && (
            <div className="code-panel">
              <div className="code-head">
                <b>{base}.report.html</b>
                <div className="tool-row" style={{ margin: 0 }}>
                  <DownloadButton filename={`${base}.report.html`} content={report.html} mime="text/html" label="Download HTML" />
                </div>
              </div>
              <iframe
                title="Evidence report preview"
                srcDoc={report.html}
                style={{ width: "100%", height: 560, border: 0, background: "#0a111d" }}
              />
            </div>
          )}

          <div className="list-block" style={{ marginTop: 14 }}>
            <h4><Info size={11} style={{ verticalAlign: -2 }} /> LIMITATIONS</h4>
            <ul>{report.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
          </div>
        </div>
      )}
    </>
  );
}

/* --------------------------------------------------------------------- Shell */

export default function App() {
  const [page, setPage] = useState<Page>("overview");
  const [health, setHealth] = useState<Health | null>(null);
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    fetch(`${API}/health`)
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  const crumbLabel = NAV.find((n) => n.id === page)?.label ?? "Overview";

  return (
    <div className="shell">
      <aside className={`sidebar ${navOpen ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Boxes size={21} /></div>
          <div><b>REVSTUDIO</b><small>INTELLIGENCE WORKSPACE</small></div>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <nav>
          {NAV.map((item) => (
            <a
              key={item.id}
              className={page === item.id ? "active" : ""}
              onClick={() => { setPage(item.id); setNavOpen(false); }}
            >
              <item.icon size={17} /> {item.label}
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="secure">
            <ShieldCheck size={16} />
            <span><b>Local-first mode</b><small>Your files stay on your machine</small></span>
          </div>
          <small className="version">VERSION 0.2.0 · DEEP ANALYSIS</small>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <button className="icon-btn mobile-menu" onClick={() => setNavOpen(!navOpen)} aria-label="Toggle menu">
            <Menu />
          </button>
          <div className="crumb">Workspace <span>/</span> {crumbLabel}</div>
          <div className="top-actions">
            <span className={`api-dot ${health ? "online" : ""}`} />
            <span className="api-label">{health ? "API connected" : "API offline"}</span>
            <button className="avatar">RS</button>
          </div>
        </header>
        <section className="content">
          {page === "overview" && <OverviewPage />}
          {page === "lab" && <LabPage />}
          {page === "code" && <CodePage />}
          {page === "report" && <ReportsPage />}
          {page === "projects" && <ProjectsPage />}
          {page === "agents" && <AgentsPage />}
          <footer>
            <span>REVSTUDIO © 2026</span>
            <span><HardDrive size={13} /> LOCAL-FIRST · EVIDENCE-DRIVEN</span>
          </footer>
        </section>
      </main>
    </div>
  );
}
