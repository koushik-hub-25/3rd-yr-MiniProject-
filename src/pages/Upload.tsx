import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, Badge } from "../components/ui";
import { UploadCloud, FileText, CheckCircle, AlertCircle, Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";

export default function Upload() {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [status, setStatus] = useState("");
  const [correlationSummary, setCorrelationSummary] = useState<any>(null);
  const navigate = useNavigate();

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files?.length) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setStatus("Extracting text and running AI analysis & CTI correlation pipeline...");
    setCorrelationSummary(null);
    
    const formData = new FormData();
    formData.append("file", file);
    
    try {
      const res = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();

      if (!res.ok) {
        setStatus(data.error || "Upload failed.");
        setUploading(false);
        return;
      }
      
      if (data.correlationResult) {
        setCorrelationSummary(data.correlationResult);
      }

      setStatus("Intelligence report analyzed & correlated with local NVD, CISA KEV, and MITRE feeds!");
      setUploading(false);
    } catch (e: any) {
      setStatus("Upload failed: " + (e?.message || "Network error"));
      setUploading(false);
    }
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white tracking-tight">Upload Intelligence</h1>
        <p className="text-slate-400 mt-2">Submit raw intelligence reports (TXT, PDF, DOCX) for automated threat extraction, normalization, and local CTI correlation.</p>
      </div>

      <Card>
        <CardContent className="p-8">
          <div 
            className="border-2 border-dashed border-slate-700 rounded-xl p-12 text-center hover:bg-slate-800/30 transition-colors"
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
          >
            <div className="flex flex-col items-center justify-center space-y-4">
              <div className="p-4 bg-slate-950 rounded-full border border-slate-800">
                <UploadCloud className="w-8 h-8 text-blue-500" />
              </div>
              <div>
                <h3 className="text-lg font-medium text-white mb-1">Drag and drop report</h3>
                <p className="text-sm text-slate-400">or click to browse files (TXT, PDF, DOCX max 15MB)</p>
              </div>
              <input 
                type="file" 
                id="file-upload" 
                className="hidden" 
                accept=".txt,.pdf,.docx,.log"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />
              <label htmlFor="file-upload" className="cursor-pointer bg-slate-800 hover:bg-slate-700 text-white px-6 py-2.5 rounded-lg font-medium transition-colors border border-slate-700">
                Select File
              </label>
            </div>
          </div>

          {file && (
            <div className="mt-8 p-4 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <FileText className="text-slate-400 w-5 h-5" />
                <div>
                  <p className="text-sm font-medium text-slate-200">{file.name}</p>
                  <p className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB</p>
                </div>
              </div>
              <button
                onClick={handleUpload}
                disabled={uploading}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
              >
                {uploading && <Loader2 className="w-4 h-4 animate-spin" />}
                {uploading ? "Processing..." : "Run AI & CTI Correlation"}
              </button>
            </div>
          )}
          
          {status && (() => {
            const isErr = status.toLowerCase().includes("fail") || status.toLowerCase().includes("error") || status.toLowerCase().includes("invalid");
            return (
              <div className={`mt-4 flex items-center justify-between gap-2 text-sm p-3 rounded-lg border ${
                isErr
                  ? "text-red-400 bg-red-500/10 border-red-500/20"
                  : "text-blue-400 bg-blue-500/10 border-blue-500/20"
              }`}>
                <div className="flex items-center gap-2">
                  {uploading ? (
                    <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                  ) : isErr ? (
                    <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                  ) : (
                    <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                  )}
                  <span>{status}</span>
                </div>
                {correlationSummary && !isErr && (
                  <button
                    onClick={() => navigate(`/reports/${correlationSummary.reportId}`)}
                    className="bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold px-3 py-1.5 rounded transition-colors shrink-0"
                  >
                    View Dossier
                  </button>
                )}
              </div>
            );
          })()}

          {correlationSummary && (
            <div className="mt-6 p-5 bg-slate-900/90 rounded-xl border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-semibold text-white">CTI Correlation Pipeline Summary</h4>
                <div className="flex items-center gap-1.5">
                  {correlationSummary.sources?.map((s: string) => (
                    <span key={s} className="px-2 py-0.5 text-[10px] font-medium rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {s}
                    </span>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
                  <div className="text-xs text-slate-400">Vulnerabilities (NVD/CISA)</div>
                  <div className="text-lg font-bold text-amber-400 mt-0.5">{correlationSummary.vulnerabilities?.length || 0}</div>
                </div>
                <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
                  <div className="text-xs text-slate-400">MITRE Techniques</div>
                  <div className="text-lg font-bold text-blue-400 mt-0.5">{correlationSummary.mitreTechniques?.length || 0}</div>
                </div>
                <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
                  <div className="text-xs text-slate-400">Normalized IOCs</div>
                  <div className="text-lg font-bold text-emerald-400 mt-0.5">{correlationSummary.iocs?.length || 0}</div>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
