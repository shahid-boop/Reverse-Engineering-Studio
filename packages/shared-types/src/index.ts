export type Platform = "windows" | "macos" | "linux" | "web" | "android";
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export interface ProjectSummary { id: string; name: string; created_at: string; }
export interface StaticInspection {
  filename: string; size_bytes: number; sha256: string;
  detected_format: string; strings_preview: string[]; warnings: string[];
}
export interface Finding {
  id: string; title: string; severity: FindingSeverity;
  evidence: string[]; confidence: number;
}
