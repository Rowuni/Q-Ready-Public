// Types aligned with Pydantic models in the backend (task F2).
// Must be kept in sync with backend/models.py.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type FindingSource =
  | 'cert_store'
  | 'ssh_key'
  | 'sshd_config'
  | 'openssl_cnf'
  | 'crypto_lib'
  | 'import_cert'
  | 'import_ssh'
  | 'import_config'

export type FindingStatus = 'open' | 'acknowledged' | 'resolved'

export type ScanMode = 'auto' | 'import'

export interface Scan {
  id: number
  hostname: string
  started_at: string
  finished_at: string | null
  qr_score: number | null
  os_version: string | null
  mode: ScanMode
}

export interface Finding {
  id: number
  scan_id: number
  source: FindingSource
  algorithm: string
  severity: Severity
  name: string | null
  key_size: number | null
  expiration_date: string | null
  store_or_path: string | null
  risk_score: number | null
  recommendation: string | null
  recommendation_url: string | null
  detail: string | null
  status: FindingStatus
  created_at: string
}

// GET /scans/ returns ScanSummary (not ScanRead). See backend/routers/scan.py.
export interface ScanSummary {
  id: number
  timestamp: string
  machine_name: string
  qr_score: number | null
  nb_findings_by_severity: Record<string, number>
}

// POST /scans/ has no request body (the agent is invoked server-side).
// This type is kept for potential future use (e.g. triggering with options).
export interface ScanRequest {
  hostname?: string
  os_version?: string
  mode?: ScanMode
}

// POST /import/cert uses multipart/form-data (file + optional password string).
// No JSON body type needed — use FormData in the UI layer. See backend/routers/imports.py (IM1).

// POST /import/ssh uses multipart/form-data (file field: UploadFile).
// No JSON body type needed — use FormData in the UI layer. See backend/routers/imports.py (IM2).

// POST /import/config uses multipart/form-data (file field: UploadFile, type auto-detected from filename).
// No JSON body type needed — use FormData in the UI layer. See backend/routers/imports.py (IM3).
