export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type IncidentStatus = 'detected' | 'investigating' | 'contained' | 'resolved' | 'false_positive';
export type EndpointStatus = 'online' | 'offline' | 'isolated';
export type AgentStatus = 'online' | 'offline' | 'degraded';
export type NetworkStatus = 'connected' | 'isolated';
export type EvidenceIntegrity =
  | 'verified'
  | 'verification_failed'
  | 'artifact_missing'
  | 'not_verified'
  | 'pending'
  | 'failed';
export type EvidenceType =
  | 'process_snapshot'
  | 'file_manifest'
  | 'event_logs'
  | 'memory_metadata'
  | 'network_metadata'
  | 'ransom_note'
  | 'detection_log'
  | 'text_artifact';
export type EvidenceCollectionMethod = 'automated' | 'manual';
export type ManualEvidenceType =
  | 'windows_event_logs'
  | 'process_snapshot'
  | 'file_manifest'
  | 'text_artifact';

export interface DashboardStats {
  activeIncidents: number;
  containedHosts: number;
  criticalAlerts: number;
  evidenceCollected: number;
  avgDetectionTime: string;
  avgContainmentTime: string;
  automationSuccessRate: string;
}

export interface ThreatDetail {
  process: string;
  pid: number;
  processPath: string;
  targetDirectory: string;
  filesModified: number;
  filesLocked: number;
  ransomNote: string;
  detectionReasons: string[];
  riskBreakdown: { label: string; value: number }[];
}

export interface Incident {
  id: string;
  threatType: string;
  hostname: string;
  ipAddress: string;
  user: string;
  department: string;
  os: string;
  severity: Severity;
  riskScore: number;
  status: IncidentStatus;
  detectedAt: string;
  detectionEngine: string;
  agentStatus: AgentStatus;
  networkStatus: NetworkStatus;
  threatDetails?: ThreatDetail;
  timeline?: TimelineEvent[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  type: 'detection' | 'analysis' | 'action' | 'notification' | 'success' | 'evidence';
  automated: boolean;
}

export interface Endpoint {
  id: string;
  hostname: string;
  ipAddress: string;
  user: string;
  os: string;
  agentStatus: AgentStatus;
  riskScore: number;
  severity: Severity | 'none';
  networkStatus: NetworkStatus;
  lastSeen: string;
  department: string;
  incidentId?: string;
}

export interface EvidenceItem {
  id: string;
  incidentId: string;
  type: EvidenceType;
  source: string;
  size: string;
  sha256: string;
  collectedAt: string;
  integrity: EvidenceIntegrity;
  description: string;
  /** Forensic metadata (empty/undefined for legacy records where not established). */
  artifactName?: string;
  mimeType?: string;
  collectionMethod?: EvidenceCollectionMethod;
  collectedBy?: string;
  sizeBytes?: number;
  hasArtifact?: boolean;
}

export interface CustodyEntry {
  timestamp: string;
  action: string;
  actor: string;
  detail: string;
}

export interface EvidenceDetail extends EvidenceItem {
  custody: CustodyEntry[];
}

export interface ArtifactContent {
  evidenceId: string;
  artifactName: string;
  mimeType: string;
  content: string;
  binaryUnsupported: boolean;
}

export interface IntegrityVerification {
  evidenceId: string;
  integrity: EvidenceIntegrity;
  message: string;
}

export interface NotificationReadResult {
  updated: number;
  unread: number;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  timestamp: string;
  read: boolean;
  incidentId?: string;
}

export interface ActivityLogEntry {
  id: string;
  timestamp: string;
  event: string;
  actor: string;
  actorType: 'automation' | 'analyst' | 'agent';
  target: string;
  result: 'success' | 'failed' | 'pending';
  details: string;
}

export interface ResponseAction {
  id: string;
  label: string;
  description: string;
  icon: string;
  variant: 'default' | 'destructive' | 'outline';
  confirmRequired: boolean;
}

export interface ChartDataPoint {
  name: string;
  value: number;
}

/** Payload of GET /api/dashboard */
export interface DashboardData {
  stats: DashboardStats;
  incidentsOverTime: ChartDataPoint[];
  severityDistribution: ChartDataPoint[];
}

/** Result of an analyst response action (POST /api/incidents/{id}/...) */
export interface ActionResult {
  success: boolean;
  message: string;
}

/** Payload of GET /api/health */
export interface HealthStatus {
  status: string;
}
