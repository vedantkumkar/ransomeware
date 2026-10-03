/**
 * Central API service layer — the ONLY place the frontend talks to data.
 *
 * Pages/components must NOT import from `@/data/mockData` directly.
 *
 * Modes (see .env.example):
 * - VITE_USE_MOCK_API=true  (default) → serve local mock data; no backend needed.
 * - VITE_USE_MOCK_API=false           → issue real HTTP requests to the FastAPI
 *                                       backend at VITE_API_BASE_URL.
 *
 * Backend contract (FastAPI, not implemented yet):
 *   GET  /api/health
 *   GET  /api/dashboard
 *   GET  /api/incidents
 *   GET  /api/incidents/{incident_id}
 *   GET  /api/incidents/{incident_id}/evidence
 *   GET  /api/incidents/{incident_id}/timeline
 *   GET  /api/endpoints
 *   GET  /api/endpoints/{endpoint_id}
 *   GET  /api/evidence
 *   GET  /api/activity
 *   GET  /api/notifications
 *   POST /api/incidents/{incident_id}/isolate
 *   POST /api/incidents/{incident_id}/release
 *   POST /api/incidents/{incident_id}/suspend-user
 *   POST /api/incidents/{incident_id}/collect-evidence
 *   POST /api/incidents/{incident_id}/false-positive
 *   POST /api/incidents/{incident_id}/close
 *
 * The VM detector agent later reports detections via POST /api/events/detection.
 * That endpoint is intentionally NOT called by this frontend.
 */

import {
  incidents as mockIncidents,
  endpoints as mockEndpoints,
  evidence as mockEvidence,
  activityLog as mockActivityLog,
  notifications as mockNotifications,
  dashboardStats as mockDashboardStats,
  incidentsOverTime as mockIncidentsOverTime,
  severityDistribution as mockSeverityDistribution,
} from '@/data/mockData';
import type {
  Incident,
  Endpoint,
  EvidenceItem,
  EvidenceDetail,
  ArtifactContent,
  IntegrityVerification,
  NotificationReadResult,
  ManualEvidenceType,
  ActivityLogEntry,
  Alert,
  DashboardData,
  HealthStatus,
  TimelineEvent,
  ActionResult,
} from '@/types';

const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

// Absent or unrecognized VITE_USE_MOCK_API safely defaults to mock mode.
const USE_MOCK_API: boolean = import.meta.env.VITE_USE_MOCK_API !== 'false';

/** Exposed for diagnostics / future settings display (e.g. "Mock mode" badge). */
export const isMockMode = USE_MOCK_API;

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Minimal JSON request helper for real API mode. */
async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
    });
  } catch {
    throw new ApiError(`Cannot reach backend at ${API_BASE_URL}`, 0);
  }

  if (!response.ok) {
    let detail = response.statusText || 'Request failed';
    try {
      const body = await response.json();
      detail = body?.detail ?? body?.message ?? detail;
    } catch {
      // non-JSON error body — keep statusText
    }
    throw new ApiError(`${detail} (HTTP ${response.status})`, response.status);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function postAction(path: string): Promise<ActionResult> {
  const body = await request<{ message?: string } | null>(path, { method: 'POST' });
  return { success: true, message: body?.message ?? 'Action completed' };
}

async function postActionWithBody(path: string, json: unknown): Promise<ActionResult> {
  const body = await request<{ message?: string } | null>(path, {
    method: 'POST',
    body: JSON.stringify(json),
  });
  return { success: true, message: body?.message ?? 'Action completed' };
}

// ── Mock store ──────────────────────────────────────────────────────────────
// Mutable copies so analyst actions keep state consistent across navigation.

const mockStore = {
  incidents: [...mockIncidents],
  endpoints: [...mockEndpoints],
  evidence: [...mockEvidence],
  activityLog: [...mockActivityLog],
};

function findMockIncident(id: string): Incident | null {
  return mockStore.incidents.find((i) => i.id === id) ?? null;
}

interface IncidentActionSpec {
  path: string;
  patch: Partial<Incident>;
  event: string;
  details: (incident: Incident) => string;
}

/** Runs an analyst action: HTTP POST against the backend, or a safe mock simulation. */
async function runIncidentAction(incidentId: string, spec: IncidentActionSpec): Promise<ActionResult> {
  if (USE_MOCK_API) {
    await delay(400);
    const incident = findMockIncident(incidentId);
    if (!incident) return { success: false, message: `Incident ${incidentId} not found` };

    mockStore.incidents = mockStore.incidents.map((i) =>
      i.id === incidentId ? { ...i, ...spec.patch } : i,
    );
    mockStore.activityLog = [
      {
        id: `act-local-${Date.now()}`,
        timestamp: new Date().toISOString(),
        event: spec.event,
        actor: 'SOC Analyst',
        actorType: 'analyst',
        target: incidentId,
        result: 'success',
        details: spec.details(incident),
      },
      ...mockStore.activityLog,
    ];
    return { success: true, message: spec.details(incident) };
  }

  return postAction(spec.path);
}

// ── Health ───────────────────────────────────────────────────────────────────

export async function getHealth(): Promise<HealthStatus> {
  if (USE_MOCK_API) return { status: 'mock' };
  return request<HealthStatus>('/api/health');
}

// ── Dashboard ────────────────────────────────────────────────────────────────

export async function getDashboard(): Promise<DashboardData> {
  if (USE_MOCK_API) {
    await delay(200);
    return {
      stats: mockDashboardStats,
      incidentsOverTime: mockIncidentsOverTime,
      severityDistribution: mockSeverityDistribution,
    };
  }
  return request<DashboardData>('/api/dashboard');
}

// ── Incidents ────────────────────────────────────────────────────────────────

export async function getIncidents(): Promise<Incident[]> {
  if (USE_MOCK_API) {
    await delay(200);
    return mockStore.incidents;
  }
  return request<Incident[]>('/api/incidents');
}

export async function getIncidentById(id: string): Promise<Incident | null> {
  if (USE_MOCK_API) {
    await delay(150);
    return findMockIncident(id);
  }
  try {
    return await request<Incident>(`/api/incidents/${encodeURIComponent(id)}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export async function getIncidentTimeline(id: string): Promise<TimelineEvent[]> {
  if (USE_MOCK_API) {
    await delay(150);
    return findMockIncident(id)?.timeline ?? [];
  }
  return request<TimelineEvent[]>(`/api/incidents/${encodeURIComponent(id)}/timeline`);
}

// ── Analyst actions (simulated in mock mode) ─────────────────────────────────

export function isolateHost(incidentId: string): Promise<ActionResult> {
  return runIncidentAction(incidentId, {
    path: `/api/incidents/${incidentId}/isolate`,
    patch: { networkStatus: 'isolated' },
    event: 'Host Isolated',
    details: (inc) => `Host isolation simulated for ${inc.hostname}`,
  });
}

export function releaseHost(incidentId: string): Promise<ActionResult> {
  return runIncidentAction(incidentId, {
    path: `/api/incidents/${incidentId}/release`,
    patch: { networkStatus: 'connected' },
    event: 'Host Released',
    details: (inc) => `Host release simulated successfully for ${inc.hostname}`,
  });
}

export function suspendUser(incidentId: string): Promise<ActionResult> {
  return runIncidentAction(incidentId, {
    path: `/api/incidents/${incidentId}/suspend-user`,
    patch: {},
    event: 'User Account Suspended',
    details: (inc) => `User suspension simulated for ${inc.user}`,
  });
}

export function collectEvidence(incidentId: string, payload?: {
  evidenceType: ManualEvidenceType;
  content?: string;
}): Promise<ActionResult> {
  if (USE_MOCK_API) {
    return runIncidentAction(incidentId, {
      path: `/api/incidents/${incidentId}/collect-evidence`,
      patch: {},
      event: 'Evidence Collected',
      details: (inc) => `Evidence collection simulated for ${inc.id}`,
    });
  }
  return postActionWithBody(
    `/api/incidents/${incidentId}/collect-evidence`,
    payload ?? { evidenceType: 'windows_event_logs' },
  );
}

export function markFalsePositive(incidentId: string): Promise<ActionResult> {
  return runIncidentAction(incidentId, {
    path: `/api/incidents/${incidentId}/false-positive`,
    patch: { status: 'false_positive' },
    event: 'Incident Marked False Positive',
    details: (inc) => `${inc.id} marked as false positive`,
  });
}

export function closeIncident(incidentId: string): Promise<ActionResult> {
  return runIncidentAction(incidentId, {
    path: `/api/incidents/${incidentId}/close`,
    patch: { status: 'resolved' },
    event: 'Incident Closed',
    details: (inc) => `${inc.id} closed successfully`,
  });
}

// ── Endpoints ────────────────────────────────────────────────────────────────

export async function getEndpoints(): Promise<Endpoint[]> {
  if (USE_MOCK_API) {
    await delay(200);
    return mockStore.endpoints;
  }
  return request<Endpoint[]>('/api/endpoints');
}

export async function getEndpointById(id: string): Promise<Endpoint | null> {
  if (USE_MOCK_API) {
    await delay(150);
    return mockStore.endpoints.find((e) => e.id === id) ?? null;
  }
  try {
    return await request<Endpoint>(`/api/endpoints/${encodeURIComponent(id)}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

// ── Evidence ─────────────────────────────────────────────────────────────────

export async function getEvidence(): Promise<EvidenceItem[]> {
  if (USE_MOCK_API) {
    await delay(200);
    return mockStore.evidence;
  }
  return request<EvidenceItem[]>('/api/evidence');
}

export async function getIncidentEvidence(incidentId: string): Promise<EvidenceItem[]> {
  if (USE_MOCK_API) {
    await delay(150);
    return mockStore.evidence.filter((e) => e.incidentId === incidentId);
  }
  return request<EvidenceItem[]>(`/api/incidents/${incidentId}/evidence`);
}

/** Full evidence record incl. chain-of-custody history. */
export async function getEvidenceDetail(evidenceId: string): Promise<EvidenceDetail> {
  return request<EvidenceDetail>(`/api/evidence/${encodeURIComponent(evidenceId)}`);
}

/** The actual stored artifact (text view — artifacts are never executed). */
export async function getEvidenceArtifact(evidenceId: string): Promise<ArtifactContent> {
  return request<ArtifactContent>(`/api/evidence/${encodeURIComponent(evidenceId)}/artifact`);
}

/** Recalculate SHA-256 from the stored artifact and compare with the recorded hash. */
export async function verifyEvidenceIntegrity(evidenceId: string): Promise<IntegrityVerification> {
  return request<IntegrityVerification>(`/api/evidence/${encodeURIComponent(evidenceId)}/verify`, {
    method: 'POST',
  });
}

// ── Activity Log ─────────────────────────────────────────────────────────────

export async function getActivityLog(): Promise<ActivityLogEntry[]> {
  if (USE_MOCK_API) {
    await delay(200);
    return mockStore.activityLog;
  }
  return request<ActivityLogEntry[]>('/api/activity');
}

// ── Notifications ────────────────────────────────────────────────────────────

export async function getNotifications(): Promise<Alert[]> {
  if (USE_MOCK_API) {
    await delay(150);
    return mockNotifications;
  }
  return request<Alert[]>('/api/notifications');
}

/** Persist read status for one notification (unread count derives from state). */
export async function markNotificationRead(notificationId: string): Promise<NotificationReadResult> {
  if (USE_MOCK_API) {
    await delay(80);
    return { updated: 1, unread: 0 };
  }
  return request<NotificationReadResult>(
    `/api/notifications/${encodeURIComponent(notificationId)}/read`,
    { method: 'POST' },
  );
}

/** Persist read status for every notification. */
export async function markAllNotificationsRead(): Promise<NotificationReadResult> {
  if (USE_MOCK_API) {
    await delay(80);
    return { updated: 0, unread: 0 };
  }
  return request<NotificationReadResult>('/api/notifications/mark-all-read', { method: 'POST' });
}
