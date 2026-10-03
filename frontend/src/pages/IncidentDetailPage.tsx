import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Monitor,
  Cpu,
  FileWarning,
  ShieldCheck,
  ShieldAlert,
  UserX,
  FolderSearch,
  CheckCircle2,
  Clock,
  Zap,
  Network,
  User,
  Building2,
  HardDrive,
  FileText,
  Lock,
  AlertCircle,
  Ban,
  PlayCircle,
  Sparkles,
  Database,
  Fingerprint,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { SeverityBadge, StatusBadge, NetworkBadge, AgentBadge, IntegrityBadge } from '@/components/badges';
import { EvidenceDetailDialog } from '@/components/EvidenceDetailDialog';
import { RiskScore } from '@/components/risk-score';
import { DataError, DataLoading } from '@/components/states';
import {
  getIncidentById,
  getIncidentEvidence,
  isolateHost,
  releaseHost,
  suspendUser,
  collectEvidence,
  markFalsePositive,
  closeIncident,
} from '@/services/api';
import { useApiData } from '@/hooks/use-api-data';
import type { Incident, ActionResult, ManualEvidenceType } from '@/types';
import { computeResponseSeconds, cn } from '@/lib/utils';
import { toast } from 'sonner';

interface PendingAction {
  label: string;
  message: string;
}

const actionApi: Record<string, (incidentId: string) => Promise<ActionResult>> = {
  'Isolate Host': isolateHost,
  'Release Host': releaseHost,
  'Suspend User': suspendUser,
  'Mark False Positive': markFalsePositive,
  'Close Incident': closeIncident,
};

/** Manual evidence collection options — only types the backend genuinely supports. */
const collectionTypes: { value: ManualEvidenceType; label: string; hint: string }[] = [
  { value: 'windows_event_logs', label: 'Windows Event Logs', hint: 'Live extract from the backend host event log' },
  { value: 'process_snapshot', label: 'Process Snapshot', hint: 'Live process listing captured at collection time' },
  { value: 'file_manifest', label: 'File / Directory Manifest', hint: 'Fresh scan of the incident target directory' },
  { value: 'text_artifact', label: 'Selected Text / Log Artifact', hint: 'Store pasted log or text content' },
];

const timelineIcons = {
  detection: { Icon: AlertCircle, color: 'text-info', bg: 'bg-info/15 border-info/30' },
  analysis: { Icon: Cpu, color: 'text-medium', bg: 'bg-medium/15 border-medium/30' },
  action: { Icon: Zap, color: 'text-warning', bg: 'bg-warning/15 border-warning/30' },
  success: { Icon: CheckCircle2, color: 'text-success', bg: 'bg-success/15 border-success/30' },
  evidence: { Icon: FolderSearch, color: 'text-primary', bg: 'bg-primary/15 border-primary/30' },
  notification: { Icon: Sparkles, color: 'text-primary', bg: 'bg-primary/15 border-primary/30' },
};

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data, loading, error, retry } = useApiData(() => getIncidentById(id ?? ''), [id], { pollMs: 5000 });
  const { data: evidence, loading: evidenceLoading, error: evidenceError, retry: retryEvidence } = useApiData(
    () => getIncidentEvidence(id ?? ''),
    [id],
  );
  const [incident, setIncident] = useState<Incident | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [actionPending, setActionPending] = useState<string | null>(null);
  // Manual evidence collection modal state
  const [collectOpen, setCollectOpen] = useState(false);
  const [collectType, setCollectType] = useState<ManualEvidenceType>('windows_event_logs');
  const [collectText, setCollectText] = useState('');
  const [collecting, setCollecting] = useState(false);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);

  useEffect(() => {
    setIncident(data);
  }, [data]);

  if (loading) {
    return (
      <div className="p-6 max-w-[1600px] mx-auto">
        <DataLoading rows={6} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 max-w-[1600px] mx-auto">
        <DataError message={error} onRetry={retry} />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="p-6 max-w-[1600px] mx-auto">
        <div className="flex flex-col items-center justify-center py-20">
          <AlertCircle className="size-10 text-muted-foreground/50 mb-3" />
          <p className="text-sm text-muted-foreground mb-3">Incident not found</p>
          <Button variant="outline" size="sm" onClick={() => navigate('/incidents')}>
            <ArrowLeft className="size-4" /> Back to Incidents
          </Button>
        </div>
      </div>
    );
  }

  const td = incident.threatDetails;
  const timeline = incident.timeline ?? [];
  const responseSeconds = computeResponseSeconds(timeline);
  const evidenceItems = evidence ?? [];

  const confirmMessages: Record<string, string> = {
    'Isolate Host': `Isolate ${incident.hostname} from the network? This will block all inbound and outbound traffic.`,
    'Release Host': `Release ${incident.hostname} from network isolation? The host will regain network access.`,
    'Suspend User': `Suspend user account ${incident.user}? All active sessions will be revoked.`,
    'Mark False Positive': `Mark incident ${incident.id} as a false positive? This will close the incident.`,
    'Close Incident': `Close incident ${incident.id}? This action cannot be undone.`,
  };

  const openCollectModal = () => {
    setCollectType('windows_event_logs');
    setCollectText('');
    setCollectOpen(true);
  };

  const submitCollection = async () => {
    setCollecting(true);
    try {
      const result = await collectEvidence(incident.id, {
        evidenceType: collectType,
        content: collectText,
      });
      toast.success(result.message);
      setCollectOpen(false);
      retryEvidence();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Evidence collection failed');
    } finally {
      setCollecting(false);
    }
  };

  const handleAction = (label: string) => {
    setPendingAction({ label, message: confirmMessages[label] ?? `${label}?` });
  };

  const confirmAction = async () => {
    if (!pendingAction) return;
    const label = pendingAction.label;
    const apiCall = actionApi[label];
    setActionPending(label);
    try {
      const result = apiCall
        ? await apiCall(incident.id)
        : { success: false, message: 'Unknown action' };
      if (result.success) {
        toast.success(result.message);
        if (label === 'Release Host') {
          setIncident({ ...incident, networkStatus: 'connected' });
        } else if (label === 'Isolate Host') {
          setIncident({ ...incident, networkStatus: 'isolated' });
        } else if (label === 'Mark False Positive') {
          setIncident({ ...incident, status: 'false_positive' });
        } else if (label === 'Close Incident') {
          setIncident({ ...incident, status: 'resolved' });
        }
      } else {
        toast.error(result.message);
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Action failed');
    } finally {
      setActionPending(null);
      setPendingAction(null);
    }
  };

  const actions = [
    { label: 'Isolate Host', icon: ShieldAlert, variant: 'destructive' as const, disabled: incident.networkStatus === 'isolated' },
    { label: 'Release Host', icon: ShieldCheck, variant: 'outline' as const, disabled: incident.networkStatus === 'connected' },
    { label: 'Suspend User', icon: UserX, variant: 'outline' as const },
    { label: 'Collect Evidence', icon: FolderSearch, variant: 'outline' as const, modal: true },
    { label: 'Mark False Positive', icon: Ban, variant: 'outline' as const },
    { label: 'Close Incident', icon: CheckCircle2, variant: 'outline' as const, disabled: incident.status === 'resolved' },
  ];

  return (
    <div className="p-6 space-y-5 max-w-[1600px] mx-auto">
      {/* Back link */}
      <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-foreground -ml-2" onClick={() => navigate('/incidents')}>
        <ArrowLeft className="size-4" /> Back to Incidents
      </Button>

      {/* Incident header band */}
      <Card className="bg-card border-border relative overflow-hidden">
        {incident.severity === 'critical' && (
          <div className="absolute top-0 inset-x-0 h-0.5 bg-gradient-to-r from-critical/70 via-critical to-critical/70" />
        )}
        <CardContent className="p-5">
          <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
            <div className="space-y-3 min-w-0">
              <div className="flex items-center gap-2.5 flex-wrap">
                <h2 className="text-xl font-bold text-foreground font-mono tracking-tight">{incident.id}</h2>
                <SeverityBadge severity={incident.severity} />
                <StatusBadge status={incident.status} />
                <NetworkBadge status={incident.networkStatus} />
                <AgentBadge status={incident.agentStatus} />
              </div>
              <div className="text-base font-semibold text-foreground">{incident.threatType}</div>
              <div className="flex items-center gap-4 flex-wrap text-xs text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <Cpu className="size-3.5" /> {incident.detectionEngine}
                </span>
                <span className="flex items-center gap-1.5">
                  <Clock className="size-3.5" />
                  {new Date(incident.detectedAt).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' })} •{' '}
                  {new Date(incident.detectedAt).toLocaleTimeString('en-US', { hour12: false })}
                </span>
                <span className="flex items-center gap-1.5 font-mono">
                  <Monitor className="size-3.5" /> {incident.hostname}
                </span>
                <span className="flex items-center gap-1.5 font-mono">
                  <Network className="size-3.5" /> {incident.ipAddress}
                </span>
                <span className="flex items-center gap-1.5">
                  <User className="size-3.5" /> {incident.user}
                </span>
              </div>
            </div>
            <RiskScore score={incident.riskScore} size="lg" />
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Left column: details in tabs */}
        <div className="xl:col-span-2 min-w-0">
          <Tabs defaultValue="overview" className="space-y-4">
            <TabsList className="bg-card border border-border h-10 p-1">
              <TabsTrigger value="overview" className="text-xs gap-1.5 data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
                <FileText className="size-3.5" /> Overview
              </TabsTrigger>
              <TabsTrigger value="timeline" className="text-xs gap-1.5 data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
                <Zap className="size-3.5" /> Timeline
                {timeline.length > 0 && (
                  <span className="ml-1 rounded-full bg-muted px-1.5 text-[10px] tabular-nums text-muted-foreground">
                    {timeline.length}
                  </span>
                )}
              </TabsTrigger>
              <TabsTrigger value="evidence" className="text-xs gap-1.5 data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
                <Database className="size-3.5" /> Evidence
                {evidenceItems.length > 0 && (
                  <span className="ml-1 rounded-full bg-muted px-1.5 text-[10px] tabular-nums text-muted-foreground">
                    {evidenceItems.length}
                  </span>
                )}
              </TabsTrigger>
            </TabsList>

            {/* ── Overview tab ── */}
            <TabsContent value="overview" className="space-y-4 mt-0">
              <Card className="bg-card border-border">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Monitor className="size-4 text-primary" /> Affected Endpoint
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                    {[
                      { label: 'Hostname', value: incident.hostname, icon: Monitor },
                      { label: 'IP Address', value: incident.ipAddress, icon: Network },
                      { label: 'Operating System', value: incident.os, icon: HardDrive },
                      { label: 'User', value: incident.user, icon: User },
                      { label: 'Department', value: incident.department, icon: Building2 },
                    ].map(({ label, value, icon: Icon }) => (
                      <div key={label} className="space-y-1">
                        <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium flex items-center gap-1">
                          <Icon className="size-3" /> {label}
                        </p>
                        <p className="text-sm font-medium text-foreground font-mono">{value}</p>
                      </div>
                    ))}
                    <div className="space-y-1">
                      <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Agent Status</p>
                      <AgentBadge status={incident.agentStatus} />
                    </div>
                    <div className="space-y-1">
                      <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Network Status</p>
                      <NetworkBadge status={incident.networkStatus} />
                    </div>
                  </div>
                </CardContent>
              </Card>

              {td && (
                <Card className="bg-card border-border">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <FileWarning className="size-4 text-high" /> Threat Details
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                      {[
                        { label: 'Process', value: td.process, icon: Cpu },
                        { label: 'PID', value: String(td.pid), icon: Cpu },
                        { label: 'Process Path', value: td.processPath, icon: HardDrive, span: true },
                        { label: 'Target Directory', value: td.targetDirectory, icon: FolderSearch, span: true },
                        { label: 'Files Modified', value: String(td.filesModified), icon: FileText },
                        { label: 'Locked Files', value: String(td.filesLocked), icon: Lock },
                        { label: 'Ransom Note', value: td.ransomNote || '—', icon: FileText },
                      ].map(({ label, value, icon: Icon, span }) => (
                        <div key={label} className={cn('space-y-1', span && 'sm:col-span-2 xl:col-span-3')}>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium flex items-center gap-1">
                            <Icon className="size-3" /> {label}
                          </p>
                          <p className="text-sm font-medium text-foreground font-mono break-all">{value}</p>
                        </div>
                      ))}
                    </div>

                    <div className="pt-3 border-t border-border">
                      <p className="text-xs font-semibold text-foreground mb-2">Detection Reasons</p>
                      <div className="space-y-1.5">
                        {td.detectionReasons.map((reason, i) => (
                          <div key={i} className="flex items-center gap-2">
                            <CheckCircle2 className="size-3.5 text-success flex-shrink-0" />
                            <span className="text-xs text-muted-foreground">{reason}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {td && (
                <Card className="bg-card border-border">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <ShieldAlert className="size-4 text-critical" /> Risk Score Breakdown
                    </CardTitle>
                    <CardDescription>Total: {incident.riskScore}/100 — CRITICAL</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {td.riskBreakdown.map((item) => (
                      <div key={item.label} className="flex items-center gap-3">
                        <span className="text-xs text-muted-foreground w-40 flex-shrink-0">{item.label}</span>
                        <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                          <div
                            className={cn(
                              'h-full rounded-full',
                              item.value >= 25 ? 'bg-critical' : item.value >= 15 ? 'bg-high' : 'bg-medium'
                            )}
                            style={{ width: `${(item.value / 35) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs font-semibold text-foreground tabular-nums w-10 text-right">+{item.value}</span>
                      </div>
                    ))}
                    <div className="flex items-center justify-between pt-3 border-t border-border">
                      <span className="text-sm font-semibold text-foreground">Total Risk Score</span>
                      <span className="text-lg font-bold text-critical tabular-nums">{incident.riskScore}/100</span>
                    </div>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            {/* ── Timeline tab ── */}
            <TabsContent value="timeline" className="mt-0">
              <Card className="bg-card border-border">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <Zap className="size-4 text-primary" /> Automated Response Timeline
                    </CardTitle>
                    <span className="text-xs text-muted-foreground">
                      Total: <span className="font-semibold text-success">{responseSeconds != null ? `${responseSeconds.toFixed(1)}s` : '—'}</span>
                    </span>
                  </div>
                </CardHeader>
                <CardContent>
                  {timeline.length === 0 ? (
                    <p className="py-10 text-center text-sm text-muted-foreground">No timeline events recorded for this incident.</p>
                  ) : (
                    <div className="relative space-y-0">
                      {timeline.map((event, idx) => {
                        const config = timelineIcons[event.type];
                        const { Icon, color, bg } = config;
                        const isLast = idx === timeline.length - 1;
                        return (
                          <div key={event.id} className="flex gap-3.5 pb-5 relative last:pb-0">
                            {!isLast && <div className="absolute left-[15px] top-8 bottom-0 w-px bg-border" />}
                            <div className={cn('relative flex size-8 items-center justify-center rounded-full border flex-shrink-0 z-10', bg)}>
                              <Icon className={cn('size-4', color)} />
                            </div>
                            <div className="flex-1 min-w-0 pt-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm font-medium text-foreground">{event.title}</span>
                                {event.automated && (
                                  <span className="text-[10px] font-semibold text-primary bg-primary/10 px-1.5 py-0.5 rounded uppercase tracking-wider">
                                    Auto
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{event.description}</p>
                              <p className="text-[11px] text-muted-foreground/70 font-mono mt-1">{event.timestamp}</p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* ── Evidence tab ── */}
            <TabsContent value="evidence" className="mt-0">
              <Card className="bg-card border-border">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Database className="size-4 text-primary" /> Collected Evidence
                  </CardTitle>
                  <CardDescription>Forensic artifacts with chain-of-custody verification</CardDescription>
                </CardHeader>
                <CardContent>
                  {evidenceLoading ? (
                    <DataLoading rows={4} />
                  ) : evidenceError ? (
                    <DataError message={evidenceError} onRetry={retryEvidence} />
                  ) : evidenceItems.length === 0 ? (
                    <p className="py-10 text-center text-sm text-muted-foreground">No evidence collected for this incident yet.</p>
                  ) : (
                    <div className="space-y-3">
                      {evidenceItems.map((ev) => (
                        <button
                          key={ev.id}
                          type="button"
                          onClick={() => setSelectedEvidenceId(ev.id)}
                          className="w-full text-left rounded-lg border border-border bg-muted/20 p-3.5 space-y-2.5 hover:border-primary/40 transition-colors cursor-pointer"
                        >
                          <div className="flex items-center justify-between gap-3 flex-wrap">
                            <div className="flex items-center gap-2.5 min-w-0">
                              <div className="flex size-8 items-center justify-center rounded-md bg-primary/10 border border-primary/25 flex-shrink-0">
                                <Fingerprint className="size-4 text-primary" />
                              </div>
                              <div className="min-w-0">
                                <p className="text-xs font-semibold text-foreground font-mono">{ev.id}</p>
                                <p className="text-[11px] text-muted-foreground">{ev.description}</p>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                              <span
                                className={cn(
                                  'rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider border',
                                  ev.collectionMethod === 'automated'
                                    ? 'bg-info/10 text-info border-info/30'
                                    : 'bg-primary/10 text-primary border-primary/30',
                                )}
                              >
                                {ev.collectionMethod}
                              </span>
                              <IntegrityBadge integrity={ev.integrity} withTooltip />
                            </div>
                          </div>
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-4 gap-y-2 text-[11px]">
                            <div>
                              <p className="text-muted-foreground uppercase tracking-wider text-[9px] font-medium">Type</p>
                              <p className="text-foreground mt-0.5">{ev.type.replace(/_/g, ' ')}</p>
                            </div>
                            <div>
                              <p className="text-muted-foreground uppercase tracking-wider text-[9px] font-medium">Source</p>
                              <p className="text-foreground font-mono mt-0.5">{ev.source}</p>
                            </div>
                            <div>
                              <p className="text-muted-foreground uppercase tracking-wider text-[9px] font-medium">Size</p>
                              <p className="text-foreground tabular-nums mt-0.5">{ev.size}</p>
                            </div>
                            <div>
                              <p className="text-muted-foreground uppercase tracking-wider text-[9px] font-medium">Collected</p>
                              <p className="text-foreground tabular-nums mt-0.5">
                                {new Date(ev.collectedAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                                {' • '}
                                {new Date(ev.collectedAt).toLocaleTimeString('en-US', { hour12: false })}
                              </p>
                            </div>
                          </div>
                          <div>
                            <p className="text-muted-foreground uppercase tracking-wider text-[9px] font-medium">SHA-256</p>
                            <p className="text-[11px] font-mono text-muted-foreground mt-0.5 break-all bg-muted/50 rounded px-2 py-1 border border-border/60">
                              {ev.sha256 || 'Not captured'}
                            </p>
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        {/* Right column: response actions + summary */}
        <div className="space-y-4">
          <Card className="bg-card border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <PlayCircle className="size-4 text-primary" /> Analyst Actions
              </CardTitle>
              <CardDescription>Simulated response controls — demo mode</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {actions.map(({ label, icon: Icon, variant, disabled, modal }) => (
                <Button
                  key={label}
                  variant={variant}
                  size="sm"
                  disabled={disabled || actionPending !== null || collecting}
                  onClick={() => (modal ? openCollectModal() : handleAction(label))}
                  className="w-full justify-start"
                >
                  <Icon className="size-4" />
                  {label}
                </Button>
              ))}
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Incident Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {[
                { label: 'Incident ID', value: incident.id },
                { label: 'Severity', value: incident.severity.toUpperCase() },
                { label: 'Risk Score', value: `${incident.riskScore}/100` },
                { label: 'Status', value: incident.status.replace('_', ' ') },
                { label: 'Endpoint', value: incident.hostname },
                { label: 'User', value: incident.user },
                { label: 'Engine', value: incident.detectionEngine },
              ].map(({ label, value }) => (
                <div key={label} className="flex items-center justify-between text-xs gap-3">
                  <span className="text-muted-foreground flex-shrink-0">{label}</span>
                  <span className="font-medium text-foreground capitalize text-right truncate">{value}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Confirmation dialog */}
      <AlertDialog open={!!pendingAction} onOpenChange={(open) => !open && setPendingAction(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <ShieldAlert className="size-5 text-warning" />
              Confirm Action
            </AlertDialogTitle>
            <AlertDialogDescription>{pendingAction?.message}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => { void confirmAction(); }}>
              {actionPending !== null ? 'Working…' : 'Confirm'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Manual evidence collection modal */}
      <Dialog open={collectOpen} onOpenChange={setCollectOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Collect Evidence</DialogTitle>
            <DialogDescription>
              Manual forensic collection — the artifact is acquired from a real source,
              hashed (SHA-256), and recorded with chain of custody.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Incident</p>
                <p className="font-mono text-foreground mt-0.5">{incident.id}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Endpoint</p>
                <p className="font-mono text-foreground mt-0.5">{incident.hostname}</p>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="evidence-type" className="text-xs">Evidence type</Label>
              <Select value={collectType} onValueChange={(v) => setCollectType(v as ManualEvidenceType)}>
                <SelectTrigger id="evidence-type" className="h-9 text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {collectionTypes.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-[10px] text-muted-foreground">
                {collectionTypes.find((t) => t.value === collectType)?.hint}
              </p>
            </div>
            {collectType === 'text_artifact' && (
              <div className="space-y-1.5">
                <Label htmlFor="evidence-text" className="text-xs">Artifact content</Label>
                <Textarea
                  id="evidence-text"
                  value={collectText}
                  onChange={(e) => setCollectText(e.target.value)}
                  placeholder="Paste the log or text content to preserve as evidence…"
                  className="min-h-28 font-mono text-xs"
                />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setCollectOpen(false)} disabled={collecting}>
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={() => void submitCollection()}
              disabled={collecting || (collectType === 'text_artifact' && !collectText.trim())}
            >
              <FolderSearch className="size-4" />
              {collecting ? 'Collecting…' : 'Collect Evidence'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rich evidence detail (Overview / Artifact / Chain of Custody) */}
      <EvidenceDetailDialog
        evidenceId={selectedEvidenceId}
        open={selectedEvidenceId !== null}
        onClose={() => setSelectedEvidenceId(null)}
        onVerified={retryEvidence}
      />
    </div>
  );
}
