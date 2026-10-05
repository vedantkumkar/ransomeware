import { useState } from 'react';
import { Settings as SettingsIcon, Cpu, Zap, Info, Shield, Palette, Sun, Moon, MonitorCog } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { useTheme } from '@/components/theme-provider';
import { cn } from '@/lib/utils';

type ThemeChoice = 'system' | 'light' | 'dark';

function AppearanceSection() {
  const { theme, setTheme } = useTheme();
  const options: { value: ThemeChoice; label: string; icon: typeof Sun; desc: string }[] = [
    { value: 'system', label: 'System', icon: MonitorCog, desc: 'Follow OS preference' },
    { value: 'light', label: 'Light', icon: Sun, desc: 'Bright SOC console' },
    { value: 'dark', label: 'Dark', icon: Moon, desc: 'Classic SOC night mode' },
  ];

  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Palette className="size-4 text-primary" /> Appearance
        </CardTitle>
        <CardDescription>Console theme — applies instantly and persists across refreshes</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-3 gap-3 max-w-md" role="radiogroup" aria-label="Theme">
          {options.map(({ value, label, icon: Icon, desc }) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={theme === value}
              onClick={() => setTheme(value)}
              className={cn(
                'flex flex-col items-center gap-1.5 rounded-lg border p-3 text-center transition-colors cursor-pointer',
                theme === value
                  ? 'border-primary/50 bg-primary/10 text-primary'
                  : 'border-border bg-muted/30 text-muted-foreground hover:border-primary/30 hover:text-foreground'
              )}
            >
              <Icon className="size-4" />
              <span className="text-xs font-semibold">{label}</span>
              <span className="text-[10px] leading-tight opacity-80">{desc}</span>
            </button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export default function SettingsPage() {
  const [autoIsolate, setAutoIsolate] = useState(true);
  const [autoSuspend, setAutoSuspend] = useState(true);
  const [autoCollect, setAutoCollect] = useState(true);
  const [autoNotify, setAutoNotify] = useState(true);

  const [fileThreshold, setFileThreshold] = useState('20');
  const [detectionInterval, setDetectionInterval] = useState('5');
  const [criticalThreshold, setCriticalThreshold] = useState('85');

  return (
    <div className="p-6 space-y-4 max-w-3xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-foreground tracking-tight">Settings</h2>
        <p className="text-sm text-muted-foreground mt-1">Platform configuration and detection policy</p>
      </div>

      <AppearanceSection />

      <Alert className="border-warning/30 bg-warning/[0.07]">
        <Info className="size-4 text-warning" />
        <AlertTitle className="text-warning">Demo Configuration</AlertTitle>
        <AlertDescription className="text-warning/80">
          Backend policy synchronization will be connected later. Changes here are stored in local state only.
        </AlertDescription>
      </Alert>

      {/* System */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <SettingsIcon className="size-4 text-primary" /> System
          </CardTitle>
          <CardDescription>Platform identity and connection settings</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="platform-name" className="text-xs">Platform Name</Label>
              <Input id="platform-name" defaultValue="RansomGuard IR" className="h-9 text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="demo-mode" className="text-xs">Demo Mode</Label>
              <div className="flex items-center gap-2 h-9">
                <Badge className="bg-success/10 text-success border-success/30">Enabled</Badge>
              </div>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="api-url" className="text-xs">API Base URL</Label>
            <Input id="api-url" placeholder="http://localhost:8000" className="h-9 text-sm font-mono" defaultValue="http://localhost:8000" />
            <p className="text-[10px] text-muted-foreground">Future FastAPI backend endpoint — set via VITE_API_BASE_URL</p>
          </div>
        </CardContent>
      </Card>

      {/* Detection Policy */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Cpu className="size-4 text-primary" /> Detection Policy
          </CardTitle>
          <CardDescription>Behavioral detection thresholds and intervals</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="file-threshold" className="text-xs">File Modification Threshold</Label>
              <Input
                id="file-threshold"
                type="number"
                value={fileThreshold}
                onChange={(e) => setFileThreshold(e.target.value)}
                className="h-9 text-sm"
              />
              <p className="text-[10px] text-muted-foreground">files per interval</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="detection-interval" className="text-xs">Detection Interval</Label>
              <Input
                id="detection-interval"
                type="number"
                value={detectionInterval}
                onChange={(e) => setDetectionInterval(e.target.value)}
                className="h-9 text-sm"
              />
              <p className="text-[10px] text-muted-foreground">seconds</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="critical-threshold" className="text-xs">Critical Risk Threshold</Label>
              <Input
                id="critical-threshold"
                type="number"
                value={criticalThreshold}
                onChange={(e) => setCriticalThreshold(e.target.value)}
                className="h-9 text-sm"
              />
              <p className="text-[10px] text-muted-foreground">risk score (0-100)</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Automation Policy */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Zap className="size-4 text-primary" /> Automation Policy
          </CardTitle>
          <CardDescription>Automatic response actions when critical incidents are detected</CardDescription>
        </CardHeader>
        <CardContent className="space-y-1">
          {[
            { label: 'Auto Isolate Host', desc: 'Automatically isolate affected endpoint from network', checked: autoIsolate, setter: setAutoIsolate },
            { label: 'Auto Suspend User', desc: 'Suspend user account and revoke active sessions', checked: autoSuspend, setter: setAutoSuspend },
            { label: 'Auto Collect Evidence', desc: 'Trigger forensic evidence collection automatically', checked: autoCollect, setter: setAutoCollect },
            { label: 'Auto Notify SOC', desc: 'Send real-time notification to SOC analysts', checked: autoNotify, setter: setAutoNotify },
          ].map(({ label, desc, checked, setter }) => (
            <div key={label} className="flex items-center justify-between py-3 border-b border-border/50 last:border-0">
              <div className="pr-4">
                <p className="text-sm font-medium text-foreground">{label}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
              </div>
              <Switch checked={checked} onCheckedChange={setter} />
            </div>
          ))}
        </CardContent>
      </Card>

      <div className="flex items-center gap-2 text-xs text-muted-foreground pt-2">
        <Shield className="size-3.5" />
        RansomGuard IR v1.0 Demo — frontend-only configuration
      </div>
    </div>
  );
}
