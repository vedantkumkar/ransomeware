import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Bell, Search, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuLabel,
} from '@/components/ui/dropdown-menu';
import { ModeToggle } from '@/components/mode-toggle';
import { getNotifications, markAllNotificationsRead, markNotificationRead } from '@/services/api';
import type { Alert } from '@/types';
import { cn } from '@/lib/utils';

const pageTitles: Record<string, string> = {
  '/': 'Security Operations Overview',
  '/incidents': 'Security Incidents',
  '/endpoints': 'Endpoint Monitoring',
  '/evidence': 'Evidence & Forensics',
  '/activity': 'Activity Log',
  '/settings': 'Settings',
};

function severityDotClass(sev: string) {
  if (sev === 'critical') return 'bg-critical';
  if (sev === 'high') return 'bg-high';
  if (sev === 'medium') return 'bg-medium';
  return 'bg-info';
}

export function Topbar() {
  const location = useLocation();
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      getNotifications()
        .then((items) => {
          if (!cancelled) setAlerts(items);
        })
        .catch(() => {
          // notifications are non-critical; leave the dropdown empty on failure
        });
    };
    load();
    const interval = window.setInterval(load, 10000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const unread = alerts.filter((a) => !a.read).length;

  const title = Object.entries(pageTitles).find(([path]) =>
    path === '/' ? location.pathname === '/' : location.pathname.startsWith(path)
  )?.[1] ?? 'RansomGuard IR';

  // Read status is persisted through the API; the periodic poll returns the
  // persisted state, so unread count stays consistent across components/refresh.
  const markAllRead = () => {
    setAlerts((prev) => prev.map((a) => ({ ...a, read: true })));
    void markAllNotificationsRead().catch(() => {
      // server persistence failed — the next poll will restore server state
    });
  };

  const markRead = (id: string) => {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, read: true } : a)));
    void markNotificationRead(id).catch(() => {
      // server persistence failed — the next poll will restore server state
    });
  };

  return (
    <header className="flex items-center justify-between gap-3 px-4 h-[52px] border-b border-border bg-background/80 backdrop-blur-sm flex-shrink-0 sticky top-0 z-10">
      {/* Page title */}
      <div className="flex items-center gap-3 min-w-0">
        <h1 className="text-sm font-semibold text-foreground truncate tracking-tight">{title}</h1>
        <span className="hidden lg:inline-flex items-center gap-1 rounded-full border border-success/25 bg-success/[0.07] px-2 py-0.5 text-[10px] font-semibold text-success">
          <ShieldCheck className="size-3" />
          Systems Normal
        </span>
      </div>

      <div className="flex items-center gap-1.5 sm:gap-2">
        {/* Search */}
        <div className="relative hidden md:block">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search incidents, endpoints…"
            className="pl-8 h-8 w-60 text-xs bg-muted/50 border-border rounded-md focus-visible:ring-1"
          />
        </div>

        <Separator orientation="vertical" className="hidden md:block h-5" />

        {/* Theme toggle */}
        <ModeToggle />

        {/* Notifications */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="relative size-8 text-muted-foreground hover:text-foreground"
              aria-label={`Notifications${unread ? ` (${unread} unread)` : ''}`}
            >
              <Bell className="size-4" />
              {unread > 0 && (
                <span className="absolute -top-0.5 -right-0.5 flex size-4 items-center justify-center rounded-full bg-critical text-[9px] font-bold text-white tabular-nums">
                  {unread}
                </span>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-96 p-0">
            <DropdownMenuLabel className="flex items-center justify-between px-3 py-2.5 border-b border-border">
              <span className="text-xs font-semibold">Notifications</span>
              {unread > 0 && (
                <button
                  onClick={markAllRead}
                  className="text-[11px] text-primary hover:underline font-medium"
                >
                  Mark all read
                </button>
              )}
            </DropdownMenuLabel>
            <div className="max-h-80 overflow-y-auto">
              {alerts.length === 0 ? (
                <p className="px-3 py-8 text-center text-xs text-muted-foreground">No notifications</p>
              ) : (
                alerts.map((alert) => (
                  <DropdownMenuItem
                    key={alert.id}
                    className="flex items-start gap-2.5 py-3 px-3 cursor-pointer border-b border-border/40 last:border-0"
                    onClick={() => {
                      if (alert.incidentId) navigate(`/incidents/${alert.incidentId}`);
                      markRead(alert.id);
                    }}
                  >
                    <span
                      className={cn('mt-1.5 size-2 rounded-full flex-shrink-0', severityDotClass(alert.severity))}
                    />
                    <div className="min-w-0">
                      <p className={cn('text-xs leading-snug', !alert.read ? 'font-semibold text-foreground' : 'text-muted-foreground')}>
                        {alert.title}
                      </p>
                      <p className="text-[11px] text-muted-foreground mt-0.5">{alert.timestamp}</p>
                    </div>
                    {!alert.read && <span className="ml-auto size-1.5 rounded-full bg-primary flex-shrink-0 mt-1.5" />}
                  </DropdownMenuItem>
                ))
              )}
            </div>
          </DropdownMenuContent>
        </DropdownMenu>

        <Separator orientation="vertical" className="h-5" />

        {/* Analyst profile */}
        <Button
          variant="ghost"
          size="sm"
          className="gap-2 h-8 px-1.5 text-muted-foreground hover:text-foreground"
        >
          <div className="flex size-6 items-center justify-center rounded-full bg-primary/15 border border-primary/30 text-primary text-[10px] font-bold">
            SA
          </div>
          <span className="hidden md:inline text-xs font-medium">SOC Analyst</span>
        </Button>
      </div>
    </header>
  );
}
