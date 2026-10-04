import { Link, useLocation } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  AlertTriangle,
  Monitor,
  FolderSearch,
  ScrollText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Radar,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { path: '/endpoints', label: 'Endpoints', icon: Monitor },
  { path: '/evidence', label: 'Evidence', icon: FolderSearch },
  { path: '/activity', label: 'Activity Log', icon: ScrollText },
  { path: '/settings', label: 'Settings', icon: Settings },
];

interface AppSidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function AppSidebar({ collapsed, onToggle }: AppSidebarProps) {
  const location = useLocation();

  return (
    <aside
      className={cn(
        'relative flex flex-col h-screen bg-sidebar border-r border-sidebar-border transition-all duration-200 ease-in-out flex-shrink-0 z-20',
        collapsed ? 'w-14' : 'w-60'
      )}
    >
      {/* Logo */}
      <div
        className={cn(
          'flex items-center gap-2.5 px-3.5 h-[52px] border-b border-sidebar-border flex-shrink-0',
          collapsed && 'justify-center px-2'
        )}
      >
        <div className="relative flex size-8 items-center justify-center rounded-lg bg-gradient-to-br from-primary/25 to-primary/5 border border-primary/30 flex-shrink-0">
          <Shield className="size-4 text-primary" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <div className="text-sm font-bold text-sidebar-foreground leading-none tracking-tight">
              RansomGuard <span className="text-primary">IR</span>
            </div>
            <div className="text-[10px] text-muted-foreground mt-1 uppercase tracking-wider">
              Incident Response Platform
            </div>
          </div>
        )}
      </div>

      {/* Nav */}
      <TooltipProvider delayDuration={200}>
        <nav className={cn('flex-1 overflow-y-auto py-4 space-y-1', collapsed ? 'px-2' : 'px-2.5')}>
          {!collapsed && (
            <p className="px-2 pb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
              Operations
            </p>
          )}
          {navItems.map(({ path, label, icon: Icon }) => {
            const isActive = path === '/' ? location.pathname === '/' : location.pathname.startsWith(path);
            const link = (
              <Link key={path} to={path} className="block" aria-current={isActive ? 'page' : undefined}>
                <div
                  className={cn(
                    'relative flex items-center gap-3 rounded-md px-2.5 py-2 text-[13px] font-medium transition-colors cursor-pointer group',
                    collapsed && 'justify-center px-2',
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-sidebar-foreground/65 hover:bg-sidebar-accent hover:text-sidebar-foreground'
                  )}
                >
                  {isActive && (
                    <span className="absolute left-0 top-1/2 -translate-y-1/2 h-4 w-0.5 rounded-full bg-primary" />
                  )}
                  <Icon
                    className={cn(
                      'size-4 flex-shrink-0 transition-colors',
                      isActive ? 'text-primary' : 'text-muted-foreground group-hover:text-sidebar-foreground'
                    )}
                  />
                  {!collapsed && <span className="truncate">{label}</span>}
                  {!collapsed && isActive && (
                    <span className="ml-auto size-1.5 rounded-full bg-primary flex-shrink-0" />
                  )}
                </div>
              </Link>
            );
            return collapsed ? (
              <Tooltip key={path}>
                <TooltipTrigger asChild>{link}</TooltipTrigger>
                <TooltipContent side="right" sideOffset={8}>
                  {label}
                </TooltipContent>
              </Tooltip>
            ) : (
              link
            );
          })}
        </nav>
      </TooltipProvider>

      {/* Footer — orchestrator status */}
      <div className={cn('px-2.5 py-3.5 border-t border-sidebar-border flex-shrink-0', collapsed && 'flex justify-center')}>
        <div
          className={cn(
            'flex items-center gap-2.5 rounded-md px-2 py-1.5 bg-success/[0.07] border border-success/20',
            collapsed && 'px-1.5'
          )}
        >
          <span className="relative flex size-2 flex-shrink-0">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-60" />
            <span className="relative inline-flex rounded-full size-2 bg-success" />
          </span>
          {!collapsed && (
            <div className="min-w-0">
              <div className="text-[11px] font-semibold text-success leading-none">Orchestrator Online</div>
              <div className="text-[9px] text-muted-foreground mt-1 flex items-center gap-1">
                <Radar className="size-2.5" /> v1.0 Demo
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Collapse toggle */}
      <Button
        variant="outline"
        size="icon"
        onClick={onToggle}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        className="absolute -right-3 top-[72px] size-6 rounded-full border-border bg-card text-muted-foreground hover:text-foreground shadow-sm z-30"
      >
        {collapsed ? <ChevronRight className="size-3" /> : <ChevronLeft className="size-3" />}
      </Button>
    </aside>
  );
}

export default AppSidebar;
