import { useNavigate } from 'react-router-dom';
import { AlertTriangle, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function NotFoundPage() {
  const navigate = useNavigate();

  return (
    <div className="p-5">
      <div className="flex flex-col items-center justify-center py-20">
        <AlertTriangle className="size-10 text-muted-foreground/50 mb-3" />
        <p className="text-sm font-medium text-foreground mb-1">404 — Page not found</p>
        <p className="text-sm text-muted-foreground mb-4">The page you are looking for does not exist.</p>
        <Button variant="outline" size="sm" onClick={() => navigate('/')}>
          <ArrowLeft className="size-4" /> Back to Dashboard
        </Button>
      </div>
    </div>
  );
}
