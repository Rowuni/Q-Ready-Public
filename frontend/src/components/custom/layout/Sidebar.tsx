import { LayoutDashboard, ShieldAlert, Upload, FlaskConical, Plus } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { Button } from '@/components/ui/button';

const navItems = [
  { name: 'Dashboard', path: '/', icon: LayoutDashboard },
  { name: 'Findings', path: '/findings', icon: ShieldAlert },
  { name: 'Import', path: '/import', icon: Upload },
  { name: 'Lab', path: '/lab', icon: FlaskConical },
];

export default function Sidebar() {
  const location = useLocation();
  const isDashboardSelected = location.pathname === '/';

  return (
    <div className="w-64 h-full bg-sidebar text-white flex flex-col justify-between">
      <div>
        <div className="p-4">
          <h1 className="text-xl font-heading font-bold">
              Q-Ready
          </h1>
        </div>
        <nav className="flex pt-10 flex-col px-2 gap-4">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            const Icon = item.icon;
            
            return (
              <Link to={item.path} key={item.name}>
                <div className={`flex flex-row group cursor-pointer ${isActive ? 'bg-accent text-accent-foreground' : 'hover:bg-accent hover:text-accent-foreground'}`}>
                    <div className="px-2 py-3 w-full">
                        <div className="flex flex-row items-center font-heading">
                            <Icon className="w-5 h-5 mr-2" />
                            {item.name}
                        </div>
                    </div>
                    <div className={`w-0.5 bg-primary-light transition-opacity ${isActive ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`} />
                </div>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Render context-specific actions at the bottom */}
      {isDashboardSelected && (
        <div className="w-full flex justify-center pb-6">
          <Button variant="sidebar">
            <div className="flex flex-row items-center">
              <Plus className="w-5 h-5 mr-2" />
              Start New Scan
            </div>
          </Button>
        </div>
      )}
    </div>
  );
}