'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/Badge';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { Button } from '@/components/ui/Button';
import { Search, ArrowUpDown, ChevronLeft, ChevronRight, CheckSquare, Square, Trash2, Download } from 'lucide-react';

interface Incident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  type: string;
  created: string;
  assigned: string;
}

const mockIncidents: Incident[] = [
  { id: 'INC-2024-001', title: 'Ransomware Attack on DC-01', severity: 'critical', status: 'contained', type: 'Ransomware', created: '2024-01-15 14:23', assigned: 'SOC Lead' },
  { id: 'INC-2024-002', title: 'Credential Dumping — LSASS Access', severity: 'high', status: 'investigating', type: 'Credential Theft', created: '2024-01-15 14:05', assigned: 'Analyst-1' },
  { id: 'INC-2024-003', title: 'Lateral Movement via WMI', severity: 'high', status: 'investigating', type: 'Lateral Movement', created: '2024-01-15 13:48', assigned: 'Analyst-2' },
  { id: 'INC-2024-004', title: 'Suspicious PowerShell on WS-08', severity: 'medium', status: 'open', type: 'Execution', created: '2024-01-15 13:30', assigned: 'Analyst-1' },
  { id: 'INC-2024-005', title: 'Unauthorized Service on WEB-02', severity: 'medium', status: 'open', type: 'Persistence', created: '2024-01-15 12:55', assigned: 'Analyst-3' },
  { id: 'INC-2024-006', title: 'External Port Scan Detection', severity: 'low', status: 'resolved', type: 'Reconnaissance', created: '2024-01-15 11:20', assigned: 'Automation' },
  { id: 'INC-2024-007', title: 'Phishing Campaign — Malicious Doc', severity: 'high', status: 'contained', type: 'Phishing', created: '2024-01-14 16:45', assigned: 'SOC Lead' },
  { id: 'INC-2024-008', title: 'Data Exfiltration via DNS', severity: 'critical', status: 'open', type: 'Exfiltration', created: '2024-01-14 14:10', assigned: 'Analyst-2' },
];

const statusColors: Record<string, string> = {
  open: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
  investigating: 'text-cyan-500 bg-cyan-500/10 border-cyan-500/30',
  contained: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
  resolved: 'text-green-500 bg-green-500/10 border-green-500/30',
};

type SortKey = 'id' | 'severity' | 'status' | 'created';

export function IncidentList() {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [sortKey, setSortKey] = useState<SortKey>('created');
  const [sortAsc, setSortAsc] = useState(false);
  const [page, setPage] = useState(0);
  const perPage = 5;

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const statusOrder = { open: 0, investigating: 1, contained: 2, resolved: 3 };

  const filtered = mockIncidents
    .filter((inc) => {
      if (search && !inc.title.toLowerCase().includes(search.toLowerCase()) && !inc.id.toLowerCase().includes(search.toLowerCase())) return false;
      if (filterSeverity !== 'all' && inc.severity !== filterSeverity) return false;
      if (filterStatus !== 'all' && inc.status !== filterStatus) return false;
      return true;
    })
    .sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'severity') cmp = severityOrder[a.severity] - severityOrder[b.severity];
      else if (sortKey === 'status') cmp = statusOrder[a.status] - statusOrder[b.status];
      else if (sortKey === 'created') cmp = new Date(b.created).getTime() - new Date(a.created).getTime();
      else cmp = a.id.localeCompare(b.id);
      return sortAsc ? cmp : -cmp;
    });

  const totalPages = Math.ceil(filtered.length / perPage);
  const paginated = filtered.slice(page * perPage, (page + 1) * perPage);

  const toggleAll = () => {
    if (selected.size === paginated.length) setSelected(new Set());
    else setSelected(new Set(paginated.map((i) => i.id)));
  };

  const toggleOne = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      {/* Toolbar */}
      <div className="px-5 py-4 border-b border-surface-border space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white">Incidents</h3>
          <div className="flex items-center gap-2">
            {selected.size > 0 && (
              <>
                <span className="text-xs text-gray-400">{selected.size} selected</span>
                <Button size="sm" variant="ghost"><Download className="h-3.5 w-3.5" /></Button>
                <Button size="sm" variant="danger"><Trash2 className="h-3.5 w-3.5" /> Bulk Actions</Button>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
            <input
              type="text"
              placeholder="Search incidents..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-accent-cyan/50"
            />
          </div>
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-2 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-gray-300 focus:outline-none focus:border-accent-cyan/50"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-2 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-gray-300 focus:outline-none focus:border-accent-cyan/50"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-surface-border bg-surface/50">
              <th className="px-4 py-3 text-left w-8">
                <button onClick={toggleAll} className="text-gray-500 hover:text-white">
                  {selected.size === paginated.length && paginated.length > 0 ? <CheckSquare className="h-4 w-4" /> : <Square className="h-4 w-4" />}
                </button>
              </th>
              {[
                { key: 'id', label: 'ID' },
                { key: null, label: 'Title' },
                { key: 'severity', label: 'Severity' },
                { key: 'status', label: 'Status' },
                { key: null, label: 'Type' },
                { key: 'created', label: 'Created' },
                { key: null, label: 'Assigned' },
              ].map((col) => (
                <th
                  key={col.label}
                  className={cn(
                    'px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider',
                    col.key && 'cursor-pointer hover:text-white'
                  )}
                  onClick={() => {
                    if (col.key) {
                      if (sortKey === col.key) setSortAsc(!sortAsc);
                      else { setSortKey(col.key as SortKey); setSortAsc(true); }
                    }
                  }}
                >
                  <div className="flex items-center gap-1">
                    {col.label}
                    {sortKey === col.key && <ArrowUpDown className="h-3 w-3" />}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paginated.map((inc) => (
              <tr key={inc.id} className={cn('border-b border-surface-border hover:bg-surface/30 transition-colors', selected.has(inc.id) && 'bg-accent-cyan/5')}>
                <td className="px-4 py-3">
                  <button onClick={() => toggleOne(inc.id)} className="text-gray-500 hover:text-white">
                    {selected.has(inc.id) ? <CheckSquare className="h-4 w-4" /> : <Square className="h-4 w-4" />}
                  </button>
                </td>
                <td className="px-4 py-3 font-mono text-accent-cyan">{inc.id}</td>
                <td className="px-4 py-3 font-medium text-white">{inc.title}</td>
                <td className="px-4 py-3"><SeverityBadge severity={inc.severity} /></td>
                <td className="px-4 py-3">
                  <span className={cn('px-2 py-0.5 rounded text-[10px] font-medium border', statusColors[inc.status])}>
                    {inc.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-400">{inc.type}</td>
                <td className="px-4 py-3 text-gray-500 font-mono">{inc.created}</td>
                <td className="px-4 py-3 text-gray-400">{inc.assigned}</td>
              </tr>
            ))}
            {paginated.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-sm text-gray-500">No incidents match the current filters</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="px-5 py-3 border-t border-surface-border flex items-center justify-between">
          <span className="text-[10px] text-gray-500">
            Showing {page * perPage + 1}–{Math.min((page + 1) * perPage, filtered.length)} of {filtered.length}
          </span>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>
              <ChevronLeft className="h-3.5 w-3.5" />
            </Button>
            {Array.from({ length: totalPages }, (_, i) => (
              <button
                key={i}
                onClick={() => setPage(i)}
                className={cn(
                  'w-6 h-6 text-[10px] rounded font-medium transition-colors',
                  i === page ? 'bg-accent-cyan/20 text-accent-cyan' : 'text-gray-500 hover:text-white hover:bg-surface-border'
                )}
              >
                {i + 1}
              </button>
            ))}
            <Button size="sm" variant="ghost" disabled={page >= totalPages - 1} onClick={() => setPage(page + 1)}>
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
