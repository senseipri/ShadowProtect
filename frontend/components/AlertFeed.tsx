'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Eye,
  TrendingUp,
  Users,
} from 'lucide-react';
import { useAppStore, type Alert } from '@/lib/store';

/* ── Types ───────────────────────────────────────────────── */
type FeedFilter = 'ALL' | 'INJECTION' | 'COLLUSION' | 'ANOMALY' | 'INDIRECT';

type AlertVisual = {
  badgeLabel: string;
  badgeClass: string;
  rowClass:   string;
  icon:       React.ComponentType<{ className?: string }>;
  severeGlow: boolean;
};

/* ── Helpers ─────────────────────────────────────────────── */
function alertKey(alert: Alert, idx: number): string {
  return `${alert.id ?? ''}|${alert.kind}|${alert.description}|${alert.timestamp ?? ''}|${idx}`;
}

function toRelativeTime(value?: string): string {
  if (!value) return 'just now';
  const diff = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (!Number.isFinite(diff)) return 'just now';
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function getVisual(kindRaw: string): AlertVisual {
  const kind = kindRaw.toUpperCase();

  if (kind.includes('INJECTION') && !kind.includes('INDIRECT')) {
    return {
      badgeLabel: 'INJECTION',
      badgeClass: 'bg-red-500/15 text-red-400 border-red-500/30',
      rowClass:   'border-l-red-500/60',
      icon:       AlertTriangle,
      severeGlow: true,
    };
  }
  if (kind.includes('ESCALATION')) {
    return {
      badgeLabel: 'ESCALATION',
      badgeClass: 'bg-red-500/15 text-red-400 border-red-500/30',
      rowClass:   'border-l-red-500/60',
      icon:       TrendingUp,
      severeGlow: true,
    };
  }
  if (kind.includes('COLLUSION')) {
    return {
      badgeLabel: 'COLLUSION',
      badgeClass: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
      rowClass:   'border-l-orange-500/50',
      icon:       Users,
      severeGlow: false,
    };
  }
  if (kind.includes('ANOMALY')) {
    return {
      badgeLabel: 'ANOMALY',
      badgeClass: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
      rowClass:   'border-l-yellow-500/50',
      icon:       Activity,
      severeGlow: false,
    };
  }
  if (kind.includes('INDIRECT')) {
    return {
      badgeLabel: 'INDIRECT',
      badgeClass: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
      rowClass:   'border-l-purple-500/50',
      icon:       Eye,
      severeGlow: true,
    };
  }
  return {
    badgeLabel: kind || 'ALERT',
    badgeClass: 'bg-slate-700/60 text-slate-400 border-slate-600/50',
    rowClass:   'border-l-slate-600/40',
    icon:       AlertTriangle,
    severeGlow: false,
  };
}

/* ── Filter pills config ─────────────────────────────────── */
const FILTER_PILLS: { label: string; value: FeedFilter }[] = [
  { label: 'All',       value: 'ALL'       },
  { label: 'Injection', value: 'INJECTION' },
  { label: 'Collusion', value: 'COLLUSION' },
  { label: 'Anomaly',   value: 'ANOMALY'   },
  { label: 'Indirect',  value: 'INDIRECT'  },
];

/* ── Component ───────────────────────────────────────────── */
export default function AlertFeed() {
  const alerts      = useAppStore((s) => s.alerts);
  const clearAlerts = useAppStore((s) => s.clearAlerts);

  const [filter,        setFilter]        = useState<FeedFilter>('ALL');
  const [unread,        setUnread]        = useState(0);
  const [animatingKeys, setAnimatingKeys] = useState<Record<string, boolean>>({});
  const [glowPhase,     setGlowPhase]     = useState<'off' | 'on' | 'fade'>('off');
  const [, setTick]                       = useState(0);

  const prevKeysRef = useRef<string[]>([]);
  const listRef     = useRef<HTMLDivElement>(null);

  /* Relative-time ticker */
  useEffect(() => {
    const id = window.setInterval(() => setTick((x) => x + 1), 1000);
    return () => window.clearInterval(id);
  }, []);

  /* Detect new alerts → animate + unread counter + panel glow */
  useEffect(() => {
    const keys    = alerts.map(alertKey);
    const prevSet = new Set(prevKeysRef.current);
    const fresh   = keys.filter((k) => !prevSet.has(k));

    if (fresh.length > 0) {
      setUnread((v) => v + fresh.length);

      setAnimatingKeys((curr) => {
        const next = { ...curr };
        fresh.forEach((k) => (next[k] = true));
        return next;
      });
      window.setTimeout(() => {
        setAnimatingKeys((curr) => {
          const next = { ...curr };
          fresh.forEach((k) => delete next[k]);
          return next;
        });
      }, 450);

      /* Glow for severe kinds */
      const hasSevere = alerts.some((a) => {
        const k = String(a.kind || '').toUpperCase();
        return k.includes('INJECTION') || k.includes('ESCALATION') || k.includes('INDIRECT');
      });
      if (hasSevere) {
        setGlowPhase('on');
        window.setTimeout(() => {
          setGlowPhase('fade');
          window.setTimeout(() => setGlowPhase('off'), 500);
        }, 300);
      }
    }

    prevKeysRef.current = keys;
  }, [alerts]);

  /* Filtered list */
  const filtered = useMemo(() => {
    const list = alerts.slice(0, 50);
    if (filter === 'ALL') return list;
    if (filter === 'INDIRECT')
      return list.filter((a) => String(a.kind || '').toUpperCase().includes('INDIRECT'));
    return list.filter((a) => String(a.kind || '').toUpperCase().includes(filter));
  }, [alerts, filter]);

  /* Glow class */
  const glowStyle: React.CSSProperties =
    glowPhase === 'on'
      ? { boxShadow: '0 0 20px rgba(239,68,68,0.45)', transition: 'box-shadow 300ms ease' }
      : glowPhase === 'fade'
      ? { boxShadow: '0 0 0px rgba(239,68,68,0)',     transition: 'box-shadow 500ms ease' }
      : {};

  /* ── Render ── */
  return (
    <section className="w-full flex flex-col h-full" style={glowStyle}>

      {/* Sticky header */}
      <header className="sticky top-0 z-10 bg-slate-900 border-b border-slate-800/80 px-4 py-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <h3 className="text-sm font-bold text-slate-100 tracking-tight whitespace-nowrap">Alert Feed</h3>
          {unread > 0 && (
            <span className="shrink-0 rounded-full bg-red-600 px-1.5 py-0.5 text-[9px] font-extrabold text-white leading-none tabular-nums">
              {unread > 99 ? '99+' : unread}
            </span>
          )}
        </div>
        <button
          type="button"
          id="btn-clear-alerts"
          onClick={() => { clearAlerts(); setUnread(0); }}
          className="shrink-0 px-2.5 py-1 rounded-md border border-slate-700 text-[10px] font-semibold text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors duration-150"
        >
          Clear
        </button>
      </header>

      {/* Filter pills */}
      <div className="flex items-center gap-1.5 px-4 py-2 border-b border-slate-800/60 flex-wrap bg-slate-900/50">
        {FILTER_PILLS.map(({ label, value }) => (
          <button
            key={value}
            type="button"
            onClick={() => setFilter(value)}
            className={`rounded-full border px-2.5 py-0.5 text-[10px] font-semibold transition-all duration-150 ${
              filter === value
                ? 'bg-slate-200 border-slate-200 text-slate-900'
                : 'bg-transparent border-slate-700 text-slate-500 hover:border-slate-500 hover:text-slate-300'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Alert list */}
      <div
        ref={listRef}
        className="flex-1 overflow-y-auto divide-y divide-slate-800/50"
        onScroll={(e) => {
          if (e.currentTarget.scrollTop <= 0) setUnread(0);
        }}
      >
        {filtered.length === 0 ? (
          <div className="px-4 py-8 text-center text-xs text-slate-600">
            No alerts for this filter.
          </div>
        ) : (
          filtered.map((alert, idx) => {
            const key    = alertKey(alert, idx);
            const visual = getVisual(String(alert.kind || ''));
            const Icon   = visual.icon;
            const source = String(
              (alert as Record<string, unknown>).source_agent ||
              (alert as Record<string, unknown>).source ||
              'unknown-agent',
            );

            return (
              <article
                key={key}
                className={`px-4 py-3 border-l-2 transition-colors duration-200 hover:bg-slate-800/30 ${visual.rowClass} ${
                  animatingKeys[key] ? 'alert-enter' : ''
                }`}
              >
                {/* Badge + time */}
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <Icon className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                    <span className={`px-1.5 py-0.5 rounded border text-[9px] font-extrabold uppercase tracking-wider ${visual.badgeClass}`}>
                      {visual.badgeLabel}
                    </span>
                  </div>
                  <span className="shrink-0 text-[10px] font-mono text-slate-600 tabular-nums">
                    {toRelativeTime(alert.timestamp)}
                  </span>
                </div>

                {/* Source */}
                <div className="text-[10px] text-slate-500 mb-1">
                  <span className="text-slate-400 font-medium">Source: </span>
                  <span className="text-slate-300 font-semibold">{source}</span>
                </div>

                {/* Description */}
                <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                  {alert.description}
                </p>
              </article>
            );
          })
        )}
      </div>

      {/* Scoped keyframe animations */}
      <style>{`
        .alert-enter {
          animation: alert-slide-down 350ms cubic-bezier(0.16, 1, 0.3, 1) both;
        }

        @keyframes alert-slide-down {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
      `}</style>
    </section>
  );
}
