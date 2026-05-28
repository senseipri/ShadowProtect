'use client';

import { useState } from 'react';
import {
  ChevronUp,
  ChevronDown,
  Play,
  Pause,
  RotateCcw,
  Zap,
} from 'lucide-react';

type ReplayScenario = 'injection' | 'collusion' | 'exfiltration' | 'lateral_movement';

type ReplayStatus = {
  running: boolean;
  paused: boolean;
  scenario: string | null;
  speed: number;
  index: number;
  total_events: number;
  last_error: string | null;
};

const REPLAY_SCENARIOS: { value: ReplayScenario; label: string }[] = [
  { value: 'injection',        label: 'Prompt Injection'  },
  { value: 'collusion',        label: 'Agent Collusion'   },
  { value: 'exfiltration',     label: 'Data Exfiltration' },
  { value: 'lateral_movement', label: 'Lateral Movement'  },
];

const SPEED_OPTIONS = [0.5, 1, 2, 5] as const;

const API = 'http://localhost:8000';

async function post(path: string, body?: unknown): Promise<ReplayStatus | null> {
  try {
    const r = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const data = await r.json();
    return (data.status ?? data) as ReplayStatus;
  } catch {
    return null;
  }
}

export default function ReplayBar() {
  const [expanded, setExpanded]   = useState(false);
  const [scenario, setScenario]   = useState<ReplayScenario>('injection');
  const [speed,    setSpeed]      = useState<number>(1);
  const [status,   setStatus]     = useState<ReplayStatus | null>(null);
  const [loading,  setLoading]    = useState(false);
  const [error,    setError]      = useState<string | null>(null);

  /* ── API helpers ── */
  const fetchStatus = async () => {
    try {
      const r    = await fetch(`${API}/replay/status`);
      const data = await r.json();
      setStatus(data);
    } catch { /* silent */ }
  };

  const handleToggle = () => {
    setExpanded((v) => {
      if (!v) fetchStatus();
      return !v;
    });
  };

  const handleStart = async () => {
    setLoading(true);
    setError(null);
    const s = await post('/replay/start', { scenario, speed });
    if (s) setStatus(s); else setError('Backend unreachable — is the server running?');
    setLoading(false);
  };

  const handlePause  = async () => { const s = await post('/replay/pause');  if (s) setStatus(s); };
  const handleResume = async () => { const s = await post('/replay/resume'); if (s) setStatus(s); };

  const isRunning = status?.running  ?? false;
  const isPaused  = status?.paused   ?? false;
  const progress  = (status && status.total_events > 0)
    ? Math.min(100, (status.index / status.total_events) * 100)
    : 0;

  /* ── Render ── */
  return (
    <div
      className="flex-none border-t border-slate-800 bg-slate-900/95 backdrop-blur-sm"
      style={{ transition: 'height 300ms ease' }}
    >
      {/* ── Collapse handle ── */}
      <button
        id="btn-replay-toggle"
        onClick={handleToggle}
        className="w-full flex items-center justify-between px-5 py-2.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 transition-colors duration-200 group"
      >
        <div className="flex items-center gap-2.5">
          <Zap className="w-3.5 h-3.5 text-yellow-400" />
          <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-400 group-hover:text-slate-200 transition-colors">
            Scenario Replay
          </span>

          {isRunning && (
            <span className="flex items-center gap-1 ml-1 px-1.5 py-0.5 bg-emerald-500/10 border border-emerald-500/25 rounded text-emerald-400 text-[9px] font-bold uppercase tracking-wider">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              {isPaused ? 'Paused' : 'Running'}
            </span>
          )}

          {isRunning && !isPaused && (
            <span className="text-[10px] font-mono text-slate-500">
              {status!.index}/{status!.total_events}
            </span>
          )}
        </div>

        {expanded
          ? <ChevronDown className="w-3.5 h-3.5" />
          : <ChevronUp   className="w-3.5 h-3.5" />
        }
      </button>

      {/* ── Expanded panel ── */}
      {expanded && (
        <div className="px-5 pb-4 border-t border-slate-800/60 space-y-3">
          {/* Controls row */}
          <div className="flex items-center gap-4 flex-wrap pt-3">

            {/* Scenario picker */}
            <div className="flex items-center gap-2">
              <label className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest whitespace-nowrap">
                Scenario
              </label>
              <select
                id="replay-scenario-select"
                value={scenario}
                disabled={isRunning}
                onChange={(e) => setScenario(e.target.value as ReplayScenario)}
                className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-md px-2.5 py-1.5 focus:outline-none focus:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {REPLAY_SCENARIOS.map((s) => (
                  <option key={s.value} value={s.value}>{s.label}</option>
                ))}
              </select>
            </div>

            {/* Speed pills */}
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">
                Speed
              </span>
              <div className="flex gap-1">
                {SPEED_OPTIONS.map((s) => (
                  <button
                    key={s}
                    disabled={isRunning}
                    onClick={() => setSpeed(s)}
                    className={`px-2 py-1 text-[10px] font-bold rounded border transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed ${
                      speed === s
                        ? 'bg-violet-600 border-violet-500 text-white shadow-[0_0_8px_rgba(124,58,237,0.4)]'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                    }`}
                  >
                    {s}×
                  </button>
                ))}
              </div>
            </div>

            {/* Action buttons — pushed to the right */}
            <div className="flex items-center gap-2 ml-auto">
              {!isRunning ? (
                <button
                  id="btn-replay-start"
                  disabled={loading}
                  onClick={handleStart}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Play className="w-3 h-3" />
                  {loading ? 'Starting…' : 'Start Replay'}
                </button>
              ) : isPaused ? (
                <button
                  id="btn-replay-resume"
                  onClick={handleResume}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-md transition-colors"
                >
                  <Play className="w-3 h-3" />
                  Resume
                </button>
              ) : (
                <button
                  id="btn-replay-pause"
                  onClick={handlePause}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 bg-yellow-600 hover:bg-yellow-500 text-white text-xs font-semibold rounded-md transition-colors"
                >
                  <Pause className="w-3 h-3" />
                  Pause
                </button>
              )}

              <button
                id="btn-replay-refresh"
                onClick={fetchStatus}
                title="Refresh status"
                className="flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-semibold rounded-md transition-colors"
              >
                <RotateCcw className="w-3 h-3" />
              </button>
            </div>
          </div>

          {/* Progress bar */}
          {status && (
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-slate-500">
                  {status.scenario
                    ? REPLAY_SCENARIOS.find((s) => status.scenario?.includes(s.value))?.label ?? status.scenario
                    : 'No scenario loaded'}
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  {status.index} / {status.total_events} events — {Math.round(progress)}%
                </span>
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-violet-600 via-indigo-500 to-cyan-500"
                  style={{ width: `${progress}%`, transition: 'width 0.5s ease' }}
                />
              </div>
            </div>
          )}

          {/* Error */}
          {error && (
            <p className="text-[10px] text-red-400 font-medium">{error}</p>
          )}
        </div>
      )}
    </div>
  );
}
