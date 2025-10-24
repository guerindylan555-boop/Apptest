import React, { useState, useEffect, useCallback, useRef } from 'react';

interface AutomationStatus {
  total_states: number;
  total_edges: number;
  avg_visit_count: number;
  new_states_last_hour: number;
  current_state: string | null;
}

interface AutomationEvent {
  type: string;
  event?: string;
  data?: any;
  commentary?: string;
  reasoning?: any;
  timestamp?: number;
}

interface AutomationControllerProps {
  className?: string;
}

export const AutomationController: React.FC<AutomationControllerProps> = ({ className }) => {
  const [status, setStatus] = useState<AutomationStatus>({
    total_states: 0,
    total_edges: 0,
    avg_visit_count: 0,
    new_states_last_hour: 0,
    current_state: null,
  });

  const [discoveryStatus, setDiscoveryStatus] = useState<'stopped' | 'running' | 'paused'>('stopped');
  const [isAutomationRunning, setIsAutomationRunning] = useState(false);
  const [events, setEvents] = useState<Array<{time: string, message: string, type: 'info' | 'success' | 'error' | 'llm' | 'watchdog'}>>([]);
  const [llmCommentary, setLlmCommentary] = useState<string>('');
  const [annotation, setAnnotation] = useState<string>('');
  const [selectedGoal, setSelectedGoal] = useState<string>('RENTAL');
  const [autoMode, setAutoMode] = useState<boolean>(true);
  const [appDetected, setAppDetected] = useState<boolean>(false);
  const wsRef = useRef<WebSocket | null>(null);
  const eventsEndRef = useRef<HTMLDivElement>(null);

  const API_BASE = 'http://localhost:8000';

  // Connect to WebSocket for real-time updates
  useEffect(() => {
    const connectWebSocket = () => {
      const ws = new WebSocket('ws://localhost:8000/ws');

      ws.onopen = () => {
        console.log('[AutomationController] WebSocket connected');
        addEvent('🔗 Connected to automation server', 'success');
      };

      ws.onmessage = (event) => {
        try {
          const msg: AutomationEvent = JSON.parse(event.data);
          handleWebSocketMessage(msg);
        } catch (error) {
          console.error('[AutomationController] Failed to parse message:', error);
        }
      };

      ws.onerror = (error) => {
        console.error('[AutomationController] WebSocket error:', error);
        addEvent('❌ WebSocket error', 'error');
      };

      ws.onclose = () => {
        console.log('[AutomationController] WebSocket closed, reconnecting...');
        setTimeout(connectWebSocket, 3000);
      };

      wsRef.current = ws;
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const handleWebSocketMessage = (msg: AutomationEvent) => {
    if (msg.type === 'discovery') {
      if (msg.event === 'state_discovered') {
        addEvent(`🆕 New state: ${msg.data?.state_id?.substring(0, 8)}`, 'success');
      } else if (msg.event === 'state_changed') {
        addEvent(`🔄 State: ${msg.data?.from?.substring(0, 8)} → ${msg.data?.to?.substring(0, 8)}`, 'info');
      }
    } else if (msg.type === 'automation') {
      addEvent(`🤖 ${msg.event}: ${JSON.stringify(msg.data).substring(0, 50)}`, 'info');
    } else if (msg.type === 'llm_commentary') {
      setLlmCommentary(msg.commentary || '');
      addEvent(`🧠 ${msg.commentary}`, 'llm');
    } else if (msg.type === 'llm_log') {
      addEvent(`🧠 ${msg.data?.message || msg.commentary || ''}`, 'llm');
    } else if (msg.type === 'watchdog') {
      if (msg.data?.status === 'app_started' || msg.event === 'app_started') {
        setAppDetected(true);
        addEvent(`📱 App started: ${msg.data?.package || 'MaynDrive'}`, 'watchdog');
      } else if (msg.data?.status === 'app_stopped' || msg.event === 'app_stopped') {
        setAppDetected(false);
        addEvent(`📱 App stopped: ${msg.data?.package || 'MaynDrive'}`, 'watchdog');
      }
    } else if (msg.type === 'discovery_status') {
      const running = msg.data?.running;
      if (running !== undefined) {
        setDiscoveryStatus(running ? 'running' : 'stopped');
        const reason = msg.data?.reason || '';
        if (reason) {
          addEvent(`🔄 Discovery ${running ? 'started' : 'stopped'}: ${reason}`, 'info');
        }
      }
    } else if (msg.type === 'status') {
      if (msg.data) {
        setStatus(prev => ({ ...prev, ...msg.data }));
      }
    }
  };

  const addEvent = (message: string, type: 'info' | 'success' | 'error' | 'llm' | 'watchdog' = 'info') => {
    const time = new Date().toLocaleTimeString();
    setEvents(prev => [{ time, message, type }, ...prev].slice(0, 50)); // Keep last 50
  };

  // Scroll events to bottom
  useEffect(() => {
    eventsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  // Poll status every 2 seconds
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/status`);
        if (response.ok) {
          const data = await response.json();
          setStatus(data);
        }
      } catch (error) {
        console.error('[AutomationController] Failed to fetch status:', error);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  // Poll control status for app detection
  useEffect(() => {
    const fetchControlStatus = async () => {
      try {
        const response = await fetch(`${API_BASE}/control/status`);
        if (response.ok) {
          const data = await response.json();
          setAppDetected(data.app_detected || false);
          if (data.running !== undefined) {
            setDiscoveryStatus(data.running ? 'running' : 'stopped');
          }
        }
      } catch (error) {
        console.error('[AutomationController] Failed to fetch control status:', error);
      }
    };

    fetchControlStatus();
    const interval = setInterval(fetchControlStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  const controlDiscovery = async (action: 'start' | 'pause' | 'resume' | 'stop') => {
    try {
      const response = await fetch(`${API_BASE}/api/discovery`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });

      if (response.ok) {
        const data = await response.json();
        setDiscoveryStatus(data.status === 'Running' ? 'running' : data.status === 'Paused' ? 'paused' : 'stopped');
        addEvent(`Discovery ${action}ed`, 'success');
      }
    } catch (error) {
      addEvent(`Failed to ${action} discovery`, 'error');
    }
  };

  const runAutomation = async (goal: string) => {
    try {
      setIsAutomationRunning(true);
      const response = await fetch(`${API_BASE}/api/automation/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ goal, max_steps: 30 }),
      });

      if (response.ok) {
        const data = await response.json();
        addEvent(`🚀 ${data.message}`, 'success');
      } else {
        addEvent('Failed to start automation', 'error');
      }
    } catch (error) {
      addEvent('Automation error', 'error');
    } finally {
      // Automation runs in background, so reset button after short delay
      setTimeout(() => setIsAutomationRunning(false), 2000);
    }
  };

  const addAnnotationToState = async () => {
    if (!annotation.trim()) return;

    try {
      const response = await fetch(`${API_BASE}/api/annotate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: annotation }),
      });

      if (response.ok) {
        addEvent(`📝 Annotation added`, 'success');
        setAnnotation('');
      }
    } catch (error) {
      addEvent('Failed to add annotation', 'error');
    }
  };

  return (
    <div className={`bg-gradient-to-br from-gray-900 via-purple-900 to-indigo-900 rounded-lg shadow-xl p-4 text-white ${className || ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center">
          <div className={`w-2 h-2 rounded-full mr-2 ${
            discoveryStatus === 'running' ? 'bg-green-400 animate-pulse' :
            discoveryStatus === 'paused' ? 'bg-yellow-400' :
            'bg-gray-400'
          }`}></div>
          <h2 className="text-sm font-bold text-purple-200">Automation Control</h2>
        </div>
        <div className="px-2 py-1 bg-white/10 backdrop-blur-sm rounded text-xs">
          {discoveryStatus.toUpperCase()}
        </div>
      </div>

      {/* Status Display */}
      <div className="mb-4 p-3 bg-gradient-to-r from-purple-500/20 to-indigo-500/20 backdrop-blur-sm rounded-lg border border-white/10">
        <div className="text-xs font-semibold text-purple-300 mb-2">Discovery Stats</div>
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <div className="text-gray-400">States:</div>
            <div className="font-mono font-bold text-white">{status.total_states}</div>
          </div>
          <div>
            <div className="text-gray-400">Edges:</div>
            <div className="font-mono font-bold text-white">{status.total_edges}</div>
          </div>
          <div>
            <div className="text-gray-400">Avg Visits:</div>
            <div className="font-mono font-bold text-white">{status.avg_visit_count}</div>
          </div>
          <div>
            <div className="text-gray-400">Current:</div>
            <div className="font-mono font-bold text-white text-[10px]">
              {status.current_state?.substring(0, 8) || '-'}
            </div>
          </div>
        </div>
      </div>

      {/* Auto-mode Toggle */}
      <div className="mb-4 p-3 bg-gradient-to-r from-indigo-500/20 to-purple-500/20 backdrop-blur-sm rounded-lg border border-white/10">
        <label className="flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={autoMode}
            onChange={(e) => setAutoMode(e.target.checked)}
            className="mr-2 h-4 w-4 rounded border-gray-300 text-purple-600 focus:ring-purple-500"
          />
          <span className="text-xs font-semibold text-indigo-300">🤖 Auto-run on app launch</span>
        </label>
        {autoMode && !appDetected && (
          <div className="mt-2 text-xs text-yellow-300">⏳ Waiting for app...</div>
        )}
        {autoMode && appDetected && (
          <div className="mt-2 text-xs text-green-300">✅ App detected</div>
        )}
      </div>

      {/* Discovery Controls */}
      <div className="mb-4 space-y-2">
        <div className="text-xs font-semibold text-indigo-300 mb-2">Discovery</div>
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={() => controlDiscovery('start')}
            disabled={discoveryStatus === 'running' || (autoMode && !appDetected)}
            className="py-2 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white text-xs font-semibold rounded shadow-lg focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            ▶️ Start
          </button>
          <button
            onClick={() => controlDiscovery(discoveryStatus === 'running' ? 'pause' : 'resume')}
            disabled={discoveryStatus === 'stopped'}
            className="py-2 bg-gradient-to-r from-yellow-600 to-orange-600 hover:from-yellow-700 hover:to-orange-700 text-white text-xs font-semibold rounded shadow-lg focus:outline-none focus:ring-2 focus:ring-yellow-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {discoveryStatus === 'running' ? '⏸️ Pause' : '▶️ Resume'}
          </button>
        </div>
        <button
          onClick={() => controlDiscovery('stop')}
          disabled={discoveryStatus === 'stopped'}
          className="w-full py-2 bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-700 hover:to-pink-700 text-white text-xs font-semibold rounded shadow-lg focus:outline-none focus:ring-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          ⏹️ Stop
        </button>
      </div>

      {/* Automation Controls */}
      <div className="mb-4 space-y-2">
        <div className="text-xs font-semibold text-indigo-300 mb-2">Run Automation</div>
        <select
          value={selectedGoal}
          onChange={(e) => setSelectedGoal(e.target.value)}
          className="w-full px-2 py-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded text-xs text-white focus:outline-none focus:ring-2 focus:ring-purple-500 transition-all"
        >
          <option value="RENTAL">🚗 Rental Flow</option>
          <option value="LOGIN">🔐 Login</option>
          <option value="UNLOCK_VEHICLE">🔓 Unlock Vehicle</option>
          <option value="MAP_ACCESS">🗺️ Map Access</option>
        </select>
        <button
          onClick={() => runAutomation(selectedGoal)}
          disabled={isAutomationRunning}
          className="w-full py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white text-xs font-semibold rounded shadow-lg focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          {isAutomationRunning ? '🔄 Running...' : '🚀 Start Automation'}
        </button>
      </div>

      {/* LLM Commentary */}
      {llmCommentary && (
        <div className="mb-4 p-3 bg-gradient-to-r from-pink-500/20 to-purple-500/20 backdrop-blur-sm rounded-lg border border-white/10">
          <div className="text-xs font-semibold text-pink-300 mb-2">🧠 LLM Commentary</div>
          <div className="text-xs text-white/90">{llmCommentary}</div>
        </div>
      )}

      {/* Annotation */}
      <div className="mb-4 space-y-2">
        <div className="text-xs font-semibold text-indigo-300 mb-2">📝 Annotate State</div>
        <textarea
          value={annotation}
          onChange={(e) => setAnnotation(e.target.value)}
          placeholder="Add notes about current screen..."
          rows={2}
          className="w-full px-2 py-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded text-xs text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 transition-all resize-none"
        />
        <button
          onClick={addAnnotationToState}
          disabled={!annotation.trim()}
          className="w-full py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white text-xs font-semibold rounded shadow-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          💾 Save Annotation
        </button>
      </div>

      {/* Event Log */}
      <div className="space-y-2">
        <div className="text-xs font-semibold text-indigo-300 mb-2">📡 Live Events</div>
        <div className="h-40 overflow-y-auto bg-black/30 backdrop-blur-sm rounded-lg p-2 space-y-1 border border-white/10">
          {events.length === 0 ? (
            <div className="text-xs text-gray-500 text-center py-4">No events yet...</div>
          ) : (
            events.map((event, idx) => (
              <div
                key={idx}
                className={`text-xs p-2 rounded ${
                  event.type === 'success' ? 'bg-green-500/20 text-green-300' :
                  event.type === 'error' ? 'bg-red-500/20 text-red-300' :
                  event.type === 'llm' ? 'bg-purple-500/20 text-purple-300' :
                  event.type === 'watchdog' ? 'bg-blue-500/20 text-blue-300' :
                  'bg-white/10 text-gray-300'
                }`}
              >
                <span className="text-gray-500">[{event.time}]</span> {event.message}
              </div>
            ))
          )}
          <div ref={eventsEndRef} />
        </div>
      </div>
    </div>
  );
};
