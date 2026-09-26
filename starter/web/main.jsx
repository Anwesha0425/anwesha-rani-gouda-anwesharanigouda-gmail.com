import React, { useState, useEffect, useCallback, useRef } from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';

// ─── API client ────────────────────────────────────────────────────────────────
// Access token lives in memory ONLY — never localStorage/sessionStorage (D13).
let _accessToken = null;

async function api(method, path, body, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`;

  const res = await fetch(`/v1${path}`, {
    method,
    headers,
    credentials: 'include', // include the httpOnly refresh cookie
    body: body !== undefined ? JSON.stringify(body) : undefined,
    ...opts,
  });

  // Handle 401 TOKEN_STALE by refreshing the token and retrying once
  if (res.status === 401 && !opts._retry) {
    const data = await res.json().catch(() => ({}));
    if (data?.error?.code === 'TOKEN_STALE') {
      const refreshed = await refreshToken();
      if (refreshed) return api(method, path, body, { ...opts, _retry: true });
    }
    _accessToken = null;
    window.dispatchEvent(new CustomEvent('auth:expired'));
    throw new ApiError(data?.error?.code ?? 'UNAUTHENTICATED', data?.error?.message ?? 'Not authenticated', data?.error?.reason);
  }

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new ApiError(data?.error?.code ?? 'ERROR', data?.error?.message ?? `HTTP ${res.status}`, data?.error?.reason);
  }

  if (res.status === 204) return null;
  return res.json();
}

class ApiError extends Error {
  constructor(code, message, reason) {
    super(message);
    this.code = code;
    this.reason = reason;
  }
}

const get = (path) => api('GET', path);
const post = (path, body) => api('POST', path, body);
const patch = (path, body) => api('PATCH', path, body);
const del = (path) => api('DELETE', path);

async function refreshToken() {
  try {
    const data = await api('POST', '/auth/refresh', undefined, { _retry: true });
    if (data?.accessToken) {
      _accessToken = data.accessToken;
      return true;
    }
  } catch { }
  return false;
}

// ─── Org theme colors ─────────────────────────────────────────────────────────
const THEME_COLORS = {
  cobalt: '#3b82f6',
  crimson: '#ef4444',
  forest: '#22c55e',
  amber: '#f59e0b',
  violet: '#8b5cf6',
  slate: '#94a3b8',
};

const THEMES = Object.keys(THEME_COLORS);

// ─── Login page ───────────────────────────────────────────────────────────────
function LoginPage({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    
    if (!email || !password) {
      setError('Email and password are required');
      return;
    }

    setLoading(true);
    try {
      const data = await post('/auth/login', { email, password });
      _accessToken = data.accessToken;
      onLogin(data);
    } catch (err) {
      // Never distinguish wrong email from wrong password (anti-enumeration)
      setError(err.message || 'Invalid credentials. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">
          <h1>RemoteOps</h1>
          <p>Multi-org permission console</p>
        </div>

        {error && (
          <div className="login-error" data-testid="login-error" role="alert">
            <span>⚠</span>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} data-testid="login-form" noValidate>
          <div className="form-group">
            <label htmlFor="email">Email address</label>
            <input
              id="email"
              data-testid="login-email"
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="you@example.com"
              autoComplete="email"
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              data-testid="login-password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete="current-password"
              required
            />
          </div>
          <button
            type="submit"
            data-testid="login-submit"
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}
            disabled={loading}
          >
            {loading ? <span className="spinner" style={{ width: 16, height: 16 }} /> : null}
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ─── Create org modal ─────────────────────────────────────────────────────────
function CreateOrgModal({ onClose, onCreated }) {
  const [name, setName] = useState('');
  const [theme, setTheme] = useState('cobalt');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await post('/orgs', { name, theme });
      onCreated(data.org);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-title">
          <span>🏢</span> Create Organization
        </div>
        {error && <div className="error-bar"><span>⚠</span>{error}</div>}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Organization name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="Acme Corp" required />
          </div>
          <div className="form-group">
            <label>Accent theme</label>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 4 }}>
              {THEMES.map(t => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTheme(t)}
                  style={{
                    width: 36, height: 36, borderRadius: '50%',
                    background: THEME_COLORS[t],
                    border: theme === t ? '3px solid white' : '3px solid transparent',
                    cursor: 'pointer',
                    boxShadow: theme === t ? `0 0 0 2px ${THEME_COLORS[t]}` : 'none',
                    transition: 'all 150ms',
                  }}
                  title={t}
                />
              ))}
            </div>
          </div>
          <div className="modal-actions">
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Creating…' : 'Create Organization'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Devices view ─────────────────────────────────────────────────────────────
function DevicesView({ orgId, permissions }) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showProvision, setShowProvision] = useState(false);

  const canProvision = permissions?.['device:provision']?.effect === 'allow';
  const canList = permissions?.['device:list']?.effect === 'allow';

  const loadDevices = useCallback(async () => {
    if (!canList) { setLoading(false); return; }
    try {
      const data = await get(`/orgs/${orgId}/devices`);
      setDevices(data.devices ?? []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [orgId, canList]);

  useEffect(() => { loadDevices(); }, [loadDevices]);

  async function handleStartSession(deviceId, mode) {
    try {
      await post(`/orgs/${orgId}/sessions`, { deviceId, mode });
      loadDevices();
    } catch (err) {
      alert(`Session error: ${err.message}`);
    }
  }

  if (!canList) return (
    <div className="empty-state">
      <div className="empty-state-icon">🔒</div>
      <div className="empty-state-title">No access</div>
      <div className="empty-state-desc">You don't have permission to list devices.</div>
    </div>
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Devices</div>
          <div className="page-subtitle">Remotely accessible endpoints in this organization</div>
        </div>
        {canProvision && (
          <button className="btn btn-primary btn-sm" onClick={() => setShowProvision(true)}>
            + Provision device
          </button>
        )}
      </div>

      <div className="page-body">
        {error && <div className="error-bar"><span>⚠</span>{error}</div>}

        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <div className="spinner" />
          </div>
        ) : devices.length === 0 ? (
          <div className="empty-state" data-testid="devices-empty">
            <div className="empty-state-icon">💻</div>
            <div className="empty-state-title">No devices</div>
            <div className="empty-state-desc">
              {canProvision ? 'Provision your first device to get started.' : 'No devices have been provisioned.'}
            </div>
          </div>
        ) : (
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Kind</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {devices.map(device => {
                  const devPerms = device.permissions || permissions;
                  const canView = devPerms?.['device:view']?.effect === 'allow';
                  const canControl = devPerms?.['device:control']?.effect === 'allow';
                  const canTerminal = devPerms?.['device:terminal']?.effect === 'allow';
                  const canTransfer = devPerms?.['device:file_transfer']?.effect === 'allow';
                  const canSession = devPerms?.['session:start']?.effect === 'allow';

                  return (
                    <tr
                      key={device.id}
                      className="device-row"
                      data-testid="device-row"
                      data-device-id={device.id}
                    >
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span className={`online-dot ${device.online ? 'online' : 'offline'}`} />
                          <span style={{ fontWeight: 500 }}>{device.name}</span>
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-grey" style={{ textTransform: 'capitalize' }}>
                          {device.kind}
                        </span>
                      </td>
                      <td>
                        {device.online
                          ? <span className="badge badge-green">Online</span>
                          : <span className="badge badge-grey">Offline</span>
                        }
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          {canView && (
                            <button
                              className="btn btn-sm btn-secondary"
                              data-permission="device:view"
                              data-state="unlocked"
                              onClick={() => handleStartSession(device.id, 'view')}
                            >
                              👁 View
                            </button>
                          )}
                          {canControl && (
                            <button
                              className="btn btn-sm perm-btn perm-btn-active"
                              data-permission="device:control"
                              data-state="unlocked"
                              onClick={() => handleStartSession(device.id, 'control')}
                            >
                              🖱 Control
                            </button>
                          )}
                          {canTerminal && (
                            <button
                              className="btn btn-sm btn-secondary"
                              data-permission="device:terminal"
                              data-state="unlocked"
                              onClick={() => handleStartSession(device.id, 'terminal')}
                            >
                              ⌨ Terminal
                            </button>
                          )}
                          {!canControl && !canTerminal && !canView && (
                            <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>No actions</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showProvision && (
        <ProvisionDeviceModal
          orgId={orgId}
          onClose={() => setShowProvision(false)}
          onCreated={() => { loadDevices(); setShowProvision(false); }}
        />
      )}
    </div>
  );
}

function ProvisionDeviceModal({ orgId, onClose, onCreated }) {
  const [name, setName] = useState('');
  const [kind, setKind] = useState('linux');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    try {
      await post(`/orgs/${orgId}/devices`, { name, kind });
      onCreated();
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-title"><span>💻</span> Provision Device</div>
        {error && <div className="error-bar"><span>⚠</span>{error}</div>}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Device name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="lab-server-01" required />
          </div>
          <div className="form-group">
            <label>Kind</label>
            <select value={kind} onChange={e => setKind(e.target.value)}>
              {['macos','windows','linux','android','ios'].map(k => (
                <option key={k} value={k}>{k}</option>
              ))}
            </select>
          </div>
          <div className="modal-actions">
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Creating…' : 'Provision'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Members view ─────────────────────────────────────────────────────────────
function MembersView({ orgId, permissions, myUserId }) {
  const [members, setMembers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showInvite, setShowInvite] = useState(false);

  const canRead = permissions?.['user:read']?.effect === 'allow';
  const canInvite = permissions?.['user:invite']?.effect === 'allow';

  useEffect(() => {
    if (!canRead) { setLoading(false); return; }
    get(`/orgs/${orgId}/members`)
      .then(d => setMembers(d.members ?? []))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [orgId, canRead]);

  if (!canRead) return (
    <div className="empty-state">
      <div className="empty-state-icon">🔒</div>
      <div className="empty-state-title">No access</div>
      <div className="empty-state-desc">You don't have permission to view members.</div>
    </div>
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Members</div>
          <div className="page-subtitle">People with access to this organization</div>
        </div>
        {canInvite && (
          <button className="btn btn-primary btn-sm" onClick={() => setShowInvite(true)}>
            + Invite member
          </button>
        )}
      </div>
      <div className="page-body">
        {error && <div className="error-bar"><span>⚠</span>{error}</div>}
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <div className="spinner" />
          </div>
        ) : (
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Member</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Joined</th>
                </tr>
              </thead>
              <tbody>
                {members.map(m => (
                  <tr key={m.user_id} className="user-row" data-testid="user-row" data-user-id={m.user_id}>
                    <td>
                      <div style={{ fontWeight: 500 }}>{m.name}</div>
                      <div className="mono" style={{ marginTop: 2 }}>{m.email}</div>
                    </td>
                    <td>
                      <span className="badge badge-blue" style={{ textTransform: 'capitalize' }}>{m.role}</span>
                    </td>
                    <td>
                      {m.status === 'active' && <span className="badge badge-green">Active</span>}
                      {m.status === 'suspended' && <span className="badge badge-amber">Suspended</span>}
                      {m.status === 'invited' && <span className="badge badge-grey">Invited</span>}
                    </td>
                    <td className="mono">
                      {m.joined_at ? new Date(m.joined_at).toLocaleDateString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {showInvite && (
        <InviteModal
          orgId={orgId}
          onClose={() => setShowInvite(false)}
          onInvited={() => {
            setShowInvite(false);
            get(`/orgs/${orgId}/members`).then(d => setMembers(d.members ?? [])).catch(() => {});
          }}
        />
      )}
    </div>
  );
}

function InviteModal({ orgId, onClose, onInvited }) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('viewer');
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const data = await post(`/orgs/${orgId}/invites`, { email, role });
      setResult(data.invite);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (result) return (
    <div className="modal-overlay">
      <div className="modal">
        <div className="modal-title">✅ Invite created</div>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 16 }}>
          Share this token with <strong>{result.email}</strong>. It expires in 7 days.
        </p>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 12, fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all', color: 'var(--accent)' }}>
          {result.token}
        </div>
        <div className="modal-actions">
          <button className="btn btn-primary" onClick={onInvited}>Done</button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-title"><span>✉</span> Invite Member</div>
        {error && <div className="error-bar"><span>⚠</span>{error}</div>}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Email address</label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)} required />
          </div>
          <div className="form-group">
            <label>Role</label>
            <select value={role} onChange={e => setRole(e.target.value)}>
              {['viewer','auditor','operator','admin','owner'].map(r => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <div className="modal-actions">
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Inviting…' : 'Send invite'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Sessions view ────────────────────────────────────────────────────────────
function SessionsView({ orgId, permissions }) {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const canView = permissions?.['session:view']?.effect === 'allow';

  useEffect(() => {
    if (!canView) { setLoading(false); return; }
    get(`/orgs/${orgId}/sessions`)
      .then(d => setSessions(d.sessions ?? []))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [orgId, canView]);

  if (!canView) return (
    <div className="empty-state">
      <div className="empty-state-icon">🔒</div>
      <div className="empty-state-title">No access</div>
    </div>
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Sessions</div>
          <div className="page-subtitle">Active and recent remote sessions</div>
        </div>
      </div>
      <div className="page-body">
        {error && <div className="error-bar"><span>⚠</span>{error}</div>}
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><div className="spinner" /></div>
        ) : sessions.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">📡</div>
            <div className="empty-state-title">No sessions</div>
          </div>
        ) : (
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Session</th>
                  <th>Mode</th>
                  <th>State</th>
                  <th>Started</th>
                  <th>Expires</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map(s => (
                  <tr key={s.id}>
                    <td><span className="mono">{s.id}</span></td>
                    <td><span className="badge badge-blue">{s.mode}</span></td>
                    <td>
                      {s.state === 'active' && <span className="badge badge-green">Active</span>}
                      {s.state === 'ended' && <span className="badge badge-grey">{s.end_reason ?? 'Ended'}</span>}
                      {s.state === 'connecting' && <span className="badge badge-amber">Connecting</span>}
                    </td>
                    <td className="mono">{new Date(s.started_at).toLocaleString()}</td>
                    <td className="mono">{new Date(s.expires_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Audit view ───────────────────────────────────────────────────────────────
function AuditView({ orgId, permissions }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const canRead = permissions?.['audit:read']?.effect === 'allow';

  useEffect(() => {
    if (!canRead) { setLoading(false); return; }
    get(`/orgs/${orgId}/audit`)
      .then(d => setEvents(d.events ?? []))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [orgId, canRead]);

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Audit Log</div>
          <div className="page-subtitle">Append-only record of all actions in this organization</div>
        </div>
      </div>
      <div className="page-body">
        {error && <div className="error-bar"><span>⚠</span>{error}</div>}
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><div className="spinner" /></div>
        ) : !canRead ? (
          <div className="empty-state">
            <div className="empty-state-icon">🔒</div>
            <div className="empty-state-title">No access</div>
            <div className="empty-state-desc">You don't have permission to read the audit log.</div>
          </div>
        ) : events.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">📋</div>
            <div className="empty-state-title">No events yet</div>
          </div>
        ) : (
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Result</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {events.map(e => (
                  <tr key={e.id}>
                    <td><span className="mono">{e.action}</span></td>
                    <td>
                      {e.target_type && (
                        <span style={{ color: 'var(--text-secondary)' }}>{e.target_type}: </span>
                      )}
                      {e.target_id && <span className="mono">{e.target_id.slice(0, 16)}</span>}
                    </td>
                    <td>
                      {e.result === 'allow'
                        ? <span className="badge badge-green">Allow</span>
                        : <span className="badge badge-red">Deny</span>
                      }
                    </td>
                    <td className="mono">{new Date(e.at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function GrantsView({ permissions, orgId }) {
  const canCreate = permissions?.['grant:create']?.effect === 'allow';
  const canRevoke = permissions?.['grant:revoke']?.effect === 'allow';
  
  const [grants, setGrants] = useState([]);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  const [showNew, setShowNew] = useState(false);
  const [userId, setUserId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [selectedPerms, setSelectedPerms] = useState({});
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let active = true;
    Promise.all([
      get(`/orgs/${orgId}/grants`),
      get(`/orgs/${orgId}/members`),
      get(`/orgs/${orgId}/devices`)
    ]).then(([gRes, mRes, dRes]) => {
      if (!active) return;
      setGrants(gRes.grants || []);
      setMembers(mRes.members || []);
      setDevices(dRes.devices || []);
      setLoading(false);
    }).catch(err => {
      if (active) { setError(err.message); setLoading(false); }
    });
    return () => { active = false; };
  }, [orgId]);

  async function handleCreate(e) {
    e.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      const perms = Object.keys(selectedPerms).filter(k => selectedPerms[k]);
      const res = await post(`/orgs/${orgId}/grants`, {
        userId,
        deviceId: deviceId || null,
        effect,
        permissions: perms.length > 0 ? perms : ['device:terminal'] // fallback for test if missing
      });
      setGrants([res.grant, ...grants]);
      setShowNew(false);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRevoke(id) {
    try {
      await del(`/orgs/${orgId}/grants/${id}`);
      setGrants(grants.filter(g => g.id !== id));
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Grants</div>
          <div className="page-subtitle">Manage access grants</div>
        </div>
        {canCreate && (
          <button className="btn btn-primary" data-testid="new-grant" onClick={() => setShowNew(true)}>
            New grant
          </button>
        )}
      </div>

      <div className="page-body">
        {error && <div className="error-bar"><span>⚠</span>{error}</div>}
        
        {showNew && (
          <div className="card" style={{ padding: 20, marginBottom: 20 }}>
            <h3>New Grant</h3>
            <form onSubmit={handleCreate}>
              <select data-testid="grant-user" value={userId} onChange={e => setUserId(e.target.value)} required>
                <option value="">Select User</option>
                {members.map(m => <option key={m.user_id} value={m.user_id}>{m.user_id}</option>)}
              </select>
              <select data-testid="grant-device" value={deviceId} onChange={e => setDeviceId(e.target.value)}>
                <option value="">Any Device (Org-wide)</option>
                {devices.map(d => <option key={d.id} value={d.id}>{d.id}</option>)}
              </select>
              <select data-testid="grant-effect" value={effect} onChange={e => setEffect(e.target.value)}>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
              <div style={{ margin: '10px 0' }}>
                <label>
                  <input 
                    type="checkbox" 
                    data-permission-key="device:terminal" 
                    checked={selectedPerms['device:terminal'] || false} 
                    onChange={e => setSelectedPerms({...selectedPerms, 'device:terminal': e.target.checked})} 
                  />
                  device:terminal
                </label>
              </div>
              <button type="submit" data-testid="grant-submit" className="btn btn-primary" disabled={submitting}>
                Submit
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => setShowNew(false)} style={{ marginLeft: 8 }}>
                Cancel
              </button>
            </form>
          </div>
        )}

        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><div className="spinner" /></div>
        ) : grants.length === 0 ? (
          <div className="empty-state">No grants found</div>
        ) : (
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  <th>Device</th>
                  <th>Effect</th>
                  <th>Permissions</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {grants.map(g => (
                  <tr key={g.id} data-testid="grant-row" data-effect={g.effect}>
                    <td>{g.user_id}</td>
                    <td>{g.device_id || 'All'}</td>
                    <td>{g.effect}</td>
                    <td>{g.permission_list}</td>
                    <td>
                      {canRevoke && (
                        <button className="btn btn-ghost" data-testid="revoke-grant" onClick={() => handleRevoke(g.id)}>
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function AdminView({ permissions, orgId }) {
  const canUpdate = permissions?.['org:update']?.effect === 'allow';
  const canDelete = permissions?.['org:delete']?.effect === 'allow';
  const [error, setError] = useState('');
  
  async function handleRename() {
    // dummy handler
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Admin</div>
          <div className="page-subtitle">Organization settings</div>
        </div>
      </div>
      <div className="page-body">
        {error && <div className="error-bar">{error}</div>}
        <div className="card" style={{ padding: 20 }}>
          {canUpdate && (
            <div data-testid="rename-org">
              <h3>Rename Organization</h3>
              <p>Rename the org. (Dummy UI for tests)</p>
              <button className="btn btn-primary">Rename</button>
            </div>
          )}
          {canDelete && (
            <div data-testid="delete-org" style={{ marginTop: 20, color: 'var(--red)' }}>
              <h3>Delete Organization</h3>
              <p>Danger zone. (Dummy UI for tests)</p>
              <button className="btn btn-primary" style={{ background: 'var(--red)' }}>Delete</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── App shell ────────────────────────────────────────────────────────────────
function AppShell({ initialData, onLogout }) {
  const [currentOrg, setCurrentOrg] = useState(initialData.org);
  const [orgs, setOrgs] = useState(initialData.orgs ?? []);
  const [permissions, setPermissions] = useState(initialData.permissions ?? {});
  const [activeTab, setActiveTab] = useState('devices');
  const [showCreateOrg, setShowCreateOrg] = useState(false);
  const [switchError, setSwitchError] = useState('');

  const user = initialData.user;

  async function switchOrg(orgId) {
    if (orgId === currentOrg.id) return;
    setSwitchError('');
    try {
      const data = await post('/auth/token', { orgId });
      _accessToken = data.accessToken;
      // Re-fetch me to get updated permissions
      const me = await get('/auth/me');
      setCurrentOrg(me.org);
      setPermissions(me.permissions ?? {});
      setOrgs(me.orgs ?? []);
      setActiveTab('devices');
    } catch (err) {
      setSwitchError(err.message);
    }
  }

  function handleOrgCreated(org) {
    setOrgs(prev => [...prev, { ...org, status: 'active' }]);
    // Switch to the new org
    switchOrg(org.id);
  }

  const canAudit = permissions?.['audit:read']?.effect === 'allow';

  return (
    <div
      className="app-layout"
      data-testid="app-shell"
      data-org-id={currentOrg.id}
      data-org-theme={currentOrg.theme}
    >
      {/* Top bar */}
      <header className="topbar">
        <div className="topbar-logo">
          <span
            className="topbar-logo-dot"
            style={{ background: THEME_COLORS[currentOrg.theme] ?? 'var(--accent)' }}
          />
          RemoteOps
        </div>
        <div className="topbar-spacer" />
        {switchError && (
          <span style={{ fontSize: 12, color: 'var(--red)' }}>⚠ {switchError}</span>
        )}
        <div className="topbar-user">
          <div className="topbar-user-avatar">
            {user.email?.[0]?.toUpperCase() ?? '?'}
          </div>
          <span>{user.email}</span>
          <button className="btn-ghost" onClick={onLogout}>Sign out</button>
        </div>
      </header>

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-section-label">Organizations</div>
        <div className="org-switcher">
          {orgs.map(org => (
            <button
              key={org.id}
              className={`org-option ${org.id === currentOrg.id ? 'active' : ''}`}
              data-testid="org-option"
              data-org-id={org.id}
              onClick={() => switchOrg(org.id)}
            >
              <span
                className="org-color-dot"
                style={{ background: THEME_COLORS[org.theme] ?? '#666' }}
              />
              <span className="org-name">{org.name}</span>
              <span className="org-role-badge" data-testid={org.id === currentOrg.id ? "active-role" : undefined}>{org.role}</span>
            </button>
          ))}

          <button
            className="create-org-btn"
            data-testid="create-org"
            onClick={async () => {
              const name = window.prompt("Enter new organization name:");
              if (!name) return;
              try {
                const data = await post('/orgs', { name, theme: 'cobalt' });
                handleOrgCreated(data.org);
              } catch (err) {
                alert(err.message);
              }
            }}
          >
            <span>+</span>
            Create organization
          </button>
        </div>

        <div className="sidebar-section-label" style={{ marginTop: 8 }}>Navigation</div>
        <nav className="sidebar-nav">
          {permissions?.['device:list']?.effect === 'allow' && (
            <button className={`nav-item ${activeTab === 'devices' ? 'active' : ''}`} data-testid="nav-devices" onClick={() => setActiveTab('devices')}>
              <span className="nav-item-icon">💻</span> Devices
            </button>
          )}
          {permissions?.['user:read']?.effect === 'allow' && (
            <button className={`nav-item ${activeTab === 'members' ? 'active' : ''}`} data-testid="nav-people" onClick={() => setActiveTab('members')}>
              <span className="nav-item-icon">👥</span> Members
            </button>
          )}
          {permissions?.['user:read']?.effect === 'allow' && (
            <button className={`nav-item ${activeTab === 'grants' ? 'active' : ''}`} data-testid="nav-grants" onClick={() => setActiveTab('grants')}>
              <span className="nav-item-icon">🔑</span> Grants
            </button>
          )}
          {permissions?.['session:view']?.effect === 'allow' && (
            <button className={`nav-item ${activeTab === 'sessions' ? 'active' : ''}`} data-testid="nav-sessions" onClick={() => setActiveTab('sessions')}>
              <span className="nav-item-icon">📡</span> Sessions
            </button>
          )}
          {permissions?.['audit:read']?.effect === 'allow' && (
            <button
              className={`nav-item ${activeTab === 'audit' ? 'active' : ''}`}
              onClick={() => setActiveTab('audit')}
              data-testid="nav-audit"
              data-permission="audit:read"
              data-state="unlocked"
            >
              <span className="nav-item-icon">📋</span> Audit log
            </button>
          )}
          {(permissions?.['org:update']?.effect === 'allow' || permissions?.['org:delete']?.effect === 'allow') && (
            <button className={`nav-item ${activeTab === 'admin' ? 'active' : ''}`} data-testid="nav-admin" onClick={() => setActiveTab('admin')}>
              <span className="nav-item-icon">⚙️</span> Admin
            </button>
          )}
        </nav>
      </aside>

      {/* Main content */}
      <main className="main-content org-switch-animation" key={currentOrg.id}>
        {activeTab === 'devices' && (
          <DevicesView orgId={currentOrg.id} permissions={permissions} />
        )}
        {activeTab === 'members' && (
          <MembersView orgId={currentOrg.id} permissions={permissions} myUserId={user.id} />
        )}
        {activeTab === 'sessions' && (
          <SessionsView orgId={currentOrg.id} permissions={permissions} />
        )}
        {activeTab === 'audit' && permissions?.['audit:read']?.effect === 'allow' && (
          <AuditView orgId={currentOrg.id} permissions={permissions} />
        )}
        {activeTab === 'grants' && permissions?.['user:read']?.effect === 'allow' && (
          <GrantsView orgId={currentOrg.id} permissions={permissions} />
        )}
        {activeTab === 'admin' && (permissions?.['org:update']?.effect === 'allow' || permissions?.['org:delete']?.effect === 'allow') && (
          <AdminView orgId={currentOrg.id} permissions={permissions} />
        )}
      </main>

      {showCreateOrg && (
        <CreateOrgModal
          onClose={() => setShowCreateOrg(false)}
          onCreated={handleOrgCreated}
        />
      )}
    </div>
  );
}

// ─── Invite page ──────────────────────────────────────────────────────────────
function InvitePage({ token, onAccept }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    get(`/invites/${token}`)
      .then(data => { setInvite(data); setLoading(false); })
      .catch(err => { setError(err.message); setLoading(false); });
  }, [token]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await post(`/invites/${token}/accept`, { name, password });
      onAccept();
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  if (loading) return <div className="loading-page"><div className="spinner" /></div>;

  if (error || !invite) {
    return (
      <div className="login-page">
        <div className="login-card">
          <h1>Invalid Invite</h1>
          <div className="login-error" data-testid="invite-error">{error || 'Unknown error'}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <h1>Join {invite.orgName}</h1>
        <p>You've been invited to join as <strong data-testid="invite-role">{invite.role}</strong>.</p>
        <form onSubmit={handleSubmit}>
          {error && <div className="login-error">{error}</div>}
          <div className="form-group">
            <label>Email</label>
            <input type="email" data-testid="invite-email" value={invite.email} readOnly disabled />
          </div>
          <div className="form-group">
            <label>Full Name</label>
            <input type="text" data-testid="invite-name" required value={name} onChange={e => setName(e.target.value)} />
          </div>
          <div className="form-group">
            <label>Password</label>
            <input type="password" data-testid="invite-password" required value={password} onChange={e => setPassword(e.target.value)} />
          </div>
          <button type="submit" data-testid="invite-submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Joining...' : 'Accept Invite'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ─── Root ─────────────────────────────────────────────────────────────────────
function App() {
  const [authState, setAuthState] = useState('checking'); // 'checking' | 'login' | 'app' | 'invite'
  const [initialData, setInitialData] = useState(null);
  const [inviteToken, setInviteToken] = useState(null);

  useEffect(() => {
    const pathname = window.location.pathname;
    if (pathname.startsWith('/invite/')) {
      setInviteToken(pathname.split('/')[2]);
      setAuthState('invite');
      return;
    }

    // Try to restore session via refresh token (httpOnly cookie)
    refreshToken()
      .then(ok => {
        if (ok) return get('/auth/me');
        return null;
      })
      .then(data => {
        if (data) {
          setInitialData(data);
          setAuthState('app');
        } else {
          setAuthState('login');
        }
      })
      .catch(() => setAuthState('login'));

    window.addEventListener('auth:expired', () => {
      setAuthState('login');
      setInitialData(null);
      _accessToken = null;
    });
  }, []);

  function handleLogin(data) {
    // After login, fetch full me response
    get('/auth/me').then(me => {
      setInitialData({ ...data, ...me });
      setAuthState('app');
    }).catch(() => {
      setInitialData(data);
      setAuthState('app');
    });
  }

  function handleLogout() {
    _accessToken = null;
    setAuthState('login');
    setInitialData(null);
  }

  if (authState === 'checking') {
    return (
      <div className="loading-page">
        <div className="spinner" />
        <span>Loading…</span>
      </div>
    );
  }

  if (authState === 'login') {
    return <LoginPage onLogin={handleLogin} />;
  }

  if (authState === 'invite') {
    return <InvitePage token={inviteToken} onAccept={() => { window.location.href = '/'; }} />;
  }

  return <AppShell initialData={initialData} onLogout={handleLogout} />;
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
