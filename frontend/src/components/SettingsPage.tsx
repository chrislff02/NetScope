import {
  Activity,
  Accessibility,
  Database,
  Info,
  RotateCcw,
  Settings as SettingsIcon,
  Table2,
} from "lucide-react";

interface SettingsPageProps {
  compactTables: boolean;
  reduceMotion: boolean;
  onCompactTablesChange: (enabled: boolean) => void;
  onReduceMotionChange: (enabled: boolean) => void;
  onReset: () => void;
  packetCount: number;
  loading: boolean;
  error: string | null;
}

function SettingsPage({
  compactTables,
  reduceMotion,
  onCompactTablesChange,
  onReduceMotionChange,
  onReset,
  packetCount,
  loading,
  error,
}: SettingsPageProps) {
  const savedDataStatus = loading
    ? "Loading"
    : error
      ? "Unavailable"
      : "Loaded";

  return (
    <section className="settings-page">
      <div className="capture-toolbar">
        <div>
          <h2>Settings</h2>
          <p>
            Customize NetScope's appearance and review application information.
          </p>
        </div>
      </div>

      {/* Display preferences */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>Display Preferences</h3>
            <p>Preferences are saved locally in your browser.</p>
          </div>

          <SettingsIcon size={20} />
        </div>

        <div className="settings-options">
          <label className="settings-option">
            <span className="settings-option-icon">
              <Table2 size={20} />
            </span>

            <span className="settings-option-text">
              <strong>Compact Tables</strong>
              <span>Reduce row spacing in packet and traffic tables.</span>
            </span>

            <input
              type="checkbox"
              checked={compactTables}
              onChange={(event) => onCompactTablesChange(event.target.checked)}
            />
          </label>

          <label className="settings-option">
            <span className="settings-option-icon">
              <Accessibility size={20} />
            </span>

            <span className="settings-option-text">
              <strong>Reduce Animations</strong>
              <span>Minimize interface animations and transitions.</span>
            </span>

            <input
              type="checkbox"
              checked={reduceMotion}
              onChange={(event) => onReduceMotionChange(event.target.checked)}
            />
          </label>
        </div>

        <div className="settings-actions">
          <button
            type="button"
            className="capture-refresh-button"
            onClick={onReset}
            disabled={!compactTables && !reduceMotion}
          >
            <RotateCcw size={16} />
            Reset Preferences
          </button>
        </div>
      </div>

      {/* Application information */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>Application Information</h3>
            <p>Current NetScope build and saved data information.</p>
          </div>

          <Info size={20} />
        </div>

        <div className="settings-info-grid">
          <div className="settings-info-item">
            <SettingsIcon size={18} />
            <span>Application</span>
            <strong>NetScope</strong>
          </div>

          <div className="settings-info-item">
            <Info size={18} />
            <span>Version</span>
            <strong>v0.1.0</strong>
          </div>

          <div className="settings-info-item">
            <Database size={18} />
            <span>Saved Capture API</span>
            <strong>{savedDataStatus}</strong>
          </div>

          <div className="settings-info-item">
            <Activity size={18} />
            <span>Loaded Packet Records</span>
            <strong>
              {loading || error ? "—" : packetCount.toLocaleString()}
            </strong>
          </div>
        </div>
      </div>

      {/* Explain the scope of browser settings. */}
      <div className="panel settings-note">
        <h3>About These Settings</h3>

        <p>
          Display preferences apply only to this browser. They do not change the
          packet capture process, backend configuration, or stored network
          traffic.
        </p>

        <p>
          NetScope captures network packet metadata through its Python backend.
          Live capture permissions and network interfaces are configured
          separately.
        </p>
      </div>
    </section>
  );
}

export default SettingsPage;
