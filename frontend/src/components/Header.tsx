import { Bell, ShieldCheck } from "lucide-react";

import ApiStatus, { type ConnectionState } from "./ApiStatus";

interface HeaderProps {
  connection: ConnectionState;
}

export default function Header({ connection }: HeaderProps) {
  return (
    <header className="topbar">
      <div className="topbar__section">
        <span className="topbar__eyebrow">OPERACIONES DE SEGURIDAD</span>
        <h1>Centro de análisis</h1>
      </div>
      <div className="topbar__actions">
        <div className="contract-chip" title="Alcance de respuesta actualmente soportado">
          <ShieldCheck aria-hidden="true" size={15} />
          <span>analysis-partial/1</span>
          <span className="contract-chip__partial">PARCIAL</span>
        </div>
        <ApiStatus state={connection} />
        <span className="topbar__divider" />
        <button
          className="icon-button"
          aria-label="Notificaciones no disponibles"
          disabled
          title="No hay notificaciones en esta versión"
        >
          <Bell aria-hidden="true" size={18} />
        </button>
        <span className="local-session-pill">SESIÓN LOCAL</span>
      </div>
    </header>
  );
}
