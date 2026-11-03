import {
  Activity,
  ArrowUpRight,
  ClipboardList,
  LayoutDashboard,
  Shield,
} from "lucide-react";

interface SidebarProps {
  onNavigate: (section: "dashboard" | "upload") => void;
}

export default function Sidebar({ onNavigate }: SidebarProps) {
  return (
    <aside className="sidebar">
      <a
        className="brand"
        href="#dashboard"
        onClick={(event) => {
          event.preventDefault();
          onNavigate("dashboard");
        }}
        aria-label="SOC L2 Analyzer, ir al dashboard"
      >
        <span className="brand-mark">
          <Shield aria-hidden="true" size={21} strokeWidth={2.2} />
          <Activity aria-hidden="true" className="brand-mark__pulse" size={11} />
        </span>
        <span className="brand-copy">
          <strong>SOC L2</strong>
          <small>ANALYZER</small>
        </span>
      </a>

      <div className="sidebar-section-label">ESPACIO DE TRABAJO</div>
      <nav className="sidebar-nav" aria-label="Navegación principal">
        <button
          className="nav-item nav-item--active"
          onClick={() => onNavigate("dashboard")}
        >
          <LayoutDashboard aria-hidden="true" size={18} />
          <span>Dashboard</span>
          <span className="nav-item__active-dot" />
        </button>
        <button className="nav-item" onClick={() => onNavigate("upload")}>
          <ClipboardList aria-hidden="true" size={18} />
          <span>Nuevo análisis</span>
          <ArrowUpRight aria-hidden="true" className="nav-item__arrow" size={14} />
        </button>
        <button
          className="nav-item nav-item--disabled"
          disabled
          title="La exploración de hallazgos queda pendiente"
        >
          <Activity aria-hidden="true" size={18} />
          <span>Hallazgos</span>
          <span className="nav-item__soon">PENDIENTE</span>
        </button>
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-footer__signal">
          <span className="signal-dot" />
          <span>Motor de reglas determinista</span>
        </div>
        <p>Sin persistencia · Sin incidentes confirmados</p>
        <span className="sidebar-version">SOC L2 ANALYZER <b>0.1</b></span>
      </div>
    </aside>
  );
}
