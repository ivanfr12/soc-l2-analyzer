import type { ReactNode } from "react";

import type { ConnectionState } from "./ApiStatus";
import Header from "./Header";
import Sidebar from "./Sidebar";

interface AppShellProps {
  connection: ConnectionState;
  onNavigate: (section: "dashboard" | "upload") => void;
  children: ReactNode;
}

export default function AppShell({
  connection,
  onNavigate,
  children,
}: AppShellProps) {
  return (
    <div className="app-shell">
      <Sidebar onNavigate={onNavigate} />
      <div className="app-shell__main">
        <Header connection={connection} />
        {children}
      </div>
    </div>
  );
}
