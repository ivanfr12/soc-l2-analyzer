import { LoaderCircle } from "lucide-react";

export default function LoadingState() {
  return (
    <div className="loading-state" role="status" aria-live="polite">
      <LoaderCircle aria-hidden="true" className="spin" size={19} />
      <span>Validando el workbook y ejecutando las reglas disponibles…</span>
    </div>
  );
}
