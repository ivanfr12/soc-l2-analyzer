import { AlertTriangle, X } from "lucide-react";

export interface UiError {
  title: string;
  message: string;
  kind: "validation" | "connection" | "unexpected";
}

interface ErrorNoticeProps {
  error: UiError;
  onDismiss?: () => void;
}

export default function ErrorNotice({ error, onDismiss }: ErrorNoticeProps) {
  return (
    <div className={`error-notice error-notice--${error.kind}`} role="alert">
      <span className="error-notice__icon">
        <AlertTriangle aria-hidden="true" size={18} />
      </span>
      <div>
        <strong>{error.title}</strong>
        <p>{error.message}</p>
      </div>
      {onDismiss && (
        <button className="icon-button error-notice__close" onClick={onDismiss} aria-label="Cerrar aviso">
          <X aria-hidden="true" size={17} />
        </button>
      )}
    </div>
  );
}
