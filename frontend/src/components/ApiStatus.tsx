import { CircleCheck, CircleX, LoaderCircle } from "lucide-react";

export type ConnectionState = "checking" | "online" | "offline";

const stateLabels: Record<ConnectionState, string> = {
  checking: "Verificando API",
  online: "API conectada",
  offline: "API no disponible",
};

interface ApiStatusProps {
  state: ConnectionState;
}

export default function ApiStatus({ state }: ApiStatusProps) {
  const Icon =
    state === "online"
      ? CircleCheck
      : state === "offline"
        ? CircleX
        : LoaderCircle;

  return (
    <div className={`api-status api-status--${state}`} role="status">
      <Icon aria-hidden="true" size={15} />
      <span>{stateLabels[state]}</span>
    </div>
  );
}
