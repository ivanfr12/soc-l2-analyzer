import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: number | null;
  description: string;
  icon: LucideIcon;
  accent: "cyan" | "blue" | "violet" | "amber" | "green" | "muted";
}

export default function StatCard({
  label,
  value,
  description,
  icon: Icon,
  accent,
}: StatCardProps) {
  return (
    <article className={`stat-card stat-card--${accent}`}>
      <div className="stat-card__top">
        <span>{label}</span>
        <span className="stat-card__icon">
          <Icon aria-hidden="true" size={17} />
        </span>
      </div>
      <strong className="stat-card__value">
        {value === null ? "No evaluable" : value.toLocaleString("es-ES")}
      </strong>
      <span className="stat-card__description">{description}</span>
    </article>
  );
}
