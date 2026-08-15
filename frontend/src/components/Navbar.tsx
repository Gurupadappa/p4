import { NavLink } from "react-router-dom";

interface NavbarProps {
  theme: "light" | "dark";
  onToggleTheme: () => void;
}

const LINKS = [
  { to: "/", label: "Home", end: true },
  { to: "/dashboard", label: "Dashboard", end: false },
  { to: "/history", label: "History", end: false },
];

export function Navbar({ theme, onToggleTheme }: NavbarProps) {
  return (
    <header
      className="sticky top-0 z-40 w-full"
      style={{ background: "var(--nav-bg)", borderBottom: "1px solid var(--nav-border)" }}
    >
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6 sm:px-10">
        <NavLink to="/" className="flex items-center gap-2.5" style={{ color: "var(--nav-ink)" }}>
          <span
            className="font-display flex h-8 w-8 items-center justify-center rounded-full text-sm font-semibold"
            style={{ background: "var(--gold)", color: "var(--gold-ink)" }}
          >
            P4
          </span>
          {/* <span className="font-display hidden text-base font-semibold tracking-tight sm:inline">
            P4
          </span> */}
        </NavLink>

        <nav className="flex items-center gap-1" aria-label="Primary">
          {LINKS.map(({ to, label, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className="font-mono rounded-full px-4 py-1.5 text-[0.78rem] transition-colors"
              style={({ isActive }) => ({
                color: isActive ? "var(--gold)" : "var(--nav-ink-muted)",
                background: isActive ? "rgba(139, 115, 85, 0.16)" : "transparent",
              })}
            >
              {label}
            </NavLink>
          ))}
        
          <button
            type="button"
            onClick={onToggleTheme}
            aria-label="Toggle color theme"
            title="Toggle color theme"
            className="ml-2 flex h-8 w-8 cursor-pointer items-center justify-center rounded-full text-sm"
            style={{ color: "var(--nav-ink)", border: "1px solid var(--nav-border)" }}
          >
            {theme === "dark" ? "☀" : "☽"}
          </button>
        </nav>
      </div>
    </header>
  );
}
