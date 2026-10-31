import { NavLink } from "react-router-dom";

export default function Nav({ connected }) {
  const link = ({ isActive }) =>
    `px-3 py-1.5 border-[3px] border-ink font-bold uppercase text-xs tracking-wide transition-all ${
      isActive ? "bg-ink text-volt" : "bg-panel hover:bg-volt"
    }`;

  return (
    <header className="sticky top-0 z-40 border-b-[3px] border-ink bg-paper/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-3 px-4 py-3">
        <NavLink to="/" className="flex items-center gap-2">
          <span className="grid h-9 w-9 place-items-center border-[3px] border-ink bg-crit text-white shadow-brutal-sm">
            <span className="font-display text-lg font-bold">S</span>
          </span>
          <div className="leading-none">
            <div className="font-display text-lg font-bold tracking-tight">SENTINEL APEX</div>
            <div className="font-mono text-[10px] uppercase tracking-widest text-ink/60">AI Shadow IT Scanner</div>
          </div>
        </NavLink>

        <nav className="flex items-center gap-2">
          <NavLink to="/" className={link} end>Home</NavLink>
          <NavLink to="/dashboard" className={link}>Command Center</NavLink>
          <NavLink to="/architecture" className={link}>Architecture</NavLink>
        </nav>

        <div className="hidden items-center gap-2 sm:flex">
          <span className={`h-3 w-3 border-2 border-ink ${connected ? "bg-low animate-blink" : "bg-crit"}`} />
          <span className="font-mono text-[11px] uppercase">{connected ? "live" : "offline"}</span>
        </div>
      </div>
    </header>
  );
}
