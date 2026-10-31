import { Routes, Route } from "react-router-dom";
import Nav from "./components/Nav.jsx";
import Home from "./pages/Home.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Architecture from "./pages/Architecture.jsx";
import { useLiveFeed } from "./api.js";

export default function App() {
  const feed = useLiveFeed();
  return (
    <div className="min-h-screen">
      <Nav connected={feed.connected} />
      <Routes>
        <Route path="/" element={<Home stats={feed.stats} />} />
        <Route path="/dashboard" element={<Dashboard feed={feed} />} />
        <Route path="/architecture" element={<Architecture />} />
      </Routes>
      <footer className="border-t-[3px] border-ink bg-ink px-4 py-6 text-paper">
        <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-2 sm:flex-row sm:items-center">
          <div className="font-display font-bold">SENTINEL APEX</div>
          <div className="font-mono text-xs text-paper/70">
            TEAM-25 · The Nice Guys · CBIT Hacktoberfest '26 · AI Security &amp; Data Privacy
          </div>
        </div>
      </footer>
    </div>
  );
}
