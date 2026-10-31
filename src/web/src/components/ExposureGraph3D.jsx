import { useEffect, useRef } from "react";
import ForceGraph3D from "3d-force-graph";
import SpriteText from "three-spritetext";

const SEV_COLOR = { critical: "#ff453a", high: "#ffb020", medium: "#4cc9f0", low: "#3ddc97", info: "#8d8d85", breach: "#ff453a" };

// Builds a 3D node graph: target → sources → findings, marking dark-web
// (.onion) nodes distinctly from public/clearnet links and showing URLs.
function buildGraph(scan) {
  const nodes = [{
    id: "root", group: "root", color: "#c6ff3a", val: 18,
    label: "TARGET", name: `TARGET · ${scan.target_url || scan.query}`,
  }];
  const links = [];
  const findings = (scan.findings || []).slice(0, 90);
  const sources = [...new Set(findings.map((f) => f.engine || "unknown"))];

  for (const s of sources) {
    const onion = /tor|onion|ahmia|phobos|deeplink|tordex/i.test(s);
    nodes.push({
      id: `src:${s}`, group: "source", color: onion ? "#b56cff" : "#4cc9f0", val: 9,
      label: s.toUpperCase(), name: `${onion ? "DARKWEB" : "PUBLIC"} · ${s}`,
    });
    links.push({ source: "root", target: `src:${s}` });
  }
  findings.forEach((f, i) => {
    const id = `f:${i}`;
    const isOnion = (f.onion_url || "").includes(".onion");
    const short = (f.title || f.category || "finding").slice(0, 22);
    nodes.push({
      id, group: "finding", url: f.onion_url || null,
      color: isOnion ? "#b56cff" : (SEV_COLOR[f.severity] || "#8d8d85"),
      val: f.severity === "critical" ? 5 : 3,
      label: `${(f.severity || "info").toUpperCase()}`,
      name: `${isOnion ? "[ONION] " : ""}${(f.severity || "info").toUpperCase()} · ${f.title || f.category}${f.onion_url ? `\n${f.onion_url}` : ""}`,
      sub: short,
    });
    links.push({ source: `src:${f.engine || "unknown"}`, target: id });
  });
  return { nodes, links };
}

export default function ExposureGraph3D({ scan }) {
  const ref = useRef(null);

  useEffect(() => {
    if (!ref.current) return;
    const el = ref.current;
    const width = el.clientWidth || 600;

    const G = ForceGraph3D()(el)
      .graphData(buildGraph(scan))
      .backgroundColor("rgba(0,0,0,0)")
      .width(width)
      .height(440)
      .nodeColor("color")
      .nodeVal("val")
      .nodeOpacity(0.95)
      .nodeResolution(12)
      .linkColor(() => "rgba(198,255,58,0.22)")
      .linkWidth(0.6)
      .nodeThreeObjectExtend(true)
      // Always-visible text label above each node.
      .nodeThreeObject((node) => {
        const txt = new SpriteText(node.group === "finding" ? `${node.label}` : `${node.label}`);
        txt.color = node.color;
        txt.backgroundColor = "rgba(8,8,10,0.65)";
        txt.padding = node.group === "root" ? 3 : 2;
        txt.fontFace = "JetBrains Mono, monospace";
        txt.fontWeight = "700";
        txt.textHeight = node.group === "root" ? 6 : node.group === "source" ? 4.5 : 3.2;
        txt.position.y = node.val + 6;
        return txt;
      })
      .onNodeClick((node) => { if (node.url) window.open(node.url, "_blank", "noopener"); })
      .onNodeHover((node) => { el.style.cursor = node && node.url ? "pointer" : "grab"; })
      .showNavInfo(false);

    // Gentle auto-rotate of the camera for a "live" feel.
    G.controls().autoRotate = true;
    G.controls().autoRotateSpeed = 0.6;
    // Frame the whole graph once the force layout settles.
    G.onEngineStop(() => { try { G.zoomToFit(600, 55); } catch { /* noop */ } });

    const onResize = () => G.width(el.clientWidth || width);
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      try { G._destructor && G._destructor(); } catch { /* noop */ }
      el.innerHTML = "";
    };
  }, [scan]);

  return <div ref={ref} style={{ width: "100%", minHeight: 440, cursor: "grab" }} />;
}
