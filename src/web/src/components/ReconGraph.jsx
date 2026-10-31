import { useEffect, useRef } from "react";
import ForceGraph3D from "3d-force-graph";
import SpriteText from "three-spritetext";

// Visual styling per entity type — this is the "route map" of the investigation.
const SEV = { critical: "#ff453a", high: "#ffb020", medium: "#4cc9f0", low: "#3ddc97", info: "#8d8d85" };
const TYPE = {
  root:       { color: "#c6ff3a", val: 16 },
  email:      { color: "#c6ff3a", val: 10 },
  registrar:  { color: "#b56cff", val: 7 },
  nameserver: { color: "#4cc9f0", val: 6 },
  mailhost:   { color: "#4cc9f0", val: 6 },
  ip:         { color: "#6aa9ff", val: 8 },
  asn:        { color: "#ffb020", val: 7 },
  subdomain:  { color: "#8d8d85", val: 5 },
  neighbor:   { color: "#7a7a72", val: 4 },
  tech:       { color: "#3ddc97", val: 6 },
  port:       { color: "#ffb020", val: 5 },
  port_risky: { color: "#ff453a", val: 7 },
  finding:    { color: "#ff453a", val: 5 },
};

function toGraph(graph) {
  const nodes = (graph.nodes || []).map((n) => {
    const t = TYPE[n.type] || { color: "#8d8d85", val: 5 };
    const color = n.type === "finding" ? (SEV[n.severity] || t.color) : t.color;
    const name = [
      `${n.type.toUpperCase()} · ${n.label}`,
      n.engine ? `source: ${n.engine}` : null,
      n.snippet ? n.snippet.slice(0, 120) : null,
      n.url || null,
    ].filter(Boolean).join("\n");
    return { id: n.id, label: n.label, type: n.type, url: n.url || null, color, val: t.val, name };
  });
  const links = (graph.edges || []).map((e) => ({ source: e.source, target: e.target, label: e.label || "" }));
  return { nodes, links };
}

export default function ReconGraph({ graph, height = 520 }) {
  const ref = useRef(null);

  useEffect(() => {
    if (!ref.current || !graph) return;
    const el = ref.current;
    const width = el.clientWidth || 600;

    const G = ForceGraph3D()(el)
      .graphData(toGraph(graph))
      .backgroundColor("rgba(0,0,0,0)")
      .width(width)
      .height(height)
      .nodeColor("color")
      .nodeVal("val")
      .nodeOpacity(0.95)
      .nodeResolution(12)
      .linkColor(() => "rgba(198,255,58,0.18)")
      .linkWidth(0.5)
      .linkLabel((l) => l.label)
      .linkDirectionalParticles(1)
      .linkDirectionalParticleWidth(1.4)
      .linkDirectionalParticleColor(() => "rgba(198,255,58,0.5)")
      .nodeThreeObjectExtend(true)
      .nodeThreeObject((node) => {
        const txt = new SpriteText(node.label.length > 26 ? node.label.slice(0, 26) + "…" : node.label);
        txt.color = node.color;
        txt.backgroundColor = "rgba(8,8,10,0.7)";
        txt.padding = node.type === "root" ? 3 : 2;
        txt.fontFace = "JetBrains Mono, monospace";
        txt.fontWeight = "700";
        txt.textHeight = node.type === "root" ? 6 : node.type === "ip" || node.type === "asn" ? 4 : 3;
        txt.position.y = node.val + 6;
        return txt;
      })
      .onNodeClick((node) => { if (node.url) window.open(node.url, "_blank", "noopener"); })
      .onNodeHover((node) => { el.style.cursor = node && node.url ? "pointer" : "grab"; })
      .showNavInfo(false);

    G.controls().autoRotate = true;
    G.controls().autoRotateSpeed = 0.5;
    G.onEngineStop(() => { try { G.zoomToFit(600, 55); } catch { /* noop */ } });

    const onResize = () => G.width(el.clientWidth || width);
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      try { G._destructor && G._destructor(); } catch { /* noop */ }
      el.innerHTML = "";
    };
  }, [graph, height]);

  return <div ref={ref} style={{ width: "100%", minHeight: height, cursor: "grab" }} />;
}
