import { useEffect, useRef } from "react";

// ── Ambient network field ───────────────────────────────────────────────────
//
// A lightweight canvas backdrop: drifting nodes, proximity links, and a few
// packets travelling the links — the "live mesh" motif, as a non-interactive
// layer behind content. Sizes itself to its parent, pauses when the tab is
// hidden or the user prefers reduced motion, and is DPR-aware so lines stay
// crisp. Pointer events pass straight through.

export default function NetworkField({
  density = 0.00009,   // nodes per pixel of area
  max = 70,
  color = "198,255,58", // acid, as "r,g,b"
  linkDist = 150,
  speed = 0.22,
  opacity = 0.5,
  style,
  className,
}) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const parent = canvas.parentElement;
    const ctx = canvas.getContext("2d");
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let W = 0, H = 0, dpr = Math.min(2, window.devicePixelRatio || 1);
    let nodes = [];
    let packets = [];
    let raf = 0;
    let running = true;

    const seed = () => {
      const area = W * H;
      const n = Math.max(14, Math.min(max, Math.round(area * density)));
      nodes = Array.from({ length: n }, () => ({
        x: Math.random() * W,
        y: Math.random() * H,
        vx: (Math.random() - 0.5) * speed,
        vy: (Math.random() - 0.5) * speed,
        r: 1 + Math.random() * 1.8,
      }));
      // A handful of packets ride between random node pairs.
      packets = Array.from({ length: Math.max(3, Math.round(n / 7)) }, () => ({
        a: (Math.random() * n) | 0,
        b: (Math.random() * n) | 0,
        t: Math.random(),
        spd: 0.004 + Math.random() * 0.006,
      }));
    };

    const resize = () => {
      W = parent.clientWidth || canvas.clientWidth || 600;
      H = parent.clientHeight || canvas.clientHeight || 400;
      dpr = Math.min(2, window.devicePixelRatio || 1);
      canvas.width = Math.floor(W * dpr);
      canvas.height = Math.floor(H * dpr);
      canvas.style.width = `${W}px`;
      canvas.style.height = `${H}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      seed();
    };

    const draw = () => {
      ctx.clearRect(0, 0, W, H);

      for (const p of nodes) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
      }

      // Proximity links.
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d = Math.hypot(dx, dy);
          if (d < linkDist) {
            const al = (1 - d / linkDist) * 0.5 * opacity;
            ctx.strokeStyle = `rgba(${color},${al.toFixed(3)})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // Nodes.
      for (const p of nodes) {
        ctx.fillStyle = `rgba(${color},${(0.65 * opacity).toFixed(3)})`;
        ctx.fillRect(p.x - p.r, p.y - p.r, p.r * 2, p.r * 2);
      }

      // Packets travelling between node pairs.
      for (const k of packets) {
        const a = nodes[k.a], b = nodes[k.b];
        if (!a || !b) { k.a = (Math.random() * nodes.length) | 0; k.b = (Math.random() * nodes.length) | 0; continue; }
        k.t += k.spd;
        if (k.t >= 1) { k.t = 0; k.a = k.b; k.b = (Math.random() * nodes.length) | 0; }
        const x = a.x + (b.x - a.x) * k.t;
        const y = a.y + (b.y - a.y) * k.t;
        ctx.fillStyle = `rgba(${color},${(0.9 * opacity).toFixed(3)})`;
        ctx.beginPath();
        ctx.arc(x, y, 1.9, 0, Math.PI * 2);
        ctx.fill();
      }

      if (running) raf = requestAnimationFrame(draw);
    };

    const onVis = () => {
      running = !document.hidden && !reduce;
      if (running) { cancelAnimationFrame(raf); raf = requestAnimationFrame(draw); }
      else cancelAnimationFrame(raf);
    };

    resize();
    const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(resize) : null;
    ro && ro.observe(parent);
    document.addEventListener("visibilitychange", onVis);

    if (reduce) {
      draw();                     // one static frame
      running = false;
    } else {
      raf = requestAnimationFrame(draw);
    }

    return () => {
      cancelAnimationFrame(raf);
      ro && ro.disconnect();
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [density, max, color, linkDist, speed, opacity]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className={className}
      style={{
        position: "absolute", inset: 0, width: "100%", height: "100%",
        pointerEvents: "none", display: "block", ...style,
      }}
    />
  );
}
