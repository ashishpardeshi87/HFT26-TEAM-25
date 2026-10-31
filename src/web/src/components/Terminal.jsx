import { useEffect, useRef } from "react";

const cls = (l) =>
  /ERROR|failed|unreachable/i.test(l) ? "e"
  : /DROPPED|skipped|•/i.test(l) ? "w"
  : /✓|classified|Done|breach|complete/i.test(l) ? "o" : "";

export default function Terminal({ logs = [] }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [logs]);
  return (
    <pre className="terminal" ref={ref}>
      {logs.length
        ? logs.map((l, i) => <div key={i} className={cls(l)}>{l}</div>)
        : "waiting for process output…"}
    </pre>
  );
}
