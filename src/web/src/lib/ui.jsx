import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

// ── In-app UI: toasts + dialogs ─────────────────────────────────────────────
// Replaces the browser's native alert()/prompt()/confirm() with on-brand cards.
//   const toast = useToast();                  toast("Saved", "ok")
//   const { prompt, confirm, alert } = useDialog();
//   const name = await prompt({ title: "New workspace", label: "Name" });
//   const ok   = await confirm({ title: "Delete?", danger: true });

const UICtx = createContext(null);

export function UIProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const [dialog, setDialog] = useState(null); // active dialog config + resolver
  const [value, setValue] = useState("");
  const idRef = useRef(0);
  const inputRef = useRef(null);

  const dismiss = useCallback((id) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  const toast = useCallback((message, type = "info", ttl = 4500) => {
    const id = ++idRef.current;
    setToasts((t) => [...t, { id, message: String(message ?? ""), type }]);
    if (ttl > 0) setTimeout(() => dismiss(id), ttl);
    return id;
  }, [dismiss]);

  const openDialog = useCallback(
    (cfg) =>
      new Promise((resolve) => {
        setValue(cfg.defaultValue ?? "");
        setDialog({ ...cfg, resolve });
      }),
    []
  );

  const prompt = useCallback((opts = {}) => openDialog({ kind: "prompt", ...opts }), [openDialog]);
  const confirm = useCallback((opts = {}) => openDialog({ kind: "confirm", ...opts }), [openDialog]);
  const alert = useCallback((opts = {}) => openDialog({ kind: "alert", ...opts }), [openDialog]);

  const settle = useCallback(
    (result) => {
      if (!dialog) return;
      dialog.resolve(result);
      setDialog(null);
      setValue("");
    },
    [dialog]
  );

  // Focus the input / confirm button when a dialog opens.
  useEffect(() => {
    if (dialog && inputRef.current) inputRef.current.focus();
  }, [dialog]);

  // Esc to cancel, Enter to confirm (handled at document level for reliability).
  useEffect(() => {
    if (!dialog) return;
    const onKey = (e) => {
      if (e.key === "Escape") settle(dialog.kind === "confirm" ? false : null);
      else if (e.key === "Enter" && dialog.kind !== "prompt") accept();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dialog, value]);

  const accept = () => {
    if (!dialog) return;
    if (dialog.kind === "prompt") {
      const v = value.trim();
      settle(v ? v : null);
    } else if (dialog.kind === "confirm") {
      settle(true);
    } else {
      settle(true); // alert
    }
  };

  const cancel = () => settle(dialog?.kind === "confirm" ? false : null);

  return (
    <UICtx.Provider value={{ toast, prompt, confirm, alert }}>
      {children}

      {/* Toasts */}
      <div className="toast-wrap" role="region" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.type}`} onClick={() => dismiss(t.id)}>
            <span className="toast-bar" />
            <span className="toast-msg">{t.message}</span>
            <button className="toast-x" aria-label="Dismiss" onClick={(e) => { e.stopPropagation(); dismiss(t.id); }}>×</button>
          </div>
        ))}
      </div>

      {/* Dialog */}
      {dialog && (
        <div className="modal-overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) cancel(); }}>
          <div className={`modal-card ticked${dialog.danger ? " danger" : ""}`} role="dialog" aria-modal="true">
            <div className="modal-head">
              <span className="eyebrow">{dialog.eyebrow ?? (dialog.danger ? "// Confirm" : "// SENTINEL APEX")}</span>
            </div>
            <div className="modal-body">
              {dialog.title && <h2 className="display modal-title">{dialog.title}</h2>}
              {dialog.message && <p className="modal-msg">{dialog.message}</p>}

              {dialog.kind === "prompt" && (
                <label className="fld" style={{ marginTop: 14 }}>
                  {dialog.label && <span>{dialog.label}</span>}
                  <input
                    ref={inputRef}
                    className="input"
                    value={value}
                    placeholder={dialog.placeholder ?? ""}
                    onChange={(e) => setValue(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") accept(); }}
                  />
                </label>
              )}
            </div>
            <div className="modal-actions">
              {dialog.kind !== "alert" && (
                <button className="btn btn-sm" onClick={cancel}>{dialog.cancelText ?? "Cancel"}</button>
              )}
              <button
                ref={dialog.kind !== "prompt" ? inputRef : null}
                className={`btn btn-sm ${dialog.danger ? "btn-danger" : "btn-primary"}`}
                onClick={accept}
              >
                {dialog.okText ?? (dialog.kind === "confirm" ? "Confirm" : dialog.kind === "alert" ? "OK" : "Create")}
              </button>
            </div>
          </div>
        </div>
      )}
    </UICtx.Provider>
  );
}

export function useUI() {
  const ctx = useContext(UICtx);
  if (!ctx) throw new Error("useUI must be used within <UIProvider>");
  return ctx;
}

export const useToast = () => useUI().toast;
export const useDialog = () => {
  const { prompt, confirm, alert } = useUI();
  return { prompt, confirm, alert };
};
