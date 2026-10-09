import { useState } from "react";
import { setOperatorToken } from "../api/client";

export default function OperatorBar() {
  const [token, setToken] = useState(localStorage.getItem("zerotrace_operator_token") || "");
  const [saved, setSaved] = useState(false);

  return (
    <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
      <span className="text-xs text-slate-500">Operator token</span>
      <input
        type="password"
        value={token}
        onChange={(e) => {
          setToken(e.target.value);
          setSaved(false);
        }}
        placeholder="demo-token"
        className="w-40 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-slate-200 outline-none focus:border-trust-600"
      />
      <button
        onClick={() => {
          setOperatorToken(token);
          setSaved(true);
        }}
        className="rounded bg-trust-700 px-2 py-1 text-xs font-medium text-white hover:bg-trust-600"
      >
        {saved ? "Saved" : "Save"}
      </button>
    </div>
  );
}
