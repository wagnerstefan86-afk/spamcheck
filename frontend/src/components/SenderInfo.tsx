"use client";

import { useState } from "react";

type Props = {
  result: any;
};

export default function SenderInfo({ result }: Props) {
  const [maskEmails, setMaskEmails] = useState(false);

  const mask = (val: string | null | undefined) => {
    if (!val) return "\u2014";
    if (!maskEmails) return val;
    return val.replace(/([a-zA-Z0-9._%+-]+)@/g, "***@");
  };

  const fields = [
    { label: "Betreff", value: result.subject || "\u2014", mono: false },
    { label: "Von", value: mask(result.sender?.from_address), mono: false },
    { label: "An", value: mask(result.sender?.to), mono: false },
    { label: "Reply-To", value: mask(result.sender?.reply_to), mono: false },
    { label: "Return-Path", value: mask(result.sender?.return_path), mono: true },
    { label: "Datum", value: result.sender?.date || "\u2014", mono: false },
  ];

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs text-text-secondary uppercase tracking-wider font-semibold">Absender & Kontext</p>
        <button
          onClick={() => setMaskEmails(!maskEmails)}
          className="inline-flex items-center gap-1.5 text-xs text-text-secondary hover:text-accent transition-colors font-medium px-2 py-1 rounded-lg hover:bg-red-50"
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            {maskEmails
              ? <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              : <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M3 3l18 18" />
            }
          </svg>
          {maskEmails ? "Anzeigen" : "Maskieren"}
        </button>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2">
        {fields.map((f) => (
          <div key={f.label} className="flex items-start text-sm py-1">
            <span className="text-text-tertiary w-24 shrink-0 text-xs font-medium pt-0.5">{f.label}</span>
            <span className={`text-text-primary break-all ${f.mono ? "font-mono text-xs" : ""}`}>{f.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
