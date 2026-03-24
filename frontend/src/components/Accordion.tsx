"use client";

import { useState } from "react";

type Props = {
  title: string;
  children: React.ReactNode;
};

export default function Accordion({ title, children }: Props) {
  const [open, setOpen] = useState(false);

  return (
    <div className="card">
      <button onClick={() => setOpen(!open)} className="accordion-trigger">
        <span>{title}</span>
        <span className="text-slate-500 transition-transform" style={{ transform: open ? "rotate(180deg)" : "" }}>
          &#9662;
        </span>
      </button>
      {open && <div className="mt-3 pt-3 border-t border-border">{children}</div>}
    </div>
  );
}
