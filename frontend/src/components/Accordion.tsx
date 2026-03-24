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
        <svg
          className={`w-4 h-4 text-text-tertiary transition-transform duration-200 ${open ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      <div
        className={`overflow-hidden transition-all duration-300 ${open ? "max-h-[2000px] opacity-100 mt-4 pt-4 border-t border-gray-100" : "max-h-0 opacity-0"}`}
      >
        {children}
      </div>
    </div>
  );
}
