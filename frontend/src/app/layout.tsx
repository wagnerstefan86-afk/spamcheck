import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "MailScope — Email Security Analysis",
  description: "Analysiert E-Mail-Dateien auf Phishing, Spoofing und andere Sicherheitsrisiken.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="de">
      <body className={inter.className}>
        <div className="min-h-screen">
          <header className="border-b border-border px-6 py-4">
            <div className="max-w-5xl mx-auto flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-accent flex items-center justify-center text-white font-bold text-sm">
                M
              </div>
              <div>
                <h1 className="text-lg font-semibold tracking-tight">
                  Mail<span className="text-accent">Scope</span>
                </h1>
                <p className="text-xs text-slate-500">Email Security Analysis</p>
              </div>
            </div>
          </header>
          <main className="max-w-5xl mx-auto px-6 py-8">{children}</main>
        </div>
      </body>
    </html>
  );
}
