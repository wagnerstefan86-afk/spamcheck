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
          {/* Frosted glass header */}
          <header className="sticky top-0 z-50 backdrop-blur-xl bg-white/70 border-b border-gray-200/50">
            <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-red-500 to-red-700 flex items-center justify-center text-white font-bold text-sm shadow-glow">
                M
              </div>
              <div>
                <h1 className="text-lg font-semibold tracking-tight text-text-primary">
                  Mail<span className="text-accent">Scope</span>
                </h1>
                <p className="text-[11px] text-text-tertiary font-medium tracking-wide uppercase">
                  Email Security Analysis
                </p>
              </div>
            </div>
          </header>
          <main className="max-w-5xl mx-auto px-6 py-8">{children}</main>
        </div>
      </body>
    </html>
  );
}
