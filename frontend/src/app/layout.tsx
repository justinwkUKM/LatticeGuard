import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "LatticeGuard | PQC Assessment",
  description: "Enterprise Post-Quantum Cryptography Assessment Tool",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} antialiased min-h-screen bg-background`}
      >
        <Sidebar />
        <main className="pl-64 min-h-screen">
          <header className="h-16 border-b border-white/5 flex items-center justify-between px-8 glass sticky top-0 z-10">
            <div className="flex items-center gap-4">
              <h2 className="text-sm font-semibold text-white/70">Overview</h2>
              <span className="text-white/20">/</span>
              <h2 className="text-sm font-semibold text-white">Dashboard</h2>
            </div>
            <div className="flex items-center gap-4">
              <div className="px-3 py-1 rounded-full bg-primary/10 border border-primary/20 flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                <span className="text-[10px] font-bold text-primary uppercase tracking-wider">Live Analysis</span>
              </div>
            </div>
          </header>
          <div className="p-8">
            {children}
          </div>
        </main>
      </body>
    </html>
  );
}
