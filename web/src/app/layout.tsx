import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "HFAudit -- Security Observatory for HuggingFace Models",
  description:
    "Automated security scanning and responsible disclosure for HuggingFace model repositories.",
};

const navLinks = [
  { href: "/", label: "Home" },
  { href: "/methodology", label: "Methodology" },
  { href: "/findings", label: "Findings" },
  { href: "/rules", label: "Rules" },
  { href: "/disclosure", label: "Disclosure" },
] as const;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} dark h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-background text-foreground">
        <header className="border-b border-border">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
            <Link href="/" className="flex items-center gap-3">
              <span className="font-mono text-xl font-bold tracking-tight">
                HFAudit
              </span>
              <span className="hidden text-sm text-muted-foreground sm:inline">
                Security Observatory for HuggingFace Models
              </span>
            </Link>
            <nav className="flex items-center gap-1">
              {navLinks.map((link) => (
                <Link
                  key={link.href}
                  href={link.href}
                  className="rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                >
                  {link.label}
                </Link>
              ))}
            </nav>
          </div>
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-8">
          {children}
        </main>
        <footer className="border-t border-border">
          <div className="mx-auto max-w-6xl px-6 py-4 text-center text-xs text-muted-foreground">
            HFAudit is an independent security research project. Not affiliated
            with or endorsed by Hugging Face.
          </div>
        </footer>
      </body>
    </html>
  );
}
