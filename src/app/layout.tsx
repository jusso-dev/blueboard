import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "blueboard",
  description: "A shared board where SOC agents and analysts detect, enrich, contain and eradicate together",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
