import { Suspense } from "react";
import { Shell } from "../components/shell";

export default function BoardLayout({ children }: { children: React.ReactNode }) {
  return (
    <Suspense>
      <Shell>{children}</Shell>
    </Suspense>
  );
}
