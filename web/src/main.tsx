import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";
import "./styles.css";
import { Shell } from "./components/shell";
import ChannelPage from "./pages/Channel";
import QueuePage from "./pages/Queue";
import IncidentPage from "./pages/Incident";
import SearchPage from "./pages/Search";
import ApprovalsPage from "./pages/Approvals";
import ReportsPage from "./pages/Reports";
import DevLogin from "./pages/DevLogin";
import NotFound from "./pages/NotFound";
import { initAuth } from "./lib/auth";

const router = createBrowserRouter([
  {
    element: <Shell />,
    children: [
      { index: true, element: <QueuePage /> },
      { path: "channels/:name", element: <ChannelPage /> },
      { path: "incidents/:id", element: <IncidentPage /> },
      { path: "search", element: <SearchPage /> },
      { path: "approvals", element: <ApprovalsPage /> },
      { path: "reports", element: <ReportsPage /> },
      { path: "*", element: <NotFound /> },
    ],
  },
  // Local development only: choose a seeded identity (the API refuses dev auth in Azure).
  ...(import.meta.env.DEV ? [{ path: "dev-login", element: <DevLogin /> }] : []),
]);

const root = createRoot(document.getElementById("root")!);
initAuth()
  .then(() =>
    root.render(
      <StrictMode>
        <RouterProvider router={router} />
      </StrictMode>,
    ),
  )
  .catch((e: unknown) => {
    root.render(<p style={{ padding: 24, fontFamily: "system-ui" }}>blueboard couldn't start: {String(e)}</p>);
  });
