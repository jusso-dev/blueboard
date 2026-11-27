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
import PolicyPage from "./pages/Policy";
import SetupPage from "./pages/Setup";
import NotificationsPage from "./pages/Notifications";
import ParticipantsPage from "./pages/Participants";
import AdminCenterPage from "./pages/AdminCenter";
import AuditLogPage from "./pages/AuditLog";
import PosturePage from "./pages/Posture";
import IntelPage from "./pages/Intel";
import IntelKeyPage from "./pages/IntelKey";
import MemoryPage from "./pages/Memory";
import ExposurePage from "./pages/Exposure";
import DevLogin from "./pages/DevLogin";
import NotFound from "./pages/NotFound";
import { initAuth } from "./lib/auth";

const routes = (dev: boolean) => [
  {
    element: <Shell />,
    children: [
      { index: true, element: <QueuePage /> },
      { path: "channels/:name", element: <ChannelPage /> },
      { path: "incidents/:id", element: <IncidentPage /> },
      { path: "search", element: <SearchPage /> },
      { path: "approvals", element: <ApprovalsPage /> },
      { path: "reports", element: <ReportsPage /> },
      { path: "policy", element: <PolicyPage /> },
      { path: "setup", element: <SetupPage /> },
      { path: "settings/notifications", element: <NotificationsPage /> },
      { path: "admin", element: <AdminCenterPage /> },
      { path: "admin/participants", element: <ParticipantsPage /> },
      { path: "admin/audit", element: <AuditLogPage /> },
      { path: "admin/posture", element: <PosturePage /> },
      { path: "intel", element: <IntelPage /> },
      { path: "intel/:key", element: <IntelKeyPage /> },
      { path: "memory", element: <MemoryPage /> },
      { path: "exposure", element: <ExposurePage /> },
      { path: "*", element: <NotFound /> },
    ],
  },
  // Local development and the local demo only: choose a seeded identity (the API refuses dev auth in Azure).
  ...(dev ? [{ path: "dev-login", element: <DevLogin /> }] : []),
];

const root = createRoot(document.getElementById("root")!);
initAuth()
  .then((auth) =>
    root.render(
      <StrictMode>
        <RouterProvider router={createBrowserRouter(routes(auth.mode === "dev"))} />
      </StrictMode>,
    ),
  )
  .catch((e: unknown) => {
    root.render(<p style={{ padding: 24, fontFamily: "system-ui" }}>blueboard couldn't start: {String(e)}</p>);
  });
