import { broadcastResponseToMainFrame } from "@azure/msal-browser/redirect-bridge";

// Entra sends the browser here after sign-in (and for silent renewal in a hidden iframe).
// The bridge stores the response for the app and returns to the page that started sign-in.
broadcastResponseToMainFrame().catch(() => {
  window.location.replace("/");
});
