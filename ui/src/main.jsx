import React from "react";
import ReactDOM from "react-dom/client";
import ErrorBoundary from "./components/ErrorBoundary";
import PacketWindow  from "./components/packets/PacketWindow";


// Fonts are bundled so the desktop app looks the same offline
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";

import "bootstrap/dist/css/bootstrap.min.css";
import "bootstrap-icons/font/bootstrap-icons.css";
import "./theme.css";
import App from "./App";

const params = new URLSearchParams(window.location.search);
const root = params.get("view") === "packet" ? <PacketWindow params={params} /> : <App />;


ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ErrorBoundary>
      {root}
    </ErrorBoundary>
  </React.StrictMode>
);
