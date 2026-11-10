import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { client } from "./queries";
import { LANG } from "./lib/i18n";
import { applyTheme } from "./state";
import { App } from "./App";
import "./styles.css";

document.documentElement.lang = LANG;
applyTheme();
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
