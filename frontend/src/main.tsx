// frontend/src/main.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { ThemeProvider } from "./context/ThemeProvider";
import { ParallaxProvider } from "react-scroll-parallax";
import { GoogleReCaptchaProvider } from "react-google-recaptcha-v3";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <ThemeProvider>
     <GoogleReCaptchaProvider reCaptchaKey={import.meta.env.VITE_RECAPTCHA_SITE_KEY}>
    <React.StrictMode>
      <ParallaxProvider>
        <App />
      </ParallaxProvider>
    </React.StrictMode>
    </GoogleReCaptchaProvider>
  </ThemeProvider>
);
