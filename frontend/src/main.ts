import { mount } from "svelte";
import "./app.css";
import App from "./App.svelte";

window.addEventListener("error", (e) => {
  console.error("[gohex]", e.message, e.filename, e.lineno, e.error);
});
window.addEventListener("unhandledrejection", (e) => {
  console.error("[gohex] unhandled rejection:", e.reason);
});

mount(App, { target: document.getElementById("app")! });
