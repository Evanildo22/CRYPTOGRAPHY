(function () {
  "use strict";

  const btns      = document.querySelectorAll(".mode-btn[data-mode]");
  const modeInput = document.getElementById("mode-value");
  const secA      = document.getElementById("mode-a-keys");
  const secB      = document.getElementById("mode-b-keys");

  if (!btns.length || !modeInput || !secA || !secB) return;

  function applyMode(mode) {
    btns.forEach(btn => btn.classList.toggle("active", btn.dataset.mode === mode));
    modeInput.value    = mode;
    secA.style.display = mode === "A" ? "" : "none";
    secB.style.display = mode === "B" ? "" : "none";
  }

  btns.forEach(btn => btn.addEventListener("click", () => applyMode(btn.dataset.mode)));
  applyMode("A");
})();
