(function () {
  "use strict";

  const modeA = document.querySelector('input[name="mode"][value="A"]');
  const modeB = document.querySelector('input[name="mode"][value="B"]');
  const secA  = document.getElementById("mode-a-keys");
  const secB  = document.getElementById("mode-b-keys");

  if (!modeA || !modeB || !secA || !secB) return;

  function applyMode() {
    secA.style.display = modeA.checked ? "" : "none";
    secB.style.display = modeA.checked ? "none" : "";
  }

  modeA.addEventListener("change", applyMode);
  modeB.addEventListener("change", applyMode);
  applyMode();
})();
