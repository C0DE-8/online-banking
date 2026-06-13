// dark-mode.js

// Function to apply dark mode if saved in localStorage
function applySavedDarkMode() {
  const isDarkMode = localStorage.getItem("darkMode") === "enabled";
  document.body.classList.toggle("dark-mode", isDarkMode);

  // If the toggle exists on this page, sync its checked state
  const toggle = document.getElementById("darkmodeSwitch");
  if (toggle) {
    toggle.checked = isDarkMode;

    toggle.addEventListener("change", function () {
      if (this.checked) {
        document.body.classList.add("dark-mode");
        localStorage.setItem("darkMode", "enabled");
      } else {
        document.body.classList.remove("dark-mode");
        localStorage.setItem("darkMode", "disabled");
      }
    });
  }
}

// Apply dark mode when the DOM is fully loaded
document.addEventListener("DOMContentLoaded", applySavedDarkMode);
