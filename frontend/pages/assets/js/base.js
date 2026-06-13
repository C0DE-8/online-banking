// base.js

document.addEventListener("DOMContentLoaded", function() {
  const loader = document.getElementById("loader");

  // Show the loader on page load
  loader.style.display = "block";

  // Hide the loader when content is fully loaded
  window.addEventListener("load", function() {
      loader.style.display = "none";
  });
});
