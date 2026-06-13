(function (window) {
  const DEFAULT_API_ORIGIN = "https://api.bencbonki.veliport24.com";
  const configuredOrigin = window.APP_API_URL || window.APP_API_BASE_URL || DEFAULT_API_ORIGIN;
  const API_ORIGIN = String(configuredOrigin).replace(/\/+$/, "");
  const API_ROOT = `${API_ORIGIN}/api`;

  window.API_ORIGIN = API_ORIGIN;
  window.API_ROOT = API_ROOT;
  window.API_BASE_URLS = {
    auth: `${API_ROOT}/auth`,
    user: `${API_ROOT}/user`,
    admin: `${API_ROOT}/admin`,
  };

  window.getApiBaseUrl = function (scope) {
    return window.API_BASE_URLS[scope];
  };

  window.getApiAssetUrl = function (path) {
    if (!path) return "";
    if (/^https?:\/\//i.test(path)) return path;

    const normalizedPath = String(path).startsWith("/") ? path : `/${path}`;
    return `${API_ORIGIN}${normalizedPath}`;
  };
})(window);
