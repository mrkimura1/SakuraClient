(function () {
  const TOKEN_KEY = "sakura.token";
  const USER_KEY = "sakura.user";

  // Сайт и API живут на одном домене (Vercel), поэтому запросы идут
  // на текущий origin. Никакого локального сервера больше не нужно.
  function apiUrl(path) {
    return /^https?:/i.test(path) ? path : new URL(path, location.origin + "/").toString();
  }

  const store = {
    get token() {
      return localStorage.getItem(TOKEN_KEY) || "";
    },
    user() {
      try {
        return JSON.parse(localStorage.getItem(USER_KEY) || "null");
      } catch {
        return null;
      }
    },
    save(auth) {
      localStorage.setItem(TOKEN_KEY, auth.token);
      localStorage.setItem(USER_KEY, JSON.stringify(auth.user));
    },
    update(user) {
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    },
    clear() {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
    }
  };

  async function api(path, options) {
    const opts = options || {};
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (store.token) headers.Authorization = "Bearer " + store.token;

    let response;
    try {
      response = await fetch(apiUrl(path), Object.assign({}, opts, { headers }));
    } catch {
      throw new Error("Сайт недоступен. Проверь подключение к интернету и попробуй ещё раз.");
    }

    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }

    if (!response.ok) {
      const message = data && (data.error || data.message);
      const error = new Error(
        message ||
        (response.status === 404
          ? "API сайта не найдено. Обнови страницу и попробуй ещё раз."
          : "Ошибка " + response.status)
      );
      error.status = response.status;
      throw error;
    }

    return data;
  }

  function money(value) {
    return new Intl.NumberFormat("ru-RU").format(value) + " ₽";
  }

  function date(value) {
    if (!value) return "—";
    return new Intl.DateTimeFormat("ru-RU", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric"
    }).format(new Date(value));
  }

  function buyLink(product) {
    if (product.kind === "hwid") return "https://funpay.com/lots/offer?id=80995797";
    if (product.days === 30) return "https://funpay.com/lots/offer?id=80610998";
    if (product.days === 180) return "https://funpay.com/lots/offer?id=80611752";
    return "https://funpay.com/lots/offer?id=80613970";
  }

  function requireAuth() {
    if (store.token) return true;
    location.href = "/login.html";
    return false;
  }

  function logout() {
    store.clear();
    location.href = "/";
  }

  window.Sakura = { api, store, money, date, buyLink, requireAuth, logout };
})();
