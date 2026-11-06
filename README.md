# SakuraClient

Сайт и API SakuraClient 26.2 для Vercel.

- `index.html`, `login.html`, `register.html`, `app.html` — страницы сайта.
- `assets/` — стили, картинки и клиентский JS.
- `api/index.js` — весь serverless API (роуты разбираются по `?route=`, см. `vercel.json`).
- `lib/` — Postgres, пароли, JWT, DTO.
- `download/` — `SakuraLoader.exe` и `SakuraClient-26.2.jar` для скачивания с сайта.

Сайт и лоадер используют один домен: `https://sakuraclient-nvp2.vercel.app`.

Инструкция по деплою и настройке базы: [DEPLOY.md](DEPLOY.md).
