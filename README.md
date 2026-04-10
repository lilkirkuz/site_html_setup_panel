# Pay Web Creator

Панель для создания страниц оплаты в одном экране.

Что умеет:
- несколько страниц в левом списке;
- один экран с тремя колонками;
- реквизиты внутри страницы;
- несколько реквизитов с рандомным показом на публичной странице;
- включение/выключение страниц;
- удаление страниц;
- кнопка `Я оплатил` с двумя сценариями:
  - переход по ссылке;
  - сообщение без редиректа;
- публичные ссылки вида `/p/:slug`.

Запуск:

```bash
npm install
npm start
```

Windows:
- запусти `Start-App.bat`

macOS:
- запусти `Start-App.command`

Открыть: `http://localhost:3000`

API:
- `GET /api/pages`
- `POST /api/pages`
- `PATCH /api/pages/:id/toggle`
- `PATCH /api/pages/:id/current-method`
- `DELETE /api/pages/:id`
- `GET /api/methods`
- `POST /api/methods`
- `PATCH /api/methods/:id/current`
- `DELETE /api/methods/:id`
- `GET /p/:slug`

Данные хранятся локально в `data/payment-pages.json`.
