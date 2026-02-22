# Ubuntu Site Deployer

Веб-приложение для управления Ubuntu-сервером по SSH:
- установка `nginx` + `certbot`
- деплой `index.html` для домена
- выпуск SSL-сертификата через Certbot
- кнопки включения/выключения сайта (`sites-enabled`)

## Быстрый старт

```bash
npm install
npm start
```

Открыть: `http://localhost:3000`

## Что умеет UI

- `Полный деплой`: install -> deploy -> certbot
- `Установить Nginx + Certbot`
- `Задеплоить HTML`
- `Получить SSL`
- `Включить сайт`
- `Выключить сайт`

## Важно

- Сервер должен принимать SSH-ключ.
- Пользователь SSH должен иметь права `sudo`.
- Домен должен указывать A/AAAA записью на этот сервер, иначе Certbot не выпустит сертификат.
- Для корректной выдачи сертификата должны быть открыты порты `80` и `443`.

## API

- `POST /api/install`
- `POST /api/deploy`
- `POST /api/certbot`
- `POST /api/site/enable`
- `POST /api/site/disable`
- `POST /api/site/status`
- `POST /api/full-deploy`
- `POST /api/ssh/bootstrap` (генерация managed-ключа и установка в `authorized_keys`)
- `GET /api/ssh/managed-keys`
- `GET /api/servers` (список сохраненных серверов)
- `POST /api/servers` (создать/обновить профиль сервера)
- `DELETE /api/servers/:id` (удалить профиль)

Общий payload:

```json
{
  "host": "203.0.113.10",
  "port": 22,
  "username": "ubuntu",
  "password": "optional-for-bootstrap",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----...",
  "domain": "example.com",
  "keyName": "deployer",
  "certbotEmail": "admin@example.com",
  "html": "<!doctype html>...",
  "includeWww": true
}
```

## Автоматизация SSH ключа

1. Заполнить `SSH host`, `SSH user` и:
- либо `SSH Password` (для первичной настройки),
- либо текущий `SSH Private Key`.
2. Нажать кнопку `Автонастроить SSH ключ`.
3. Приложение:
- сгенерирует managed ed25519 ключ локально в `data/keys/<keyName>`,
- добавит публичный ключ на сервер в `~/.ssh/authorized_keys`,
- подставит приватный ключ в UI автоматически.

## Несколько серверов

- Профили серверов хранятся в `data/servers.json`.
- В UI слева отображается список профилей.
- Кнопки:
  - `Новый профиль` очищает форму.
  - `Сохранить профиль` сохраняет все поля текущего профиля.
  - `Удалить профиль` удаляет выбранный профиль.
