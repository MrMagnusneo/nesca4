# nesca4 — Перенос недостающих сервисов из nesca (design)

**Дата:** 2026-09-01
**Статус:** черновик на ревью
**Цель:** довести nesca4 до функционального паритета со старым nesca по
модулям детекта/брутфорса сетевых сервисов, реализуя всё нативно на
`libncsnet` (единственное исключение — SSH через libssh), и попутно
улучшить затрагиваемый код.

---

## 1. Контекст

Существует два независимых проекта в `/home/x13/VScodeProjects/nesca`:

- **nesca** (`nesca/`) — легаси Qt5 GUI-сканер (~12.6k строк C++),
  зависит от `Qt`, `libssh`, `openssl`, `libcurl`. Содержит богатый
  набор модулей авторизации/брута для камер и сервисов.
- **nesca4** (`nesca4/`) — переписанный с нуля CLI-сканер (~7.6k строк)
  другого автора, построен на собственной библиотеке `libncsnet`
  (git-сабмодуль). Сейчас поддерживает детект/брут только HTTP и FTP.

Проекты архитектурно несовместимы: перенос означает **переписывание**
каждого модуля под API `libncsnet` и под паттерны nesca4, а не
копирование кода.

### 1.1 Исходное состояние (проверено)

- Сабмодуль `libncsnet` изначально был **не выкачан** (пустая папка);
  инициализирован (`git submodule update --init`).
- После этого проект **собирается**: `./configure && make -j` →
  бинарь `nesca4` (10 MB), exit 0. Это базовая точка.
- `libncsnet` предоставляет прикладные протоколы: **dns, ftp, http,
  smtp**, raw-сокеты (tcp/udp/icmp/sctp), base64, md5/sha1/sha256/512,
  socks5, url, html-парсер. **Нет**: SSH, RTSP, telnet, SNMP.

## 2. Архитектура расширения nesca4 (точки встраивания)

Добавление нового сервиса `X` затрагивает ровно 4 места:

1. **Реестр сервисов** — `include/nescadata.h:143`:
   `#define S_X <n>` и инкремент `S_NUM`.
2. **Детект сервиса** — `NESCAPROCESSING::INIT` switch
   (`nescaservices.cc:146`): регистрация check/method-функций через
   `NESCAPROCESSINGCORPUS` (`setcheck`/`setmethod`).
3. **Брутфорс** — `NESCABRUTE::probe` switch (`nescabrute.cc:115`):
   добавить `case S_X` с вызовом `x_qprc_auth(fd, login, pass)`;
   при необходимости — спец-поведение соединения в
   `NESCABRUTE::newfd` (`nescabrute.cc:81`).
4. **Правила находок** — файл `resources/nesca-database` (движок
   `nescafind.cc`, правила по redirect/title/html/mac/dns/ip/ftp_hello,
   с regex).

### 2.1 Контракт auth-функции (единый паттерн)

Существующий паттерн — `ftp_qprc_auth(fd, login, pass)` /
`http_basicauth(fd, ip, path, login, pass)`. Каждый новый модуль
предоставляет одну функцию по образцу:

```
bool <svc>_qprc_auth(int fd, const char *ip, u16 port,
                     const char *login, const char *pass,
                     long long timeout, /* svc-specific ctx */ ...);
```

Соединение открывается через `sock_session(ip, port, timeoutns, buf, len)`;
обмен — `sock_probe(fd, recvbuf, len, fmt, ...)` / `sock_recv`. fd
управляется владеющим кодом (RAII-обёртка, см. §5).

## 3. Список переносимых модулей и как их реализовать

| # | Модуль nesca | S_* | Транспорт libncsnet | Заметки |
|---|---|---|---|---|
| — | HTTP basic brute | S_HTTP | http.h | уже есть |
| — | FTP brute | S_FTP | ftp.h | уже есть |
| 1 | RTSP камеры (+Digest) | S_RTSP | socket + md5 | DESCRIBE, realm/nonce, 401→Digest |
| 2 | Hikvision/RVI/SAFARI DVR | S_HIKVISION | socket (raw TCP) | бинарный IVMS-протокол (headerIVMS 32B, признак `buff[3]==0x10`) |
| 3 | IPC web-камеры | S_IPC (или под S_HTTP) | http.h + urlencode | множество vendor CGI (`/cgi-bin/...`) |
| 4 | SMTP brute | S_SMTP | smtp.h + base64 | AUTH LOGIN/PLAIN вручную (в smtp.h только version) |
| 5 | Webform GET/POST brute | под S_HTTP | http.h | парс формы, отправка креды, детект успеха |
| 6 | SSH brute | S_SSH | **libssh (внешняя)** | обязательная зависимость (реш. пользователя) |

### 3.1 Детали по модулям

- **RTSP:** открыть TCP, послать `DESCRIBE rtsp://ip:port/ RTSP/1.0`.
  По `401 Unauthorized` извлечь `realm`/`nonce`, построить Digest
  (md5 из libncsnet), повторить. `200 OK` = успех. Перебор словаря
  логин/пароль (существующий `NESCABRUTE` цикл).
- **Hikvision/RVI:** raw-TCP. Детект по IVMS-хендшейку; логин —
  бинарные пакеты из `HikvisionLogin.cpp` (checkHikk/checkRVI/hikLogin,
  rviLogin). Порт в отдельный `nescahikvision.{cc,h}`.
- **IPC:** для каждого вендора — свой HTTP-запрос (Foscam CGIProxy,
  hi3510 checkuser, gw.cgi, videoconfiguration и т.д. из
  `IPCAuth.cpp`). urlencode реализовать/взять из `url.h`. Успех — по
  сигнатуре ответа (не 401/negatives).
- **SMTP:** `EHLO`, затем `AUTH LOGIN` с base64(login)/base64(pass);
  `235` = успех, `535` = неверно. base64 из `libncsnet/ncsnet/base64.h`.
- **Webform:** GET страницы логина, поиск `<form>`/полей, POST
  креденшелов, детект успеха (redirect/cookie/отсутствие формы). Порт
  логики `WebformWorker.cpp` (parseResponse/doGetCheck/doPostCheck).
- **SSH:** libssh (`ssh_new`, `ssh_connect`, `ssh_userauth_password`).
  Configure: обязательная проверка наличия `libssh` (fail при
  отсутствии), линковка `-lssh`.

## 4. Фазы (порядок реализации)

- **Фаза 0 — база:** зафиксировать обязательность `libncsnet` (README +
  проверка в configure/Makefile), убедиться что собирается «с нуля».
  Обновить `configure.ac` для проверки libssh (Фаза 3 зависит).
- **Фаза 1 — камеры (ядро ценности):**
  1.1 RTSP → 1.2 Hikvision/RVI → 1.3 IPC.
- **Фаза 2 — сервисы:** 2.1 SMTP → 2.2 Webform.
- **Фаза 3 — SSH:** реализация за libssh (обязательная зависимость).
- **Улучшения кода** делаются по ходу в затрагиваемом коде (см. §5),
  без несвязанного рефакторинга.

Каждая фаза: отдельные коммиты + сборка/дымовой прогон перед следующей.

## 5. Улучшения кода (в затрагиваемых местах)

- **RAII на fd:** обёртка `NescaSock`/`unique fd` вместо ручного
  `push_back`/закрытия в `NESCABRUTE`; устранить потенциальные утечки
  дескрипторов в цикле брута.
- **Единый диспетчер probe:** таблица `service → auth_fn` вместо
  растущего switch (данные вместо кода), чтобы каждый модуль
  регистрировался декларативно.
- **Единый error-handling:** возврат статуса вместо смешения
  `-1`/`bool`/глобалов; логирование через `libncsnet/log.h`.
- **Изоляция модулей:** каждый новый сервис — свой `.cc/.h`
  (`nescartsp`, `nescahikvision`, `nescaipc`, `nescasmtp`,
  `nescawebform`, `nescassh`), подключаемый в brute/services; никаких
  Qt/CURL/глобалов старого nesca.
- Обновление `Makefile.in` для новых объектных файлов.

## 6. Тестирование

Сеть-зависимый брут трудно юнит-тестировать. Стратегия:

- **Юнит-тесты на чистых функциях:** парсинг Digest (realm/nonce),
  base64 AUTH-строк, urlencode, разбор IVMS-заголовка, парсинг формы —
  на зафиксированных байтовых входах/выходах (без сокетов).
- **Локальные фейковые серверы:** мини TCP-заглушки (RTSP 401→Digest,
  SMTP AUTH, HTTP-форма) в тестах — проверка полного цикла auth-функции
  на loopback.
- **Дымовые прогоны:** сборка + запуск `nesca4` по каждому новому
  сервису против локального стенда, где возможно.
- **Регрессия:** существующие HTTP/FTP брут и детект продолжают
  работать (сборка + запуск на известной цели).

TDD: для каждой чистой функции — тест до реализации.

## 7. Не входит в объём (YAGNI)

- GUI/Qt (nesca4 — CLI по замыслу).
- Легаси-механизмы находок/бэкапов nesca, уже покрытые `nescafind` и
  выводом nesca4, — только доведение правил `nesca-database`.
- telnet/SNMP и прочие сервисы, которых не было в nesca.

## 8. Риски / открытые вопросы

- **Hikvision бинарный протокол** — самый рискованный порт; детали
  берутся из `HikvisionLogin.cpp`, требуется точное воспроизведение
  пакетов. Валидация без живой камеры ограничена.
- **IPC вендоры** — множество эвристик; переносим набор из `IPCAuth.cpp`
  как есть, детект успеха может требовать подстройки.
- **libssh версия** — API 0.9+ предполагается; зафиксировать в configure.

---

## Приложение: статус реализации (2026-09-01)

Реализовано и покрыто тестами (`make test`), каждый модуль изолирован в
своих `nesca*.{cc,h}`, встроен как отдельный `S_*` сервис (детект +
probe + `-s`):

| Сервис | S_* | Статус | Тесты |
|---|---|---|---|
| RTSP (Basic/Digest) | S_RTSP | ✅ | unit + fake-server |
| SSH (libssh) | S_SSH | ✅ код; сборка включается при наличии libssh-dev (`HAVE_LIBSSH`) | stub-компиляция |
| RVI DVR (raw binary) | S_RVI | ✅ | unit + fake-server |
| IPC (17 вендоров) | S_IPC | ✅ | unit + fake-server |
| Webform (GET/POST) | S_WF | ✅ | unit + fake-server |

### Отклонения от спека (обоснованные)

- **SSH — не «обязательная libssh», а опциональная за `HAVE_LIBSSH`.** В
  окружении отсутствуют dev-заголовки libssh (есть только `libssh.so.4`),
  а прав root нет — обязательная линковка сломала бы сборку. Модуль
  компилируется в рабочий вид сразу после установки `libssh-dev`; без неё
  — безопасная заглушка. Ветка HAVE_LIBSSH проверена компиляцией против
  stub-заголовка.
- **Hikvision iVMS / SAFARI login — не портирован.** Зависит от
  проприетарного `HCNetSDK.lib` (Windows), нативно невоспроизводим.
  Портирована только RVI-часть (открытый бинарный протокол).
- **SMTP — не реализован.** В старом nesca модуля SMTP нет (был только
  закомментированный `SMTP_BRUTEFORCE`), поэтому «перенос из nesca» его
  не включает.

### Найденные (pre-existing) дефекты nesca4, вне объёма переноса

- `nescafind.cc:272` — регистрация HTTP-brute задач закомментирована/битая
  (в место вызова вставлена сигнатура функции); порт не требует правки, но
  HTTP basic-brute по find-правилам сейчас не регистрируется.
- `NESCAOPTS::args_apply` (`nescadata.cc`) — неизвестный флаг вызывает
  SIGSEGV в `getopt_long_only` вместо ошибки разбора.
