# Linux DFIR: Артефакты для реагирования на инциденты

> **Применимость:** Ubuntu, Debian, RHEL/CentOS/AlmaLinux 
> **Назначение:** Справочник для сбора и анализа артефактов с живой системы или образа диска  
> **Версия:** 1.1 | Обновлено: 2026-02

---

## Важное примечание о дистрибутивах

Linux — семейство операционных систем, и пути к артефактам, названия логов, пакетные менеджеры и системы инициализации различаются в зависимости от дистрибутива. В документе используются следующие обозначения:

| Метка | Дистрибутивы |
|-------|-------------|
| `[deb]` | Debian, Ubuntu и производные |
| `[rpm]` | RHEL, CentOS, AlmaLinux, Fedora и производные |
| `[all]` | Применимо ко всем основным дистрибутивам |

---

## Условные обозначения

| Символ | Значение |
|--------|----------|
| 🔴 | Критически важно — собирать в первую очередь |
| 🟡 | Важно — стандартный IR |
| 🟢 | Дополнительно — углублённое расследование |
| ⚠️ | Требует root |
| ⏱️ | Волатильный — исчезает при перезагрузке |
| 🔄 | Подвергается ротации — логи перезаписываются со временем |

---

## Понимание файловой системы Linux (FHS)

FHS (Filesystem Hierarchy Standard) — стандарт иерархии директорий Linux. Знание того, что где лежит по стандарту, помогает сразу понять, что является аномалией, а что нет.

| Директория | Назначение | IR-значимость |
|-----------|-----------|--------------|
| `/bin`, `/sbin` | Базовые бинари системы | Сюда максируют свои бинари атакующие |
| `/usr/bin`, `/usr/sbin` | Пользовательские утилиты | Нелегитимные инструменты атакующего |
| `/usr/local/` | Локально установленное ПО | Частое место дропа малвари |
| `/tmp`, `/var/tmp` | Временные файлы | Классическая staging area |
| `/dev/shm` | Shared memory (tmpfs) | Сюда часто кладут временные файлы |
| `/etc` | Конфигурационные файлы | Persistence, изменения конфигов |
| `/home`, `/root` | Домашние директории | User artifacts, shell history |
| `/var/log` | Журналы системы и приложений | Основной источник логов |
| `/proc` | Псевдофайловая ФС ядра | Live данные о процессах и системе |
| `/lib/systemd/`, `/etc/systemd/` | Юниты systemd | Persistence через службы |
| `/var/spool/cron` | Cron задачи пользователей | Persistence через cron |



---

## Содержание

| # | Категория | Ключевые артефакты |
|---|-----------|-------------------|
| [1](#1-persistence) | **Persistence** | Systemd, Cron, rc.local, Bashrc hooks, LD_PRELOAD, PAM, /etc/environment |
| [2](#2-process) | **Process** | /proc, ps, lsof, хэши, procfs-эвристики |
| [3](#3-network) | **Network** | Соединения, ARP, маршруты, DNS, Unix sockets, netfilter |
| [4](#4-file-system) | **File System** | MACB, Bodyfile, /tmp, SUID/SGID, capabilities |
| [5](#5-user-activity) | **User Activity** | Shell history, редакторы, БД, файловые менеджеры |
| [6](#6-system-logs) | **System Logs** | auth.log, wtmp, journald, auditd, syslog, kern, pacct |
| [7](#7-authentication) | **Authentication** | passwd/shadow, SSH, sudo, PAM, пользователи |
| [8](#8-applications) | **Applications** | Пакетные менеджеры, веб-серверы, Docker |
| [9](#9-security-state) | **Security State** | Kernel modules, AppArmor/SELinux, integrity |
| [10](#10-memory--volatile) | **Memory & Volatile** | RAM-дамп, /proc/mem, Volatility |
| [11](#11-external-devices) | **External Devices** | USB, монтирование, udev |
| [П1](#приложение-1-порядок-сбора) | **Приложение 1** | Order of Volatility |
| [П2](#приложение-2-быстрый-ir-скрипт) | **Приложение 2** | Быстрый IR-скрипт |
| [П3](#приложение-3-инструменты) | **Приложение 3** | Инструменты сбора и анализа |
| [П4](#приложение-4-ссылки) | **Приложение 4** | Ссылки |
| [П5](#приложение-5-покрытие-артефактов-по-инструментам) | **Приложение 5** | Покрытие артефактов по инструментам |

---

## 1. Persistence

*Механизмы закрепления в системе — первый приоритет при любом IR. В Linux нет единого реестра как в Windows, поэтому persistence разбросана по множеству мест.*

### 1.1 Systemd Units 🔴

**Что это:** Systemd — основная система инициализации и управления службами в современных Linux-дистрибутивах (заменила SysVInit). Юниты (`unit files`) — текстовые конфигурационные файлы, описывающие условия запуска, зависимости и параметры службы. Malware создаёт вредоносный `.service` юнит в одном из системных путей и включает его через `systemctl enable`. Это **самый распространённый механизм persistence** в серверных Linux-инцидентах.

**Типы юнитов, релевантных для IR:**

| Тип | Расширение | Назначение | IR-значимость |
|-----|-----------|-----------|--------------|
| Service | `.service` | Управление демонами и службами | ⚠️ Основной вектор |
| Timer | `.timer` | Планировщик (аналог cron) | ⚠️ Триггерит `.service` по расписанию |
| Socket | `.socket` | Активация службы при обращении на порт | ⚠️ Может поднимать C2 при коннекте |
| Path | `.path` | Активация при изменении файла | ⚠️ Триггер при удалении артефакта |
| Device | `.device` | Триггер при подключении устройства | Редко используется |
| Generator | `.generator` | Генерация юнитов на лету при загрузке | Экзотический вектор |
| Config | `<service>.d/local.conf` | Добавление условий для запуска службы | менее заметный метод, используется многими акторами |

**Расположение:**
```
# Системные — проверять всегда
/etc/systemd/system/              ← созданные администратором
/etc/systemd/system.control/
/lib/systemd/system/              ← пакеты из репозитория
/usr/lib/systemd/system/

# Пользовательские
/{root,home/*}/.config/systemd/user/  
/{root,home/*}/.local/share/systemd/user/

# Volatile (только в RAM, очищаются при перезагрузке)
/run/systemd/system/
/run/systemd/generator/
/run/user/*/systemd/user/
```

**На какие вопросы отвечает:**
- Какие службы автозапуска существуют в системе и что они запускают?
- Когда создан/изменён юнит (дата файла = дата persistence)?
- Есть ли нестандартные таймеры, скрывающие регулярное выполнение задач?
- Ссылается ли юнит на исполняемый файл в настандартных директориях?

**Парсинг:**
```bash
# Список всех активных юнитов (живая система)
systemctl list-units --all --type=service
systemctl list-units --all --type=timer
systemctl list-timers --all

# Список всех включённых юнитов (автозапуск)
systemctl list-unit-files --state=enabled

# Просмотр конкретного юнита с деревом зависимостей
systemctl cat suspicious.service
systemctl show suspicious.service

# Поиск юнитов, запускающих подозрительные пути
grep -r "ExecStart\|ExecStartPre\|ExecStartPost" \
  /etc/systemd/system/ /lib/systemd/system/ /usr/lib/systemd/system/ | \
  grep -Ei "/tmp|/dev/shm|/var/tmp|bash|python|curl|wget|nc |ncat"

# Поиск юнитов в пользовательских директориях (не требуют root)
find /home /root -path "*/.config/systemd/user/*.service" 2>/dev/null
find /home /root -path "*/.local/share/systemd/user/*.service" 2>/dev/null

# Поиск по подозрительным ключевым словам в содержимом юнитов
grep -rE "LD_PRELOAD|wget|curl|base64|/tmp|/dev/shm|reverse|shell" \
  /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null
```

**Инструменты:** UAC · easy_triage · Velociraptor (`Linux.Sys.Services`)

---

### 1.2 SysVInit / rc.d Scripts 🟡

**Что это:** Устаревшая система инициализации. Скрипты в `/etc/init.d/` (или `/etc/rc.d/init.d/`) запускаются при загрузке согласно runlevel. В современных системах полностью вытеснена systemd, но файлы могут сохраняться. Злоумышленники используют этот механизм именно потому, что он реже проверяется. Каждый скрипт — исполняемый shell-файл.

**Расположение:**
```
/etc/init.d/                    ← [deb] основные скрипты служб
/etc/rc.d/init.d/               ← [rpm] основные скрипты служб
/etc/rc0.d/ ... /etc/rc6.d/     ← символические ссылки на init.d по runlevel
/etc/rc.local                   ← выполняется в конце загрузки (legacy)
```

**На какие вопросы отвечает:**
- Есть ли нестандартные init-скрипты, которых не должно быть?
- Содержит ли `/etc/rc.local` команды, добавленные злоумышленником?
- Когда создан или изменён скрипт?

**Парсинг:**
```bash
# Список всех init-скриптов
service --status-all 2>/dev/null
ls -lat /etc/init.d/
cat /etc/rc.local

# Поиск подозрительного содержимого
grep -Ei "wget|curl|bash|python|nc |ncat|/tmp|/dev/shm|base64" \
  /etc/init.d/* /etc/rc.local 2>/dev/null
```

**Инструменты:** UAC

---

### 1.3 Cron и Anacron 🔴

**Что это:** Стандартный планировщик задач. `cron` — для серверов (выполняет задачи по точному расписанию), `anacron` — для рабочих станций (выполняет задачи при следующей загрузке, если система была выключена). Cron — один из самых популярных векторов persistence на Linux-серверах: тихо, надёжно, везде есть.

**Расположение:**
```
# Системные cron (требуют root)
/etc/crontab                    ← системная crontab
/etc/cron.d/                    ← дополнительные задачи пакетов и ВПО
/etc/cron.hourly/               ← выполняются каждый час
/etc/cron.daily/                ← ежедневно
/etc/cron.weekly/               ← еженедельно
/etc/cron.monthly/              ← ежемесячно

# Пользовательские cron (не требуют root)
/var/spool/cron/crontabs/<username>   ← [deb] каждый пользователь свой файл
/var/spool/cron/<username>            ← [rpm]

# Anacron
/etc/anacrontab
/var/spool/anacron/
```

**На какие вопросы отвечает:**
- Какие задачи по расписанию существуют в системе?
- Есть ли задачи, запускающие скрипты из нестандартных директорий?
- Когда добавлена или изменена задача (дата файла)?
- Есть ли задачи в crontab нестандартных пользователей?

**Парсинг:**
```bash
# Системные cron
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/
cat /etc/cron.d/*

# Пользовательские cron
for user in $(cut -f1 -d: /etc/passwd); do
  echo "=== $user ==="; crontab -u "$user" -l 2>/dev/null
done

# Прямой просмотр файлов (более надёжно при компрометации crontab)
ls -la /var/spool/cron/crontabs/ 2>/dev/null   # deb
ls -la /var/spool/cron/ 2>/dev/null             # rpm
cat /var/spool/cron/crontabs/*

# Поиск подозрительного содержимого
grep -rEi "wget|curl|bash|python|nc |ncat|/tmp|/dev/shm|base64|/var/tmp" \
  /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null
```

**Инструменты:** UAC · easy_triage · Velociraptor (`Linux.Persistence.Cron`)

---

### 1.4 At Jobs 🟢

**Что это:** Одноразовый планировщик задач. Задачи `at` выполняются один раз в указанное время. На продакшн-серверах редко используется легитимно — любая задача в `/var/spool/at/` является потенциальным IoC.

**На какие вопросы отвечает:**
- Есть ли одноразовые задачи, запланированные злоумышленником?
- Когда запланирована задача и какую команду она выполняет?
- Кому принадлежит задача?

**Расположение:**
```
/var/spool/at/            ← очередь задач at
/var/spool/atjobs/        ← альтернативный путь
/etc/at.allow             ← список пользователей, которым разрешён at
/etc/at.deny              ← список пользователей, которым запрещён at
```

**Парсинг:**
```bash
atq                                 # текущая очередь at
sudo ls -la /var/spool/at/
sudo cat /var/spool/at/*            # содержимое задач
```

**Инструменты:** UAC · easy_triage

---

### 1.5 Shell Profile и Bashrc Hooks 🔴

**Что это:** Файлы конфигурации командной оболочки, выполняемые при старте интерактивной сессии (или любого дочернего процесса bash). Злоумышленники добавляют в них команды для восстановления persistence или кражи данных. Особенно опасны глобальные файлы — `/etc/profile` и `/etc/bash.bashrc`, так как выполняются для **всех** пользователей.

**Расположение:**
```
# Глобальные (для всех пользователей, требуют root)
/etc/profile                    ← выполняется при login shell
/etc/profile.d/*.sh             ← отдельные скрипты для profile
/etc/bash.bashrc                ← [deb] для всех интерактивных bash
/etc/bashrc                     ← [rpm]

# Пользовательские
~/.bashrc                       ← для интерактивных сессий
~/.bash_profile                 ← для login-сессий
~/.profile                      ← для login-сессий (sh-совместимый)
~/.zshrc                        ← zsh
~/.zprofile                     ← zsh login
/root/.bashrc                   ← отдельно проверить root
```

**На какие вопросы отвечает:**
- Добавлены ли в profile-файлы посторонние команды (reverse shell при логине)?
- Перекрыты ли системные переменные (`PATH`, `LD_PRELOAD`, `HISTFILE`)?
- Есть ли команды, отключающие запись истории (`unset HISTFILE`, `HISTSIZE=0`)?

**Парсинг:**
```bash
# Системные profile-файлы
cat /etc/profile
cat /etc/bash.bashrc 2>/dev/null || cat /etc/bashrc 2>/dev/null
ls -la /etc/profile.d/; cat /etc/profile.d/*.sh

# Пользовательские — для всех пользователей
for dir in /root /home/*; do
  echo "=== $dir ==="; 
  cat "$dir/.bashrc" "$dir/.bash_profile" "$dir/.profile" 2>/dev/null
done

# Поиск подозрительного содержимого
grep -rEi "wget|curl|nc |ncat|/tmp|/dev/shm|base64|HISTFILE|LD_PRELOAD|reverse|shell" \
  /etc/profile /etc/profile.d/ /etc/bash.bashrc /etc/bashrc \
  /root/.bashrc /home/*/.bashrc 2>/dev/null
```

**Инструменты:** UAC · easy_triage

---

### 1.6 LD_PRELOAD и /etc/ld.so.preload 🔴 ⚠️

**Что это:** Механизм динамического линковщика Linux (ld.so), позволяющий загрузить произвольную разделяемую библиотеку (.so) **до любых других** — включая системные libc. Используется руткитами для перехвата системных вызовов и сокрытия файлов, процессов, сетевых соединений. `/etc/ld.so.preload` — системный файл для глобального preload; его наличие с нестандартными записями = критический индикатор компрометации. Кроме того, любой процесс может иметь переменную `LD_PRELOAD` в своём окружении.

**Расположение:**
```
/etc/ld.so.preload              ← ALERT: любая нестандартная запись = руткит
/proc/<PID>/environ             ← LD_PRELOAD для конкретного процесса
```

**На какие вопросы отвечает:**
- Есть ли нестандартные библиотеки, загружаемые до системных?
- Какие процессы используют `LD_PRELOAD`?
- Есть ли подозрительные .so-файлы в нестандартных путях?

**Парсинг:**
```bash
# Системный preload
cat /etc/ld.so.preload

# Поиск процессов с LD_PRELOAD в окружении
find /proc -maxdepth 2 -name 'environ' -type f \
  -exec grep -Fl 'LD_PRELOAD=' {} \; 2>/dev/null

# Получить значение LD_PRELOAD для каждого такого процесса
for f in $(find /proc -maxdepth 2 -name 'environ' -type f \
  -exec grep -Fl 'LD_PRELOAD=' {} \; 2>/dev/null); do
  pid=$(echo "$f" | cut -d/ -f3)
  comm=$(cat /proc/$pid/comm 2>/dev/null)
  val=$(cat "$f" 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD)
  echo "PID=$pid COMM=$comm $val"
done
```

**Инструменты:** easy_triage · UAC

---

### 1.7 PAM Modules (Pluggable Authentication Modules) 🔴 ⚠️

**Что это:** PAM — стандартный механизм аутентификации Linux. Конфигурационные файлы в `/etc/pam.d/` определяют, какие модули (`.so`-библиотеки) участвуют в процессе аутентификации. Злодеи добавляют вредоносный PAM-модуль, который логирует все вводимые пароли или обеспечивает вход с заданным паролем для любого пользователя. Фактически это backdoor в систему аутентификации, который будет работать даже после смены всех паролей.

**Расположение:**
```
/etc/pam.d/                             ← конфиги PAM
/lib/security/*.so                      ← [deb] PAM-модули
/lib64/security/*.so                    ← [rpm] PAM-модули  
/lib/x86_64-linux-gnu/security/*.so     ← [deb, x64] PAM-модули
/usr/lib/security/*.so                  ← альтернативный путь
```

**На какие вопросы отвечает:**
- Есть ли нестандартные или модифицированные PAM-модули?
- Добавлены ли в конфиги аутентификации посторонние строки?
- Хэши всех PAM-модулей для сравнения с эталоном (package manager)?

**Парсинг:**
```bash
# Конфигурация PAM
cat /etc/pam.d/sshd
cat /etc/pam.d/common-auth 2>/dev/null   # deb
cat /etc/pam.d/system-auth 2>/dev/null   # rpm

# Хэши всех PAM-модулей (для сравнения с эталонными)
find /lib /lib64 /usr/lib -name "*.so" -path "*/security/*" \
  -exec md5sum {} \; 2>/dev/null

# Проверка целостности PAM-пакета (сравнение с пакетным менеджером)
dpkg -V libpam-modules 2>/dev/null         # deb
rpm -V pam 2>/dev/null                     # rpm
# Строки, начинающиеся с "5" = изменён хэш = модифицированный файл

# Поиск нестандартных .so в путях PAM
find /lib /lib64 /usr/lib -name "*.so" -path "*/security/*" -newer /bin/bash
```

**Инструменты:** easy_triage (PAM hashes) · UAC

---

### 1.8 SSH Authorized Keys (Backdoor Keys) 🔴

**Что это:** `authorized_keys` — файл со списком публичных ключей, которым разрешён вход по SSH без пароля. **Добавление постороннего публичного ключа в `authorized_keys` — наиболее распространённый и простой способ сохранить долгосрочный SSH-доступ после компрометации.**

**Расположение:**
```
/root/.ssh/authorized_keys      ← контролируется root
/home/*/.ssh/authorized_keys    ← для каждого пользователя
/etc/ssh/sshd_config            ← конфигурация SSH-сервера
/etc/ssh/sshd_config.d/         ← дополнительные конфиги (Ubuntu 22+)
```

**На какие вопросы отвечает:**
- Есть ли посторонние SSH-ключи (backdoor)?
- Когда добавлен ключ (дата файла authorized_keys)?
- Разрешён ли вход root по SSH?
- Есть ли нестандартные директивы в sshd_config (PermitRootLogin, нестандартный порт, AuthorizedKeysFile в нестандартном месте)?

**Парсинг:**
```bash
# Проверить authorized_keys всех пользователей
find /root /home -name "authorized_keys" -exec echo "=== {} ===" \; \
  -exec cat {} \; 2>/dev/null

# Дата создания/изменения файлов
find /root /home -name "authorized_keys" -exec ls -la --full-time {} \; 2>/dev/null

# Ключевые настройки sshd
grep -Ev "^#|^$" /etc/ssh/sshd_config
cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null

# SSH-конфиг хоста: нестандартный порт, PermitRootLogin, AllowUsers
grep -i "PermitRootLogin\|AllowUsers\|AllowGroups\|DenyUsers\|Port\|AuthorizedKeysFile\|PasswordAuthentication" \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

**Инструменты:** UAC · Velociraptor (`Linux.Sys.SSHAuthorizedKeys`)

---

### 1.9 MOTD и Update-MOTD 🟢

**Что это:** Message Of The Day (MOTD) — скрипты в `/etc/update-motd.d/` выполняются при каждом SSH-входе пользователя с правами root.

**На какие вопросы отвечает:**
- Есть ли в MOTD-скриптах посторонние команды (reverse shell, curl, wget)?
- Когда изменён файл скрипта (дата создания/изменения)?
- Добавлены ли нестандартные скрипты в `/etc/update-motd.d/`?

**Расположение:**
```
/etc/update-motd.d/             ← скрипты MOTD (Ubuntu/Debian)
/etc/motd                       ← статический MOTD
```

**Парсинг:**
```bash
ls -la /etc/update-motd.d/
cat /etc/update-motd.d/*
grep -Ei "wget|curl|bash|python|nc |/tmp|/dev/shm" /etc/update-motd.d/* 2>/dev/null
```

**Инструменты:** UAC

---

### 1.10 Глобальные переменные окружения (/etc/environment) 🟡

**Что это:** `/etc/environment` и директория `/etc/environment.d/` задают переменные окружения для **всех** пользователей и всех сессий. Это не shell-скрипт — файл читается PAM при логине и применяется к любой сессии, включая GUI.

**Расположение:**
```
/etc/environment                ← глобальные переменные (PAM)
/etc/environment.d/             ← дополнительные файлы (systemd-environment-d-generator)
/etc/security/pam_env.conf      ← PAM-переменные (альтернатива)
```

**На какие вопросы отвечает:**
- Есть ли нестандартные переменные `LD_PRELOAD` или `LD_LIBRARY_PATH`, загружающие вредоносную библиотеку?
- Переопределён ли `PATH` для подмены системных утилит?
- Когда изменён файл (дата изменения = дата persistence)?

**Парсинг:**
```bash
cat /etc/environment
ls -la /etc/environment.d/
cat /etc/environment.d/*.conf 2>/dev/null
cat /etc/security/pam_env.conf 2>/dev/null

# Подозрительные переменные
grep -rEi "LD_PRELOAD|LD_LIBRARY_PATH|PATH.*=|PYTHONPATH" \
  /etc/environment /etc/environment.d/ /etc/security/pam_env.conf 2>/dev/null
```

**Инструменты:** UAC · easy_triage

---

## 2. Process

*Процессы — волатильный и ценный источник данных. На Linux вся информация о процессах живёт в `/proc` — псевдофайловой системе ядра.*

### 2.1 /proc — Псевдофайловая система процессов ⏱️ 🔴 ⚠️

**Что это:** `/proc` — виртуальная файловая система, через которую ядро Linux экспортирует информацию о всех запущенных процессах и о системе в целом. **Данные существуют только в RAM и исчезают при перезагрузке.** Каждый процесс представлен директорией `/proc/<PID>/` с набором файлов.

Критически важные файлы для каждого процесса:

| Файл | Содержимое | IR-значение |
|------|-----------|------------|
| `/proc/<PID>/exe` | Симлинк на исполняемый файл | Может указывать на `(deleted)` — fileless |
| `/proc/<PID>/cmdline` | Полная командная строка с аргументами | Аргументы запуска |
| `/proc/<PID>/comm` | Имя исполняемого файла (≤15 байт) | Несоответствие с cmdline = подозрение |
| `/proc/<PID>/environ` | Переменные окружения (null-separated) | `LD_PRELOAD`, `HOME`, конфигурация ВПО |
| `/proc/<PID>/maps` | Маппинг памяти: загруженные библиотеки | Инжекты, шелкоды |
| `/proc/<PID>/fd/` | Открытые файловые дескрипторы | Открытые файлы, сокеты |
| `/proc/<PID>/net/tcp` | Сетевые соединения в hex-кодировке | Обход подменённого netstat |
| `/proc/<PID>/status` | Состояние, UID/GID, память | Привилегии процесса |

Системные файлы в `/proc`:

| Файл | Содержимое |
|------|-----------|
| `/proc/modules` | Загруженные модули ядра |
| `/proc/net/tcp`, `/proc/net/udp` | Все TCP/UDP соединения (hex) |
| `/proc/net/arp` | ARP-таблица |
| `/proc/mounts` | Примонтированные устройства |
| `/proc/kallsyms` | Таблица символов ядра (признаки руткитов) |
| `/proc/sys/kernel/tainted` | Код «загрязнения» ядра (unsigned modules) |

**На какие вопросы отвечает:**
- Есть ли процессы, запущенные из удалённых файлов (`exe -> (deleted)`) — fileless persistence?
- Есть ли несоответствие между `/proc/<PID>/comm` и `/proc/<PID>/cmdline` (process hollowing)?
- Какие библиотеки загружены в процесс (maps) — есть ли инжектированные .so?
- Какие переменные окружения у подозрительного процесса?

**Парсинг:**
```bash
# Все исполняемые файлы всех процессов
find /proc -maxdepth 2 -name 'exe' -exec ls -l --full-time {} \; 2>/dev/null

# процессы с удалёнными исполняемыми файлами (fileless)
find /proc -maxdepth 2 -name 'exe' -exec ls -l {} \; 2>/dev/null | grep "(deleted)"

# Все командные строки (два варианта для разных версий strings)
find /proc -maxdepth 2 -name 'cmdline' -print \
  -exec strings -n 1 {} \; 2>/dev/null

# Несоответствие comm vs cmdline (process name spoofing)
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  comm=$(cat /proc/$pid/comm 2>/dev/null)
  cmdline=$(strings -n 1 /proc/$pid/cmdline 2>/dev/null | head -1)
  [ -n "$comm" -a -n "$cmdline" ] && \
    echo "$pid | comm: $comm | cmd: $cmdline"
done | awk -F'|' '$2 != $3 {print}' | head -30   # упрощённо, для быстрой проверки

# Поиск процессов с LD_PRELOAD
find /proc -maxdepth 2 -name 'environ' -type f \
  -exec grep -Fl 'LD_PRELOAD=' {} \; 2>/dev/null

# Прямое чтение сетевой таблицы из /proc (обход подменённого netstat)
cat /proc/net/tcp
# Декодирование hex: адрес в little-endian hex → IP
# Например: 0F02000A:1F40 → 10.0.2.15:8000
```

**Инструменты:** UAC · easy_triage · Velociraptor (`Linux.Memory.ProcessMaps`)

---

### 2.2 Список живых процессов (ps) ⏱️ 🔴

**Что это:** `ps` читает данные из `/proc` и выводит список процессов. Нюанс: при руткит-компрометации вывод `ps` может быть **подменён** (перехват syscall readdir или патч бинаря). В таком случае данные из `/proc` напрямую надёжнее.

**На какие вопросы отвечает:**
- Есть ли процессы из `/tmp`, `/dev/shm`, `/var/tmp` — нетипичных директорий?
- Какова иерархия процессов (parent → child) — есть ли аномалии PPID?
- Есть ли процессы с подозрительными командными строками?
- Запущены ли процессы от root без видимой причины?

**Парсинг:**
```bash
# Все процессы всех пользователей с полным cmdline
ps auxww

# Дерево процессов
ps -deaf
pstree -p -a

# Кастомный вывод: PID, PPID, имя, путь к exe, cmdline
ps -e -o pid,ppid,user,comm,cmd --width 200

# Процессы из подозрительных директорий
ps auxww | grep -E "/tmp/|/dev/shm/|/var/tmp/|/run/user|/proc/[0-9]"

# Прямое чтение из /proc (надёжнее при руткитах)
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  cmd=$(strings -n 1 /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
  echo "PID=$pid EXE=$exe CMD=$cmd"
done | grep -Ei "(deleted)|/tmp|/dev/shm|/var/tmp"
```

**Инструменты:** UAC · easy_triage

---

### 2.3 Хэши исполняемых файлов 🔴

**Что это:** SHA256/MD5-хэши бинарей для сравнения с TI источниками и эталонными хэшами пакетного менеджера. Изменение хэша системного бинаря - признак потенциальной подмены.

**На какие вопросы отвечает:**
- Есть ли известные вредоносные хэши в системе?
- Изменены ли системные бинари?
- Какие исполняемые файлы есть в нетипичных директориях?

**Парсинг:**
```bash
# Хэши системных бинарей
find /usr/bin /usr/sbin /bin /sbin -type f \
  -exec sha256sum {} \; 2>/dev/null > hashes_system.txt

# Исполняемые в подозрительных местах
find /tmp /var/tmp /dev/shm -type f \
  -exec sha256sum {} \; 2>/dev/null > hashes_suspicious.txt

# Проверка целостности через пакетный менеджер
debsums -c 2>/dev/null | head -50              # deb: изменённые файлы пакетов
rpm -Va 2>/dev/null | grep "^..5" | head -50   # rpm: измененный хэш (5 = hash)

# Поиск ВСЕХ исполняемых файлов не из пакетного менеджера (нетипичные бинари)
# [deb]:
find /usr/bin /usr/sbin /bin /sbin -type f | while read f; do
  dpkg -S "$f" > /dev/null 2>&1 || echo "NOT IN PACKAGES: $f"
done
```

**Инструменты:** UAC · easy_triage

---

### 2.4 Открытые файловые дескрипторы (lsof) ⏱️ 🔴

**Что это:** В Linux всё — файл: сокеты, пайпы, устройства, обычные файлы — всё представлено дескрипторами. `lsof` агрегирует данные из `/proc/<PID>/fd/` и `/proc/<PID>/maps`.

**На какие вопросы отвечает:**
- Какие файлы открыты у подозрительного процесса?
- Есть ли процессы с открытыми **удалёнными** файлами (`(deleted)`)?
- Какие сетевые соединения активны и какой процесс их держит?
- Есть ли файлы, которые отсутствуют в bodyfile (скрытые от `stat`)?

**Парсинг:**
```bash
# Все дескрипторы всех процессов
sudo lsof -nPl > lsof_full.txt

# Только сетевые соединения
sudo lsof -i -n -P

# Только удалённые файлы, которые всё ещё открыты (fileless)
sudo lsof -n | grep "(deleted)"

# Дескрипторы конкретного процесса
sudo lsof -p <PID>

# Кто использует конкретный файл или директорию
lsof /path/to/file
```

**Инструменты:** UAC · Velociraptor (`Linux.Sys.OpenFiles`)

---

## 3. Network

*Сетевые артефакты — собирать сразу после процессов. На живой системе — первый приоритет.*

### 3.1 Активные соединения ⏱️ 🔴

**Что это:** Таблица всех текущих TCP/UDP сокетов с привязкой к процессам. При руткит-компрометации вывод `netstat`/`ss` может быть подменён — в этом случае читай напрямую из `/proc/net/tcp`.

**На какие вопросы отвечает:**
- Какие процессы имеют активные соединения с внешними IP?
- Есть ли C2 (нетипичные порты, подозрительные IP)?
- Есть ли новые listening ports (потенциальный backdoor)?

**Парсинг:**
```bash
# Все соединения с привязкой к процессу
ss -anp
netstat -anp

# Только ESTABLISHED соединения
ss -anp state established
netstat -anp | grep ESTABLISHED

# Listening ports (потенциальные backdoor'ы)
ss -lnp
netstat -lnp

# Прямое чтение из /proc (обход подменённого netstat/ss)
# TCP: /proc/net/tcp (IPv4), /proc/net/tcp6 (IPv6)
# UDP: /proc/net/udp
cat /proc/net/tcp | awk '{print $2, $3, $4}' | head -20
# Декодирование: awk скрипт для hex→IP:PORT
awk '{
  if ($4 == "01") {
    n=split($2,a,":"); printf "LOCAL: "
    for(i=7;i>=1;i-=2) printf "%d.", strtonum("0x" substr(a[1],i,2)); 
    printf "\b:%d\n", strtonum("0x" a[2])
  }
}' /proc/net/tcp
```

**Инструменты:** UAC · Velociraptor (`Linux.Network.Netstat`)

---

### 3.2 ARP-кэш и соседи ⏱️ 🟡

**Что это:** Таблица разрешения IP → MAC для локальной сети. Аномальные записи (один IP у двух разных MAC) указывают на ARP-спуфинг — перехват трафика в LAN.

**Расположение:**
```
/proc/net/arp               ← текущая ARP-таблица ядра
```

**На какие вопросы отвечает:**
- Есть ли ARP-спуфинг (один IP привязан к подозрительному MAC)?
- Какие хосты находятся в локальной сети?
- Есть ли незнакомые MAC-адреса в таблице?

**Парсинг:**
```bash
arp -a -n
ip neighbor show
cat /proc/net/arp
```

**Инструменты:** UAC · easy_triage

---

### 3.3 Таблица маршрутизации ⏱️ 🟡

**Что это:** Правила маршрутизации сетевых пакетов. Злоумышленники могут добавить нестандартные маршруты для перенаправления трафика через подконтрольный хост или для сокрытия C2-коммуникации.

**Расположение:**
```
/proc/net/route             ← таблица маршрутизации IPv4 (hex-формат)
/proc/net/ipv6_route        ← таблица маршрутизации IPv6
```

**На какие вопросы отвечает:**
- Есть ли нестандартные маршруты, перенаправляющие трафик?
- Изменён ли шлюз по умолчанию?
- Добавлены ли статические маршруты к подозрительным подсетям?

**Парсинг:**
```bash
ip route show
ip route show table all
netstat -rn
cat /proc/net/route
```

**Инструменты:** UAC · easy_triage

---

### 3.3.1 Unix Domain Sockets ⏱️ 🟢

**Что это:** Сокеты Unix-домена — IPC-механизм для коммуникации процессов на одном хосте. Малварь использует их для локальной C2-коммуникации между компонентами (дроппер ↔ агент), обходя сетевые инструменты мониторинга.

**На какие вопросы отвечает:**
- Есть ли Unix-сокеты в нестандартных путях (не `/run/`, `/var/run/`)?
- Какие процессы держат открытые сокеты — нет ли неизвестных связей между компонентами?
- Используются ли сокеты как канал локальной C2-коммуникации?

**Парсинг:**
```bash
cat /proc/net/unix
ss -xlp                              # Unix сокеты с привязкой к процессам
lsof -U 2>/dev/null | head -50       # Unix сокеты через lsof

# Подозрительные сокеты вне стандартных путей
ss -xlp | grep -v "/run/\|/tmp/.X\|/var/run\|/sys"
```

**Инструменты:** UAC

---

### 3.4 DNS-кэш ⏱️ 🔴

**Что это:** Кэш недавно разрешённых доменных имён. Позволяет увидеть C2-домены, DGA-паттерны. Очищается при перезагрузке или рестарте DNS-сервиса.

**На какие вопросы отвечает:**
- Есть ли DNS-запросы к известным C2 или DGA-доменам?
- К каким доменам обращалась система?

**Парсинг:**
```bash
# systemd-resolved (Ubuntu 18.04+, современный стандарт)
resolvectl show-cache 2>/dev/null || systemd-resolve --statistics 2>/dev/null

# Принудительный дамп кэша в journal
pkill -USR1 systemd-resolve 2>/dev/null   # записывает кэш в journald
journalctl -u systemd-resolved --since "1 minute ago" | grep -i "cache\|query"

# nscd (если установлен — Network Service Cache Daemon)
nscd -g 2>/dev/null

# dnsmasq
cat /var/cache/dnsmasq/* 2>/dev/null
```

**Инструменты:** UAC · easy_triage

---

### 3.5 Конфигурация сети и /etc/hosts 🟡

**Что это:** `/etc/hosts` имеет приоритет над DNS. Малварь модифицирует его для блокировки обновлений AV или перенаправления трафика. `resolv.conf` определяет DNS-серверы.

**Расположение:**
```
/etc/hosts
/etc/resolv.conf
/etc/nsswitch.conf              ← порядок разрешения имён
/etc/systemd/resolved.conf      ← конфигурация systemd-resolved
/etc/network/interfaces         ← [deb] конфигурация сетевых интерфейсов
/etc/sysconfig/network-scripts/ ← [rpm] конфигурация интерфейсов
/etc/NetworkManager/            ← конфигурация NetworkManager
/etc/netplan                    ← конфигурация netplan
```

**На какие вопросы отвечает:**
- Изменён ли `/etc/hosts` (перенаправление доменов обновлений или C2-доменов)?
- Изменены ли DNS-серверы в `resolv.conf` (перехват DNS)?
- Какие сетевые интерфейсы активны и с какими адресами?

**Парсинг:**
```bash
cat /etc/hosts
cat /etc/resolv.conf
ip addr show
ip link show
ifconfig -a 2>/dev/null
nmcli -t 2>/dev/null

# Wi-Fi (если применимо)
iwconfig 2>/dev/null
iwgetid 2>/dev/null
```

**Инструменты:** UAC · easy_triage

---

### 3.6 Netfilter / iptables / nftables 🟡

**Что это:** Межсетевой экран Linux. Правила могут быть настроены злоумышленником для перенаправления трафика через DNAT/SNAT, блокировки трафика к AV-серверам или сокрытия listening-портов ВПО.

**Расположение:**
```
/etc/iptables/rules.v4          ← [deb] сохранённые правила iptables
/etc/sysconfig/iptables         ← [rpm] сохранённые правила
/etc/nftables.conf              ← nftables конфигурация
```

**На какие вопросы отвечает:**
- Есть ли правила NAT/DNAT, перенаправляющие трафик?
- Блокируется ли трафик к серверам обновлений или AV?
- Добавлены ли нестандартные ACCEPT-правила для скрытых портов?

**Парсинг:**
```bash
iptables -L -v -n 2>/dev/null
iptables -t nat -L -v -n 2>/dev/null
ip6tables -L -v -n 2>/dev/null
nft list ruleset 2>/dev/null

# Сохранённые правила
cat /etc/iptables/rules.v4 2>/dev/null     # deb
cat /etc/sysconfig/iptables 2>/dev/null    # rpm
```

**Инструменты:** UAC · easy_triage

---

## 4. File System

*Файловые артефакты — история активности на диске.*

### Метки времени (MACB)

В Linux применяется стандартная модель MACB:

| Метка | Значение | Изменяется при |
|-------|---------|---------------|
| **M** — mtime | Последнее изменение **содержимого** файла | Запись в файл |
| **A** — atime | Последний доступ к файлу | Чтении файла (если не `noatime`) |
| **C** — ctime | Изменение метаданных inode | Смена прав, владельца, mtime |
| **B** — crtime/btime | Создание файла | Только при создании |

> ⚠️ Метка Birth (btime) поддерживается не всеми файловыми системами. ext4 поддерживает, но многие утилиты не показывают её по умолчанию. Для получения btime используй `debugfs` или `stat --printf='%w'`.


### 4.1 Bodyfile (MACB Timestamps) 🔴

**Что это:** Дамп метаданных всех файлов с четырьмя временными метками MACB. Используется для построения детального timeline файловых событий. В отличие от Windows (MFT) и macOS (FSEvents), Linux не имеет встроенного журнала файловой системы с богатой телеметрией, поэтому bodyfile — **главный инструмент построения временно́й шкалы** на Linux.

**На какие вопросы отвечает:**
- Когда создан/изменён/открыт любой файл системы?
- Есть ли timestomping (несоответствие между временными метками)?
- Какова хронология файловых операций злоумышленника?
- Какие файлы появились/изменились в период инцидента?

**Парсинг:**
```bash
# Создание bodyfile (The Sleuth Kit / fls)
sudo fls -r -m "/" /dev/sda1 > bodyfile.txt    # для образа

# На живой системе — через find и stat
find / -xdev -print0 2>/dev/null | \
  xargs -0 stat --printf="%i|%N|%n|%x|%y|%z|%w|%U|%G|%A|%s\n" \
  2>/dev/null > bodyfile_live.txt

# Timeline из bodyfile
mactime -b bodyfile.txt -d > timeline.csv
mactime -b bodyfile.txt -d -z UTC 2024-01-01 2024-12-31 > timeline_filtered.csv

# Обнаружение timestomping:
# mtime < ctime — подозрительно (mtime откатили назад, ctime обновился)
find / -xdev -type f -newer /tmp/ref_time 2>/dev/null -exec \
  stat --printf="%n mtime=%y ctime=%z\n" {} \; | head -50
```

**Инструменты:** UAC (bodyfile) · The Sleuth Kit · Plaso (`--parsers filestat`)

---

### 4.2 Временные и Volatile директории 🔴

**Что это:** Классические места для staging вредоносного ПО. `/tmp` и `/var/tmp` доступны на запись всем пользователям. `/dev/shm` — **shared memory tmpfs, существует только в RAM** — используется для временных файлов и fileless malware. Содержимое `/tmp` очищается при перезагрузке; `/var/tmp` — нет.

**Расположение:**
```
/tmp/                   ← очищается при перезагрузке
/var/tmp/               ← не очищается (persistent temp)
/dev/shm/               ← shared memory, только RAM, очищается при ребуте
/run/                   ← volatile runtime данные
/run/user/<UID>/        ← пользовательский runtime
```

**На какие вопросы отвечает:**
- Есть ли исполняемые файлы в `/tmp`, `/dev/shm`, `/var/tmp`?
- Когда они появились и кто их создал?
- Есть ли fileless malware — процессы с открытыми удалёнными файлами из `/dev/shm`?

**Парсинг:**
```bash
# Файлы в подозрительных местах
ls -latR /tmp/ /var/tmp/ /dev/shm/ 2>/dev/null

# Созданные за последние 24 часа
find /tmp /var/tmp /dev/shm -mtime -1 -type f -ls 2>/dev/null

# Исполняемые файлы в /tmp и /dev/shm
find /tmp /var/tmp /dev/shm -type f -perm /111 \
  -exec sha256sum {} \; 2>/dev/null

# Скопировать содержимое для анализа
cp -r /dev/shm/ /output/dev_shm/ 2>/dev/null
```

**Инструменты:** UAC · easy_triage

---

### 4.3 SUID/SGID Файлы 🔴 ⚠️

**Что это:** SUID (Set User ID) — бит, позволяющий запускать файл с правами его **владельца** (обычно root), а не запускающего пользователя. SGID — аналогично для группы. Это легитимный механизм (например, `passwd`, `sudo`, `ping`), но нелегитимный SUID-бинарь = мгновенное повышение привилегий до root. **Любой SUID-файл вне стандартных системных путей — критический индикатор.**

**На какие вопросы отвечает:**
- Есть ли нелегитимные SUID-бинари в системе?
- Изменился ли хэш легитимных SUID-файлов?
- Есть ли SUID-файлы в `/tmp`, `/dev/shm` или пользовательских директориях?

**Парсинг:**
```bash
# Все SUID файлы в системе
find / -xdev -type f -perm -u+s 2>/dev/null

# Все SGID файлы
find / -xdev -type f -perm -g+s 2>/dev/null

# Только в подозрительных местах
find /tmp /var/tmp /dev/shm /home -type f -perm -u+s 2>/dev/null

# Сравнить с эталоном (только файлы пакетного менеджера должны иметь SUID)
find / -xdev -type f -perm -u+s 2>/dev/null | while read f; do
  dpkg -S "$f" > /dev/null 2>&1 || echo "NOT IN PACKAGES (SUID!): $f"  # deb
done
```

**Инструменты:** easy_triage · UAC · Velociraptor

---

### 4.4 Linux Capabilities 🔴

**Что это:** Более гранулярная альтернатива SUID. Capabilities позволяют выдать процессу только конкретные привилегии (например, `cap_net_raw` для raw sockets, `cap_sys_admin` для системных вызовов admin-уровня). Нелегитимные capabilities на бинарях = повышение привилегий без SUID.

**Особо опасные capabilities:**

| Capability | Что позволяет |
|-----------|--------------|
| `cap_sys_admin` | Почти root (mount, ioctl, ptrace и др.) |
| `cap_net_admin` | Управление сетью, firewall |
| `cap_dac_override` | Обход проверки прав доступа к файлам |
| `cap_setuid` | Смена UID произвольно |
| `cap_bpf` | Загрузка eBPF-программ |
| `cap_sys_module` | Загрузка модулей ядра |

**На какие вопросы отвечает:**
- Есть ли нелегитимные capabilities на бинарях в нестандартных путях?
- Какие процессы обладают повышенными capabilities в runtime?
- Есть ли capabilities, позволяющие получить root без SUID?

**Парсинг:**
```bash
# Все файлы с capabilities
getcap -r / 2>/dev/null

# Только в подозрительных местах
getcap -r /tmp /var/tmp /dev/shm /home /usr/local 2>/dev/null

# Capabilities в /proc (на процессы)
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  cap=$(cat /proc/$pid/status 2>/dev/null | grep -E "CapPrm|CapEff|CapBnd")
  [ -n "$cap" ] && echo "PID=$pid $cap"
done | grep -v "0000000000000000"
```

**Инструменты:** easy_triage · UAC

---

### 4.5 Скрытые файлы и директории 🟡

**Что это:** Файлы/директории, начинающиеся с точки (`.`), скрыты от стандартного `ls`. Злоумышленники часто помещают инструменты и конфиги в скрытые директории.

**На какие вопросы отвечает:**
- Есть ли скрытые исполняемые файлы в `/tmp`, `/home`, `/root`?
- Есть ли скрытые директории вне стандартных (`.git`, `.config`, `.local`)?
- Используются ли имена с пробелами или спецсимволами для маскировки?

**Парсинг:**
```bash
# Скрытые файлы в чувствительных местах
find /tmp /var/tmp /dev/shm /home /root -name ".*" -type f -ls 2>/dev/null

# Скрытые директории
find / -xdev -name ".*" -type d 2>/dev/null | grep -v ".git\|.config\|.local"

# Файлы с необычными именами (пробелы, спецсимволы)
find / -xdev -name "* *" -o -name ".. " 2>/dev/null | head -20
```

**Инструменты:** UAC · easy_triage

---

### 4.6 World-Writable Files 🟢

**Что это:** Файлы с правами записи для всех пользователей. Могут быть использованы злоумышленником без root-прав для внедрения кода или подмены файлов.

**На какие вопросы отвечает:**
- Есть ли world-writable файлы в системных директориях?
- Есть ли writable директории вне `/tmp` и `/var/tmp` (нестандартные staging-точки)?
- Могут ли быть подменены скрипты, запускаемые из cron или systemd?

**Парсинг:**
```bash
find / -xdev -type f -perm -o+w 2>/dev/null | \
  grep -v "/proc\|/sys\|/dev" | head -50

# Writable директории (staging-точки)
find / -xdev -type d -perm -o+w 2>/dev/null | \
  grep -v "/proc\|/sys\|/dev\|/tmp\|/var/tmp" | head -30
```

**Инструменты:** UAC · easy_triage

---

## 5. User Activity

*Цифровой след пользователя: команды, файлы, активность.*

### 5.1 Shell History 🔴

**Что это:** Файлы истории командной оболочки. Основной источник информации о действиях пользователя/злоумышленника. Важная особенность: **история записывается в файл при завершении сессии**, поэтому если злоумышленник убил терминал — последние команды могут не сохраниться. Кроме того, злоумышленники часто намеренно отключают запись истории (`unset HISTFILE`, `export HISTSIZE=0`, `HISTFILE=/dev/null`).

**Расположение:**
```
# Bash (наиболее распространён)
~/.bash_history                         ← основной файл истории
/root/.bash_history                     ← root shell

# Zsh
~/.zsh_history
~/.zhistory

# Fish
~/.local/share/fish/fish_history

# Текстовые редакторы (история команд в редакторе)
~/.viminfo                              ← vim: история поиска, файлы
~/.nano_history                         ← nano
~/.lesshst                             ← less: история поиска

# Файловые менеджеры
~/.local/share/mc/history              ← Midnight Commander

# СУБД (Базы данных)
~/.psql_history                         ← PostgreSQL
~/.mysql_history                        ← MySQL
~/.sqlite_history                       ← SQLite

# Языки программирования
~/.python_history                       ← Python
~/.irb_history                          ← Ruby IRB
~/.node_repl_history                    ← Node.js

# Сетевые утилиты
~/.netrc                                ← credentials для ftp/curl
~/.wget-hsts                           ← wget HSTS база
```

**На какие вопросы отвечает:**
- Какие команды выполнял злоумышленник?
- Есть ли lateral movement (ssh, scp к другим хостам)?
- Использовались ли инструменты эксфильтрации (curl, wget, nc, base64)?
- Были ли попытки сокрытия следов (удаление history, перенаправление в `/dev/null`)?
- Есть ли следы компиляции exploit-кода (gcc, make, python)?

**Парсинг:**
```bash
# История для всех пользователей
for dir in /root /home/*; do
  echo "=== $dir ==="
  cat "$dir/.bash_history" 2>/dev/null
  cat "$dir/.zsh_history" 2>/dev/null
done

# Поиск подозрительных команд (регулярка из easy_triage ^_^)
grep -Ei 'wget|curl|qemu|http|tcp|tor|tunnel|reverse|socks|proxy|cred|ssh|php|perl|python|\.py|\.sh|\.sql|tmp|temp|shm|splo|xplo|cve|gcc|chmod|passwd|shadow|useradd|authorized_keys|hosts|[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}|github|pastebin|cdn|(:| )(443|80|22|445|3389)|nmap|scan|dump|flood|ddos|ncat|netcat|a\.out|HISTFILE|preload|whoami' \
  /root/.bash_history /home/*/.bash_history 2>/dev/null

# Viminfo — недавно редактировавшиеся файлы
cat /root/.viminfo | grep "^>"
cat /home/*/.viminfo 2>/dev/null | grep "^>"

# Python history
cat /root/.python_history /home/*/.python_history 2>/dev/null
```

**Инструменты:** UAC · easy_triage · Velociraptor

---

### 5.2 Недавно изменённые файлы пользователя 🟡

**Что это:** Файлы в пользовательских директориях, изменённые недавно. Позволяют быстро найти созданные злоумышленником файлы.

**На какие вопросы отвечает:**
- Какие файлы появились или изменились в период инцидента?
- Есть ли новые исполняемые файлы в домашних директориях?
- Когда последний раз изменялись конфигурационные файлы пользователей?

**Парсинг:**
```bash
# Изменённые за последние 7 дней в домашних директориях
find /home /root -mtime -7 -type f -ls 2>/dev/null | sort -k8

# Созданные исполняемые файлы
find /home /root -mtime -30 -type f -perm /111 -ls 2>/dev/null
```

**Инструменты:** UAC · easy_triage

---

## 6. System Logs

*Системные журналы — критически важный источник данных на Linux. Большинство логов подвергаются ротации — старые файлы перезаписываются. Всегда обращать внимание на файлы с расширениями `.1`, `.2`, `.gz` — это архивные версии.*

### 6.1 Логи аутентификации 🔴 🔄

**Что это:** Журналы входа пользователей в систему. Включают успешную и неуспешную аутентификацию через SSH, su, sudo, PAM. Существуют в двух форматах: текстовом (auth.log / secure) и бинарном (wtmp, btmp, lastlog).

**Расположение:**
```
# Текстовые логи аутентификации
/var/log/auth.log*              ← [deb] успешная аутентификация, sudo, su, SSH
/var/log/secure*                ← [rpm] аналог auth.log

# Бинарные журналы (читаются специальными утилитами)
/var/log/wtmp                   ← успешные входы/выходы (исторический)
/var/log/btmp                   ← неуспешные попытки аутентификации
/var/run/utmp                   ← текущие активные сессии (volatile)
/var/log/lastlog                ← последний вход каждого пользователя (sparse-файл)
/var/log/faillog                ← количество неудачных попыток входа
```

> ⚠️ `/var/log/lastlog` — **sparse-файл**. Размер на диске намного меньше видимого. В средах с доменными учётками и высокими UID файл может выглядеть гигантским (иногда, сотни терайбайт и более), но фактически занимать килобайты. Копировать через `cp --sparse=always`.

> **Новые дистрибутивы:** openSUSE, часть Fedora и экспериментальные сборки systemd заменяют `wtmp`/`lastlog` на `wtmpdb` и `lastlog2` (SQLite-базы). Инструменты: `wtmpdb show`, `lastlog2`. Традиционные `last`/`lastb` на таких системах могут вернуть пустой вывод — проверяй наличие `/var/lib/wtmpdb/wtmpdb`.

**На какие вопросы отвечает:**
- Кто и когда входил в систему?
- Откуда (IP-адрес) происходили SSH-входы?
- Были ли попытки брутфорса (btmp)?
- Какие команды выполнялись с sudo?
- Были ли попытки su под другого пользователя?

**Парсинг:**
```bash
# auth.log — базовая фильтрация
cat /var/log/auth.log | grep -Ei "Failed|Accepted|Invalid|sudo|session"

# Только SSH-входы
grep "sshd" /var/log/auth.log | grep -E "Accepted|Failed|Invalid" | tail -100

# Попытки брутфорса (группировка по IP)
grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# wtmp — история успешных входов
last -f /var/log/wtmp | head -50
last -w -f /var/log/wtmp | head -50   # полный hostname

# btmp — история неудачных входов
lastb -f /var/log/btmp | head -50

# lastlog — последний вход каждой учётки
lastlog

# utmp — текущие активные сессии (кто сейчас в системе)
who
w
utmpdump /var/run/utmp
```

**Инструменты:** UAC · easy_triage · Velociraptor

---

### 6.2 Systemd Journal (journald) 🔴 🔄

**Что это:** Бинарная система логирования, встроенная в systemd. Пишет логи от всех служб, ядра и системных компонентов в структурированный бинарный формат. Является заменой (и дополнением) syslog на современных системах. `journalctl` — инструмент просмотра. **Важная особенность:** journal хранит больше метаданных, чем syslog (PID, UID, GID, systemd unit). По нему гораздо удобнее выстраивать общий таймлайн действий.

**Расположение:**
```
/var/log/journal/               ← persistent journal (если включён)
/run/log/journal/               ← volatile journal (очищается при перезагрузке)
/run/journal/                   ← альтернативный volatile путь
```

**На какие вопросы отвечает:**
- Что делали все службы системы в любой момент времени?
- Какие ошибки и краши происходили?
- Какие process/service запускались и завершались?

**Парсинг:**
> По умолчанию journalctl выводит данные в часовом поясе системы. Для вывода в UTC добавить параметр `--utc`.

```bash
# Все логи за последние 7 дней
journalctl --since "7 days ago" --no-pager

# По конкретной службе
journalctl -u ssh.service --no-pager
journalctl -u cron.service --no-pager

# Логи ядра
journalctl -k --no-pager

# Экспорт всего journal в JSON (для дальнейшего анализа)
journalctl -o json > journal_export.json

# Поиск по строке
journalctl --grep "Failed\|error\|segfault" --no-pager | tail -100

# Строки из journal-файлов напрямую (резервный метод)
find /run/log/journal/ /run/journal/ /var/log/journal/ -type f \
  -exec strings -n 8 {} \; 2>/dev/null | gzip > journal_strings.txt.gz
```

**Инструменты:** UAC · easy_triage · Velociraptor (`Linux.Logs.Journald`)

---

### 6.3 Syslog 🟡 🔄

**Что это:** Традиционная система текстового логирования. На современных системах rsyslog или syslog-ng собирают события от различных источников и записывают их в `/var/log/syslog` (deb) или `/var/log/messages` (rpm). Практически все важные системные события попадают сюда в том или ином виде.

**На какие вопросы отвечает:**
- Какие системные события происходили в период инцидента?
- Есть ли ошибки, указывающие на эксплуатацию (fail, error, segfault)?
- Фиксировались ли попытки подключения по SSH или события cron?

**Расположение:**
```
/var/log/syslog*                ← [deb] основной системный лог
/var/log/messages*              ← [rpm] основной системный лог
/etc/rsyslog.conf               ← конфигурация rsyslog
/etc/rsyslog.d/                 ← дополнительные конфиги rsyslog
```

**Парсинг:**
```bash
cat /var/log/syslog | tail -1000
grep -Ei "error|fail|warning|cron|kernel|ssh" /var/log/syslog | tail -200
```

> Проверить, в каком часовом поясе пишется syslog. Обычно - в локальном системы.

**Инструменты:** UAC · easy_triage

---

### 6.4 Лог ядра (kernel/dmesg) 🟡

**Что это:** Системные сообщения ядра. Критичен для анализа: эксплуатации LPE уязвимостей (kernel exploits), загрузки нестандартных модулей ядра, ошибок сегментации (shellcode-индикатор), аппаратных событий.

**Расположение:**
```
/var/log/kern.log*              ← [deb] персистентные лог ядра
/var/log/dmesg*                 ← снапшот на момент загрузки
```

**На какие вопросы отвечает:**
- Были ли ошибки сегментации (segfault) — признак shellcode или нестабильного эксплойта?
- Загружались ли неподписанные или нестандартные модули ядра?
- Есть ли kernel oops или panic, совпадающие по времени с инцидентом?

**Парсинг:**
```bash
dmesg --since "1 hour ago"
dmesg | grep -Ei "error|oops|panic|segfault|killed\|taint\|module"
cat /var/log/kern.log | grep -Ei "segfault|killed|module\|exploit" | tail -100

# Tainted kernel (загружены неподписанные модули или произошли ошибки)
cat /proc/sys/kernel/tainted
# 0 = чисто; любое другое значение требует проверки
```

**Инструменты:** UAC · easy_triage

---

### 6.5 Логи аудита (auditd) 🔴 ⚠️

**Что это:** Подсистема аудита Linux ядра. При включённом `auditd` записывает детальные события: системные вызовы, изменения файлов, команды с отслеживанием исполнителя. По объёму информации значительно богаче syslog — если auditd настроен, это лучший источник для расследования. Однако срок жизни журналов очень маленький (обычно 1-3 дня), поэтому источник данных очень волатильный.

**Расположение:**
```
/var/log/audit/audit.log*       ← основной журнал auditd
/var/log/auditd.log*
/etc/audit/auditd.conf          ← конфигурация
/etc/audit/rules.d/             ← правила аудита
```

**На какие вопросы отвечает:**
- Какие команды выполнялись и от имени каких пользователей?
- Были ли изменены критические файлы (`/etc/passwd`, `/etc/sudoers`)?
- Какие системные вызовы (execve, setuid) вызывались в период инцидента?
- Были ли неудачные попытки аутентификации?

**Парсинг:**
```bash
# Проверить, запущен ли auditd
systemctl status auditd 2>/dev/null

# Базовое чтение (текстовый формат)
cat /var/log/audit/audit.log | tail -200

# Человекочитаемый вывод через ausearch
ausearch -ts recent 2>/dev/null | head -100

# Все execve (выполненные команды)
ausearch -sc execve -ts today 2>/dev/null | head -200

# Попытки смены uid (sudo, su, setuid)
ausearch -sc setuid -ts today 2>/dev/null

# Изменения файлов в /etc
ausearch -f /etc/passwd -ts today 2>/dev/null

# Конвертация в human-readable через aureport
aureport --summary 2>/dev/null
aureport -au --failed 2>/dev/null     # неуспешные аутентификации
aureport -x --summary 2>/dev/null     # выполненные команды
```

**Инструменты:** UAC · easy_triage · Velociraptor

---

### 6.6 Логи пакетных менеджеров 🟡 🔄

**Что это:** Журналы установки, удаления и обновления пакетов. Позволяют установить точное время инсталляции подозрительного ПО. Злоумышленники нередко устанавливают легитимные инструменты (nmap, netcat, ncat) прямо с репозитория.

**Расположение:**
```
# Debian/Ubuntu
/var/log/dpkg.log*              ← история операций dpkg
/var/log/apt/history.log*       ← история apt (высокоуровневые операции)
/var/log/apt/term.log*          ← терминальный вывод apt

# RHEL/CentOS/Fedora
/var/log/dnf.log*               ← история dnf
/var/log/dnf.rpm.log*           ← RPM-операции через dnf
/var/log/yum.log*               ← история yum (legacy)
```

**На какие вопросы отвечает:**
- Какое ПО устанавливалось и когда?
- Устанавливались ли подозрительные инструменты (nmap, nc, ncat, wget, curl)?
- Были ли установки в нетипичное время (ночью, в выходные)?
- Удалялись ли пакеты для сокрытия следов?

**Парсинг:**
```bash
# dpkg история — deb
cat /var/log/dpkg.log | grep " install\| remove" | tail -100
cat /var/log/apt/history.log | head -200

# Поиск подозрительных пакетов
grep -Ei "nmap|netcat|ncat|masscan|hydra|john|hashcat|aircrack|socat|chisel" \
  /var/log/dpkg.log /var/log/apt/history.log 2>/dev/null

# dnf/yum история — rpm
dnf history list 2>/dev/null | head -30
cat /var/log/dnf.log | grep "Installed\|Removed" | tail -100
```

**Инструменты:** UAC · easy_triage

---

### 6.7 Лог Cron 🟡 🔄

**Что это:** Журнал выполнения cron-задач. Критичен для обнаружения вредоносных задач и установления хронологии их выполнения. Часто логируется syslog.

**Расположение:**
```
/var/log/cron*                  ← [rpm]
/var/log/cron.log*              ← [deb] (если настроен)
# Также в syslog/journal: grep для "CRON"
```

**На какие вопросы отвечает:**
- Выполнялись ли вредоносные cron-задачи и когда?
- Есть ли задачи, запускавшиеся в нетипичное время?
- Какой пользователь владеет задачей и что она запускает?

**Парсинг:**
```bash
cat /var/log/cron* 2>/dev/null | tail -200
grep -i "CRON\|crontab" /var/log/syslog 2>/dev/null | tail -100
journalctl -u cron --no-pager | tail -200
```

**Инструменты:** UAC · easy_triage

---

### 6.8 Лог загрузчика (boot) 🟢

**Что это:** Журнал процесса загрузки ОС. Редкий кейс, но может помочь в обнаружении bootkit'ов и модификаций загрузчика.

**Расположение:**
```
/var/log/boot.log
/boot/grub/grub.cfg             ← конфигурация GRUB
/boot/grub2/grub.cfg            ← [rpm]
```

**На какие вопросы отвечает:**
- Были ли изменения в конфигурации GRUB (нестандартные параметры ядра)?
- Есть ли признаки bootkit'а (аномальные записи в начале загрузки)?
- Совпадает ли время последней перезагрузки с предполагаемым инцидентом?

**Парсинг:**
```bash
cat /var/log/boot.log | tail -100
cat /boot/grub/grub.cfg 2>/dev/null || cat /boot/grub2/grub.cfg 2>/dev/null
```

**Инструменты:** UAC

---

### 6.9 Process Accounting (pacct) 🟢 ⚠️

**Что это:** Подсистема ядра, которая записывает базовую информацию о каждом завершившемся процессе в бинарный файл. В отличие от auditd не требует настройки правил — если включена, фиксирует всё. Включается через `accton`. По умолчанию выключена, но на некоторых серверах (особенно старых) может быть активна.

**Что фиксирует:** имя команды, время старта и завершения, UID, GID, exit-код, использование CPU.

**Что НЕ фиксирует:** аргументы командной строки (только имя бинаря).

**На какие вопросы отвечает:**
- Какие команды (имена бинарей) выполнялись в системе и кем?
- Есть ли активность от подозрительных пользователей в период инцидента?
- Выполнялись ли нестандартные бинари — даже если auditd не был настроен?

**Расположение:**
```
/var/account/pacct              ← [deb] основной файл
/var/log/account/pacct          ← [rpm]
```

**Парсинг:**
```bash
# Проверить, включён ли accounting
ls -la /var/account/pacct /var/log/account/pacct 2>/dev/null

# Чтение через lastcomm (показывает команды в обратном порядке)
lastcomm 2>/dev/null | head -100

# Статистика по пользователю
lastcomm root 2>/dev/null

# Все команды за сегодня с временными метками
lastcomm --time 2>/dev/null | head -100

# Детальный анализ через sa
sa 2>/dev/null | head -50
```

**Инструменты:** UAC

---

## 7. Authentication

*Аутентификация и разрешения — кто, что и когда мог делать.*

### 7.1 /etc/passwd и /etc/shadow 🔴 ⚠️

**Что это:** Основная база пользователей Linux. `/etc/passwd` — список всех пользователей (без паролей, читается всеми). `/etc/shadow` — хэши паролей (читается только root). Злоумышленники создают backdoor-пользователей или модифицируют существующих.

**На какие вопросы отвечает:**
- Есть ли нелегитимные пользователи в системе?
- Есть ли пользователи с UID=0 (фактически root) кроме root?
- Какой shell назначен пользователям (наличие `/bin/bash` у служебных учётных записей)?
- Когда изменялся файл `/etc/passwd`?

**Парсинг:**
```bash
cat /etc/passwd

# Пользователи с UID=0 (root-эквиваленты) кроме root
awk -F: '$3==0 {print}' /etc/passwd

# Пользователи с интерактивным shell
grep -v "/nologin\|/false" /etc/passwd | grep -v "^#"

# Сравнение с эталоном через пакетный менеджер
debsums -c passwd 2>/dev/null        # deb
rpm -V shadow-utils 2>/dev/null      # rpm

# Просмотр shadow (только root)
sudo cat /etc/shadow | head -20

# Дата последней смены пароля (поле 3 в shadow: дней с 1970-01-01)
awk -F: '$3 != "" {print $1, $3}' /etc/shadow | while read user days; do
  date -d "1970-01-01 $days days" +"%Y-%m-%d $user" 2>/dev/null
done
```

**Инструменты:** UAC · easy_triage · Velociraptor (`Linux.Sys.Users`)

---

### 7.2 /etc/sudoers и sudo-конфигурация 🔴 ⚠️

**Что это:** Конфигурация привилегий sudo. Определяет, какие пользователи могут выполнять какие команды с повышенными привилегиями. Злоумышленник может добавить запись `ALL=(ALL) NOPASSWD:ALL` для backdoor-пользователя.

**Расположение:**
```
/etc/sudoers                    ← основная конфигурация
/etc/sudoers.d/                 ← дополнительные конфиги
```

**На какие вопросы отвечает:**
- Есть ли NOPASSWD-записи для backdoor-пользователей?
- Кто из пользователей может получить полный sudo?
- Когда изменялись файлы sudoers (дата файла = дата компрометации)?

**Парсинг:**
```bash
sudo cat /etc/sudoers
sudo ls -la /etc/sudoers.d/
sudo cat /etc/sudoers.d/*

# Нестандартные записи NOPASSWD
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Кто может использовать sudo
grep -r "ALL=(ALL)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```

**Инструменты:** UAC · Velociraptor

---

### 7.3 SSH конфигурация и история 🔴

**Что это:** SSH-сервер — основной вектор для удалённого доступа на Linux-сервере. Конфигурация sshd определяет политику входа. `known_hosts` — история SSH-соединений хоста (lateral movement).

**Расположение:**
```
/etc/ssh/sshd_config            ← конфигурация SSH-сервера
/etc/ssh/sshd_config.d/         ← дополнительные конфиги
/etc/ssh/ssh_config             ← клиентская конфигурация

# Ключи хоста
/etc/ssh/ssh_host_*_key         ← приватные ключи хоста

# Пользовательские
~/.ssh/authorized_keys          ← авторизованные ключи (см. 1.8)
~/.ssh/known_hosts              ← куда подключались (lateral movement)
~/.ssh/config                   ← SSH-клиент конфигурация
~/.ssh/id_*                     ← приватные ключи пользователя
```

**На какие вопросы отвечает:**
- К каким хостам подключалась система по SSH (lateral movement)?
- Нестандартные настройки sshd: PermitRootLogin, PasswordAuthentication, нестандартный порт?
- Есть ли BackdoorKeysFile или другие аномальные директивы в sshd_config?

**Парсинг:**
```bash
grep -Ev "^#|^$" /etc/ssh/sshd_config

# known_hosts для всех пользователей (lateral movement)
find /root /home -name "known_hosts" -exec cat {} \; 2>/dev/null

# Ключевые настройки
grep -Ei "PermitRootLogin|PasswordAuthentication|AuthorizedKeysFile|Port|ListenAddress" \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

**Инструменты:** UAC

---

### 7.4 Sudo Log (journald / auth.log) 🔴

**Что это:** Детальный журнал sudo-сессий. На современных системах пишется в journald, дублируется в auth.log.

**На какие вопросы отвечает:**
- Какие команды выполнялись с повышением привилегий?
- Были ли попытки подбора sudo-пароля?
- Когда впервые появились sudo-сессии от нетипичного пользователя?

**Парсинг:**
```bash
# Через journald
journalctl -u sudo --no-pager | tail -200

# Через auth.log
grep "sudo" /var/log/auth.log | tail -200
grep "sudo" /var/log/secure 2>/dev/null | tail -200

# Только неудачные попытки
grep "sudo.*incorrect password\|sudo.*3 incorrect" /var/log/auth.log 2>/dev/null

# Sudo с логированием в директорию (sudo-io, редко присутствует)
sudo ls /var/log/sudo-io/ 2>/dev/null
```

**Инструменты:** UAC · easy_triage · Velociraptor

---

### 7.5 Пользователи и группы 🟡

**Что это:** `/etc/group` определяет группы и их состав. Членство в `sudo` или `wheel` = доступ к root. При компрометации злодеи могут добавить своего backdoor-пользователя в группу sudo без создания нового аккаунта — это иногда остаётся незамеченным.

**Расположение:**
```
/etc/group                      ← группы и их состав
/etc/gshadow                    ← пароли групп
/etc/login.defs                 ← параметры создания пользователей
```

**На какие вопросы отвечает:**
- Есть ли backdoor-пользователи в группах `sudo` или `wheel`?
- Какие пользователи имеют интерактивный shell и могут войти в систему?
- Когда созданы учётные записи (дата домашней директории)?

**Парсинг:**
```bash
cat /etc/group

# Члены группы sudo/wheel (кто может получить root)
grep -E "^sudo:|^wheel:" /etc/group

# Все пользователи с UID ≥ 1000
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $6, $7}' /etc/passwd

# Когда создан пользователь (через lastlog или home directory mtime)
ls -la --full-time /home/ | awk '{print $6, $7, $8, $9}'
```

**Инструменты:** UAC · Velociraptor

---

## 8. Applications

*Приложения — установленные пакеты, веб-серверы, контейнеры.*

### 8.1 Пакетные менеджеры (установленное ПО) 🟡

**Что это:** Список всех установленных пакетов — эталон для сравнения с тем, что должно быть в системе. Нелегитимные установки = инструменты злоумышленника.

**Расположение:**
```
# dpkg база — Debian/Ubuntu
/var/lib/dpkg/info/             ← информация о файлах каждого пакета
/var/lib/dpkg/status            ← статус установленных пакетов

# RPM база
/var/lib/rpm/                   ← RPM база данных
```

**На какие вопросы отвечает:**
- Какое ПО установлено и нет ли хакерских инструментов (nmap, ncat, hydra)?
- Есть ли пакеты, не соответствующие назначению сервера?
- Установлены ли бинари вне репозитория (ручная инсталляция без пакетного менеджера)?

**Парсинг:**
```bash
# Полный список установленных пакетов
dpkg -l 2>/dev/null | grep "^ii"          # deb
rpm -qa 2>/dev/null                        # rpm

# Недавно установленные (по дате)
dpkg -l --no-pager | grep "^ii" | awk '{print $2}' | \
  xargs -I {} dpkg-query -W -f='${Installed-Size}\t${Package}\t${InstallDate}\n' {} \
  2>/dev/null | sort -k3 | tail -30       # deb (упрощённо)

# dnf история установок — rpm
dnf history list 2>/dev/null
dnf history info <ID> 2>/dev/null

# Пакеты, которых быть не должно (hackertools)
dpkg -l 2>/dev/null | grep -Ei "nmap|netcat|ncat|masscan|metasploit|aircrack|hydra|john|hashcat|sqlmap|chisel|socat"
rpm -qa 2>/dev/null | grep -Ei "nmap|netcat|ncat|masscan|metasploit"
```

**Инструменты:** UAC

---

### 8.2 Веб-серверы 🟡

**Что это:** Лог веб-сервера фиксирует все HTTP-запросы. Критичен для расследований web-application attacks: SQL-инъекции, LFI, загрузка webshell, эксфильтрация через GET/POST.

**Расположение:**
```
# Apache
/var/log/apache2/access.log*    ← [deb]
/var/log/apache2/error.log*
/var/log/httpd/access_log*      ← [rpm]
/var/log/httpd/error_log*
/etc/apache2/                   ← [deb] конфигурация
/etc/httpd/                     ← [rpm] конфигурация

# Nginx
/var/log/nginx/access.log*
/var/log/nginx/error.log*
/etc/nginx/                     ← конфигурация

# Webroot (место размещения webshell'ов)
/var/www/html/
/srv/www/
/usr/share/nginx/html/
```

**На какие вопросы отвечает:**
- Какие запросы предшествовали компрометации?
- Есть ли признаки сканирования уязвимостей (404/400 массово)?
- Были ли успешные запросы к webshell'ам?
- Откуда (IP) происходили атаки?

**Парсинг:**
```bash
# Последние запросы
tail -200 /var/log/apache2/access.log
tail -200 /var/log/nginx/access.log

# Подозрительные запросы: LFI, RCE, webshell признаки
grep -Ei "\.\.\/|\.\.%2f|cmd=|exec=|system\(|passthru|eval\(|base64|/etc/passwd|select.*from|union.*select|<script|alert\(" \
  /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null

# 500 ошибки (признаки эксплуатации)
grep " 500 " /var/log/apache2/access.log | tail -50

# Поиск webshell'ов в webroot
find /var/www /srv/www /usr/share/nginx/html -name "*.php" \
  -exec grep -Eli "eval\|base64_decode\|system\|passthru\|exec\|shell_exec" {} \; 2>/dev/null
```

**Инструменты:** UAC · Velociraptor

---

### 8.3 Docker и контейнеры 🟡

**Что это:** Контейнеры — стандарт для продакшн-систем. Злодеи могут компрометировать контейнер и выбраться из него (container escape), использовать незащищённый Docker API как вектор атаки или разворачивать вредоносные контейнеры прямо на хосте.

**Расположение:**
```
/var/lib/docker/                ← данные Docker
/var/log/docker.log             ← лог Docker daemon
```

**На какие вопросы отвечает:**
- Есть ли привилегированные контейнеры (container escape vector)?
- Запущены ли нелегитимные или нестандартные образы?
- Был ли Docker daemon доступен без аутентификации (порт 2375/2376)?

**Парсинг:**
```bash
# Список всех контейнеров (включая остановленные)
docker container ps --all 2>/dev/null
docker container ls -a 2>/dev/null

# Инспекция контейнеров
docker inspect $(docker ps -aq) 2>/dev/null

# Логи каждого контейнера
for cn in $(docker ps -aq 2>/dev/null); do
  echo "=== Container: $cn ==="
  docker container logs --timestamps "$cn" 2>/dev/null | tail -50
done

# Образы (есть ли нестандартные)
docker images 2>/dev/null

# Привилегированные контейнеры (container escape vector)
docker inspect $(docker ps -aq) 2>/dev/null | \
  python3 -c "import json,sys; d=json.load(sys.stdin); \
  [print(c.get('Name'), 'PRIVILEGED!') for c in d if c.get('HostConfig',{}).get('Privileged')]"
```

**Инструменты:** easy_triage · Velociraptor

---

## 9. Security State

*Состояние защитных механизмов — фундаментальная оценка системы.*

### 9.1 Модули ядра (Kernel Modules) 🔴 ⚠️

**Что это:** Модули ядра (`.ko` файлы) — код, выполняемый в пространстве ядра с максимальными привилегиями. Руткиты реализуются как нелегитимные модули ядра, обеспечивая сокрытие процессов, файлов и сетевых соединений. `tainted` kernel — признак загрузки неподписанного или проблемного модуля.

**На какие вопросы отвечает:**
- Есть ли нестандартные (не из пакетов) загруженные модули ядра?
- Загружен ли известный руткит?
- Является ли ядро tainted (загрязнённым)?

**Парсинг:**
```bash
# Все загруженные модули
lsmod
cat /proc/modules

# Код загрязнения ядра
cat /proc/sys/kernel/tainted
# 0 = нормально; значения: https://kernel.org/doc/html/latest/admin-guide/tainted-kernels.html

# Таблица символов (признаки руткита: модуль без имени или подозрительные символы)
cat /proc/kallsyms | grep -v " [tTwW] " | head -50

# Нестандартные модули (не из пакетного менеджера)
for mod in $(lsmod | awk 'NR>1 {print $1}'); do
  modinfo "$mod" 2>/dev/null | grep -q "filename:" && \
    modfile=$(modinfo "$mod" | grep "filename:" | awk '{print $2}') && \
    dpkg -S "$modfile" > /dev/null 2>&1 || echo "NOT IN PACKAGES: $mod ($modfile)"
done 2>/dev/null
```

**Инструменты:** easy_triage · UAC

---

### 9.2 Скрытые процессы (Rootkit Detection) 🔴 ⚠️

**Что это:** Руткиты скрывают процессы от стандартных инструментов (ps, top) путём перехвата syscall'ов или монтирования поверх `/proc/<PID>` (overmount). Детектирование: сравнение PID-пространства из `/proc` с выводом ps. Есть много других методов, о них в другом разделе, здесь информация для примера.

**На какие вопросы отвечает:**
- Есть ли PID в `/proc`, которые не видит `ps` (overmount руткит)?
- Есть ли пропуски в PID-пространстве, указывающие на скрытые процессы?

**Парсинг:**
```bash
# Сравнение списка PID из /proc с выводом ps
ps_pids=$(ps -e -o pid= | sort -n)
proc_pids=$(ls /proc | grep -E '^[0-9]+$' | sort -n)

# PID видимые в /proc, но отсутствующие в ps (скрытые процессы)
comm -23 <(echo "$proc_pids") <(echo "$ps_pids")

# Обнаружение overmount /proc/<PID> (easy_triage method)
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  if [ -d "/proc/$pid" ]; then
    # Если /proc/<pid> смонтирован поверх — filesystem будет отличаться
    mount | grep -q "/proc/$pid " && echo "OVERMOUNTED: /proc/$pid"
  fi
done

# rkhunter (если установлен)
rkhunter --check --skip-keypress 2>/dev/null | grep -E "Warning|Found"

# chkrootkit (если установлен)
chkrootkit 2>/dev/null | grep -v "not infected\|not found\|nothing found"
```

**Инструменты:** easy_triage · rkhunter · chkrootkit

---

### 9.3 AppArmor / SELinux 🟡

**Что это:** Системы мандатного управления доступом (MAC — Mandatory Access Control). **AppArmor** (Ubuntu/Debian) ограничивает приложения набором профилей. **SELinux** (RHEL/Fedora) — более мощная политика с метками безопасности. Отключённый или переведённый в режим `permissive` MAC — признак попытки обхода защиты.

**Расположение:**
```
/etc/apparmor.d/                <- [deb] профили AppArmor
/etc/selinux/config             <- [rpm] конфигурация SELinux
/var/log/audit/audit.log        <- отказы SELinux (AVC)
```

**На какие вопросы отвечает:**
- Включён ли MAC (ожидается: AppArmor enabled / SELinux Enforcing)?
- Есть ли DENIED-события, указывающие на попытки обхода политики?
- Переведён ли режим в `permissive` или `disabled` — признак намеренного ослабления защиты?

**Парсинг:**
```bash
# AppArmor
aa-status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
# Ожидаемый результат: Y (enabled)
journalctl | grep -i "apparmor\|DENIED" | tail -50

# SELinux
getenforce 2>/dev/null
sestatus 2>/dev/null
# Ожидаемый результат: Enforcing
# ALERT: Permissive или Disabled = обход защиты
cat /etc/selinux/config | grep SELINUX=
ausearch -m AVC,USER_AVC -ts today 2>/dev/null | head -50   # отказы SELinux
```

**Инструменты:** UAC · Velociraptor

---

### 9.4 Сертификаты и CA 🟡

**Что это:** Нелегитимный корневой сертификат в системном хранилище — и curl, wget, браузер больше не ругаются на MITM. Тихий, но эффективный способ перехвата трафика, особенно в корпоративных атаках.

**Расположение:**
```
/etc/ssl/certs/                         ← [deb] системные сертификаты
/usr/share/ca-certificates/            ← добавленные CA
/etc/pki/ca-trust/                     ← [rpm]
/usr/local/share/ca-certificates/      ← локально добавленные (нестандартные)
```

**На какие вопросы отвечает:**
- Есть ли нелегитимные корневые сертификаты в системном хранилище?
- Когда добавлен сертификат (дата файла)?
- Какой CA издал сертификат — легитимный ли это центр сертификации?

**Парсинг:**
```bash
# Список всех доверенных CA
ls -la /usr/local/share/ca-certificates/   # нестандартные — здесь быть не должно

# Проверить через openssl
find /etc/ssl/certs /usr/share/ca-certificates -name "*.crt" -o -name "*.pem" | \
  xargs -I {} sh -c 'echo "=== {} ===" && openssl x509 -noout -subject -issuer -dates -in {} 2>/dev/null'
```

**Инструменты:** UAC

---

## 10. Memory & Volatile

### 10.1 RAM-дамп ⏱️ 🟡 ⚠️

**Что это:** Снапшот оперативной памяти. Содержит: запущенные процессы (включая скрытые руткитами), ключи шифрования, fileless malware, инжектированный shellcode, сетевые артефакты, credentials в памяти.

**Инструменты сбора:**

| Инструмент | Метод | Особенности |
|-----------|-------|------------|
| **AVML** (Microsoft) | LiME-совместимый | Не требует компиляции, один статический бинарь |
| **LiME** | Kernel module | Требует компиляции под конкретную версию ядра, точнее |
| **dd** | Block device | Ненадёжно, пропускает memory gaps |

**На какие вопросы отвечает:**
- Есть ли fileless malware или инжектированный shellcode в памяти?
- Какие процессы скрыты руткитом (невидимы в `ps`, но есть в памяти)?
- Есть ли credentials (пароли, ключи шифрования) в открытом виде?
- Модифицированы ли syscall'ы (признак kernel rootkit)?

---

**⚠️ Нюанс: символы ядра и Volatility**

Volatility 3 для анализа Linux-дампов использует **ISF-файлы** (Intermediate Symbol Format) — JSON-таблицы символов, описывающие структуры ядра конкретной версии. Без ISF большинство плагинов (`linux.pslist`, `linux.netstat` и др.) просто не запустятся — Volatility не знает, как читать структуры `task_struct`, `mm_struct` и других объектов ядра.

ISF уникален для каждой тройки: **версия ядра + дистрибутив + конфигурация сборки**. Ядро `5.15.0-91-generic` (Ubuntu 22.04) и `5.15.0-91-generic` (Mint) — разные ISF, несмотря на одинаковый номер.

**Что брать с системы при сборе RAM:**

```bash
# Версия ядра (нужна для поиска/генерации ISF)
uname -r
uname -a

# System.map — таблица символов ядра (главный источник для ISF)
ls -la /boot/System.map-$(uname -r)
cp /boot/System.map-$(uname -r) /output/System.map

# /proc/kallsyms — аналог System.map, доступен на живой системе
# Содержит символы загруженных модулей, которых нет в System.map
sudo cat /proc/kallsyms > /output/kallsyms.txt

# Образ ядра (vmlinuz) — нужен для dwarf2json при генерации ISF из debug-info
cp /boot/vmlinuz-$(uname -r) /output/vmlinuz

# Debug-info пакет — если установлен, содержит DWARF-отладочную информацию
# deb:
dpkg -l | grep "linux-image.*dbg\|linux-modules-extra"
find /usr/lib/debug/ -name "vmlinux-$(uname -r)" 2>/dev/null

# rpm:
rpm -qa | grep "kernel-debuginfo"
find /usr/lib/debug/ -name "vmlinux" 2>/dev/null

# Конфигурация ядра (влияет на структуры данных)
cp /boot/config-$(uname -r) /output/kernel.config 2>/dev/null || \
  zcat /proc/config.gz > /output/kernel.config 2>/dev/null
```

**Получение ISF: три пути**

```bash
# Путь 1 — Готовые ISF от сообщества (быстро, если повезёт с версией)
# https://isf-server.code16.fr/ — большая коллекция готовых ISF
# Кладём в: volatility3/symbols/linux/<имя>.json.xz
# Готовые профили символов также здесь: https://github.com/Abyss-W4tcher/volatility3-symbols
#

# Путь 2 — Генерация из DWARF debug-info (нужен debug-пакет ядра)
# https://github.com/volatilityfoundation/dwarf2json

# deb: установить debug-info
sudo apt install linux-image-$(uname -r)-dbg    # Ubuntu/Debian

# Найти vmlinux с DWARF
find /usr/lib/debug -name "vmlinux-$(uname -r)" -o -name "vmlinux"

# Сгенерировать ISF
./dwarf2json linux \
  --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
  --system-map /boot/System.map-$(uname -r) \
  > /output/$(uname -r).json

# Положить ISF в Volatility
cp /output/$(uname -r).json ~/volatility3/volatility3/symbols/linux/

# Путь 3 — Из /proc/kallsyms (наименее точный, без структур, только символы)
# Подходит только для базовых плагинов типа banners.Banners
```

**Парсинг:**
```bash
# Сбор RAM через AVML (рекомендуется — один статический бинарь)
# https://github.com/microsoft/avml
sudo ./avml /output/memory.lime

# Сбор через LiME (kernel module, если AVML недоступен)
sudo insmod lime.ko "path=/output/memory.lime format=lime"

# Проверить, что ISF подхватился
python3 vol.py -f memory.lime banners.Banners

# Анализ через Volatility 3 (требует ISF)
python3 vol.py -f memory.lime linux.pslist              # список процессов
python3 vol.py -f memory.lime linux.pstree              # дерево процессов
python3 vol.py -f memory.lime linux.netstat             # сетевые соединения
python3 vol.py -f memory.lime linux.malfind             # подозрительные регионы памяти
python3 vol.py -f memory.lime linux.bash                # bash history из памяти
python3 vol.py -f memory.lime linux.lsmod               # модули ядра из памяти
python3 vol.py -f memory.lime linux.hidden_modules      # скрытые модули (руткит-детект)
python3 vol.py -f memory.lime linux.check_syscall       # модифицированные syscall'ы

# Поиск строк в сыром дампе (без ISF, если символы недоступны)
strings memory.lime | grep -Ei "password|passwd|Authorization|token|BEGIN.*KEY"
```

**Инструменты:** AVML · LiME · Volatility 3 · dwarf2json · [isf-server](https://isf-server.code16.fr/)

---

### 10.2 Crash Dumps 🟢

**Что это:** Дампы ядра при крахе системы (kernel panic) или краши приложений (core dumps). Аномальные краши = признак нестабильных эксплойтов или ошибок в шеллкоде.

**На какие вопросы отвечает:**
- Были ли краши подозрительных или неизвестных процессов?
- Есть ли серийные краши одного процесса (нестабильный эксплойт)?
- Совпадает ли время краша с началом инцидента?

**Расположение:**
```
/var/crash/                     ← [deb] kernel crash dumps
/var/lib/systemd/coredump/      ← systemd core dumps
/var/core/                      ← альтернативный путь
```

**Парсинг:**
```bash
# Недавние краши (последние 60 дней)
find /var/crash/ /var/lib/systemd/coredump/ -type f -mtime -60 -ls 2>/dev/null

# systemd coredump info
coredumpctl list 2>/dev/null
coredumpctl info --no-pager 2>/dev/null | head -100
```

**Инструменты:** UAC

---

## 11. External Devices

### 11.1 USB и внешние устройства 🟡

**Что это:** История подключения USB-устройств. В отличие от Windows (реестр) и macOS, Linux не хранит персистентной базы USB-устройств. Информация доступна из logов ядра (dmesg/journal) и udev-событий.

**Расположение:**
```
/var/log/kern.log               ← события USB в kernel log
/run/udev/                      ← runtime udev данные
/etc/udev/rules.d/              ← правила udev (злоумышленники могут добавить автозапуск)
```

**На какие вопросы отвечает:**
- Какие USB-устройства подключались к системе и когда?
- Были ли подключения в нетипичное время?
- Есть ли нестандартные udev-правила, запускающие команды при подключении устройства?

**Парсинг:**
```bash
# USB-события из dmesg (kernel buffer)
dmesg | grep -i "usb\|mass storage\|scsi"

# USB-события из journal
journalctl -k | grep -i "usb\|mass storage" | tail -100

# Из kernel log
grep -i "usb\|mass storage" /var/log/kern.log | tail -100

# Устройства, подключённые прямо сейчас
lsusb
lsblk

# udev-правила (автозапуск при подключении = подозрительно)
grep -rEi "RUN|EXEC" /etc/udev/rules.d/ 2>/dev/null
```

**Инструменты:** UAC

---

### 11.2 Примонтированные устройства 🟡

**Что это:** История монтирования файловых систем. `/etc/fstab` — постоянные точки монтирования; `/proc/mounts` — текущее состояние.

**Расположение:**
```
/etc/fstab                      ← постоянные точки монтирования
/proc/mounts                    ← текущие монтирования
/var/log/kern.log               ← события монтирования
```

**На какие вопросы отвечает:**
- Есть ли нестандартные NFS/CIFS-монтирования (потенциальная эксфильтрация или C2)?
- Монтируются ли внешние диски автоматически?
- Есть ли записи в fstab, добавленные злоумышленником?

**Парсинг:**
```bash
cat /proc/mounts
cat /etc/fstab
mount | grep -v "cgroup\|proc\|sysfs\|devtmpfs"

# Нестандартные NFS/CIFS монтирования (потенциальная эксфильтрация или C2)
mount | grep -Ei "nfs|cifs|smb|sshfs"
```

**Инструменты:** UAC · easy_triage

---

## Приложение 1: Порядок сбора

*Собирай от наиболее волатильных к наименее.*

| Приоритет | Артефакт | Причина волатильности |
|:---------:|----------|-----------------------|
| 1 | Живые процессы, сетевые соединения | Исчезают при завершении процесса |
| 2 | `/proc/<PID>/` (environ, maps, fd) | Пропадает вместе с процессом |
| 3 | DNS-кэш (resolvectl) | Сбрасывается при перезагрузке/рестарте |
| 4 | ARP-таблица, таблица маршрутизации | Сбрасываются при перезагрузке |
| 5 | `/dev/shm/` содержимое | Очищается при перезагрузке |
| 6 | RAM-дамп | Полностью теряется при выключении |
| 7 | `/var/run/utmp` | Текущие сессии, очищается при ребуте |
| 8 | Journald volatile (`/run/log/journal/`) | Очищается при перезагрузке |
| 9 | Journald persistent (`/var/log/journal/`) | Ротация, старые данные перезаписываются |
| 10 | Auth.log, syslog | Ротация (7-30 дней по умолчанию) |
| 11 | Cron logs | Ротация |
| 12 | Shell history | Записывается при закрытии сессии |
| 13 | Package manager logs | Ротация, но дольше хранятся |
| 14 | Systemd units, cron files | Персистентны, меняются при установке |
| 15 | Auditd logs | Конфигурируемая ротация |
| 16 | Bodyfile / MACB timestamps | Изменяются при доступе к файлам |
| 17 | /etc/passwd, /etc/shadow | Практически не меняются |
| 18 | SSH authorized_keys | Персистентны |

---

## Приложение 2: Быстрый IR-скрипт

*Минимальный скрипт для первичного сбора на живой системе. Запускать с правами root.*

```bash
#!/bin/bash
# Linux Minimal IR Collection Script
# Запускать: sudo bash ir_collect.sh

OUTPUT="/tmp/ir_$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT"

echo "[*] 1. Volatile: processes & network..."
ps auxww > "$OUTPUT/processes.txt"
ps -deaf > "$OUTPUT/processes_tree.txt"
sudo lsof -i -n -P > "$OUTPUT/network_connections.txt" 2>/dev/null
ss -anp > "$OUTPUT/ss_connections.txt"
netstat -anp > "$OUTPUT/netstat.txt" 2>/dev/null
arp -a -n > "$OUTPUT/arp.txt"
ip route show > "$OUTPUT/routes.txt"
sudo lsof -nPl > "$OUTPUT/lsof_full.txt" 2>/dev/null
sudo lsof -n | grep "(deleted)" > "$OUTPUT/lsof_deleted.txt" 2>/dev/null

echo "[*] 2. /proc snapshot..."
find /proc -maxdepth 2 -name 'exe' -exec ls -l --full-time {} \; \
  2>/dev/null > "$OUTPUT/proc_all_exe.txt"
find /proc -maxdepth 2 -name 'cmdline' -exec strings -n 1 --print-file-name {} \; \
  2>/dev/null > "$OUTPUT/proc_all_cmdline.txt"
find /proc -maxdepth 2 -name 'environ' -type f \
  -exec grep -Fl 'LD_PRELOAD=' {} \; 2>/dev/null > "$OUTPUT/proc_ld_preload.txt"
cat /proc/modules > "$OUTPUT/kernel_modules.txt"
cat /proc/sys/kernel/tainted > "$OUTPUT/kernel_tainted.txt"
cat /proc/net/tcp > "$OUTPUT/proc_net_tcp.txt"

echo "[*] 3. Volatile directories..."
cp -r /dev/shm/ "$OUTPUT/dev_shm/" 2>/dev/null
ls -latR /tmp/ > "$OUTPUT/tmp_listing.txt" 2>/dev/null
ls -latR /var/tmp/ >> "$OUTPUT/tmp_listing.txt" 2>/dev/null
find /tmp /var/tmp /dev/shm -type f -perm /111 \
  -exec sha256sum {} \; 2>/dev/null > "$OUTPUT/suspicious_executables.txt"

echo "[*] 4. Security state..."
csrutil status 2>/dev/null || echo "not macOS" > /dev/null
cat /proc/sys/kernel/tainted >> "$OUTPUT/kernel_tainted.txt"
lsmod > "$OUTPUT/lsmod.txt"
aa-status > "$OUTPUT/apparmor_status.txt" 2>/dev/null
getenforce > "$OUTPUT/selinux_status.txt" 2>/dev/null
cat /etc/ld.so.preload > "$OUTPUT/ld_so_preload.txt" 2>/dev/null

echo "[*] 5. Persistence..."
systemctl list-unit-files --state=enabled > "$OUTPUT/systemd_enabled.txt" 2>/dev/null
cp -r /etc/systemd/system/ "$OUTPUT/systemd_etc_system/" 2>/dev/null
cp -r /etc/cron.d/ "$OUTPUT/cron_d/" 2>/dev/null
crontab -l > "$OUTPUT/crontab_root.txt" 2>/dev/null
cp /etc/crontab "$OUTPUT/etc_crontab.txt" 2>/dev/null
for user in $(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd); do
  crontab -u "$user" -l > "$OUTPUT/crontab_${user}.txt" 2>/dev/null
done
cat /etc/rc.local > "$OUTPUT/rc_local.txt" 2>/dev/null
cat /etc/ld.so.preload >> "$OUTPUT/ld_so_preload.txt" 2>/dev/null

echo "[*] 6. Authentication & users..."
cat /etc/passwd > "$OUTPUT/passwd.txt"
cat /etc/group > "$OUTPUT/group.txt"
cat /etc/sudoers > "$OUTPUT/sudoers.txt" 2>/dev/null
grep -v "^#|^$" /etc/ssh/sshd_config > "$OUTPUT/sshd_config.txt" 2>/dev/null
find /root /home -name "authorized_keys" \
  -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null > "$OUTPUT/authorized_keys.txt"
find /root /home -name "known_hosts" \
  -exec cat {} \; 2>/dev/null > "$OUTPUT/known_hosts.txt"
cp --sparse=always /var/log/lastlog "$OUTPUT/lastlog" 2>/dev/null
cp /var/run/utmp "$OUTPUT/utmp" 2>/dev/null
last -w -f /var/log/wtmp > "$OUTPUT/wtmp.txt" 2>/dev/null
lastb -f /var/log/btmp > "$OUTPUT/btmp.txt" 2>/dev/null

echo "[*] 7. Shell history..."
for dir in /root /home/*; do
  user=$(basename "$dir")
  cat "$dir/.bash_history" > "$OUTPUT/history_bash_${user}.txt" 2>/dev/null
  cat "$dir/.zsh_history" > "$OUTPUT/history_zsh_${user}.txt" 2>/dev/null
  cat "$dir/.viminfo" > "$OUTPUT/viminfo_${user}.txt" 2>/dev/null
done

echo "[*] 8. Network config..."
ip addr > "$OUTPUT/ip_addr.txt"
ip route > "$OUTPUT/ip_route.txt"
cat /etc/hosts > "$OUTPUT/hosts.txt"
cat /etc/resolv.conf > "$OUTPUT/resolv_conf.txt"
iptables -L -v -n > "$OUTPUT/iptables.txt" 2>/dev/null

echo "[*] 9. Logs (copy)..."
mkdir -p "$OUTPUT/logs"
cp -r /var/log/auth* /var/log/secure* "$OUTPUT/logs/" 2>/dev/null
cp /var/log/wtmp /var/log/btmp "$OUTPUT/logs/" 2>/dev/null
cp -r /var/log/audit/ "$OUTPUT/logs/audit/" 2>/dev/null
cp /var/log/syslog* /var/log/messages* "$OUTPUT/logs/" 2>/dev/null
cp /var/log/dpkg.log* "$OUTPUT/logs/" 2>/dev/null
cp /var/log/dnf.log* "$OUTPUT/logs/" 2>/dev/null

echo "[*] 10. SUID/SGID & capabilities..."
find / -xdev -type f -perm -u+s 2>/dev/null > "$OUTPUT/suid_files.txt"
find / -xdev -type f -perm -g+s 2>/dev/null >> "$OUTPUT/suid_files.txt"
getcap -r / 2>/dev/null > "$OUTPUT/capabilities.txt"

echo "[*] 11. System info..."
uname -a > "$OUTPUT/uname.txt"
cat /etc/os-release > "$OUTPUT/os_release.txt"
uptime > "$OUTPUT/uptime.txt"
w > "$OUTPUT/who_is_logged.txt"
lsblk > "$OUTPUT/lsblk.txt"
lsusb > "$OUTPUT/lsusb.txt" 2>/dev/null

echo "[+] Done. Output: $OUTPUT"
echo "[+] Size: $(du -sh "$OUTPUT" | awk '{print $1}')"
echo "[!] Copy to safe media: tar czf ${OUTPUT}.tgz -C $(dirname $OUTPUT) $(basename $OUTPUT)"
```

---

## Приложение 3: Инструменты

| Инструмент | Тип | Назначение | Особенности |
|------------|-----|-----------|-------------|
| [**UAC**](https://github.com/tclahr/uac) | Сборщик | Универсальный сборщик, любой Unix/Linux | Без зависимостей, YAML-профили, S3/Azure |
| [**easy_triage**](https://github.com/msuhanov/easy_triage) | Сборщик | Углублённый триаж Linux, фокус на безопасности | PAM-хэши, LD_PRELOAD, rootkit detection, SUID/capabilities |
| [**Velociraptor**](https://velociraptor.app) | Агент + сборщик | Масштабируемый сбор на флоте | VQL-запросы, web UI, агент |
| [**AVML**](https://github.com/microsoft/avml) | Дамп памяти | RAM dump для Linux | Microsoft, один статический бинарь, no install |
| [**LiME**](https://github.com/504ensicsLabs/LiME) | Дамп памяти | Linux Memory Extractor (kernel module) | Максимальная точность, требует компиляции |
| [**Volatility 3**](https://volatilityfoundation.org) | Анализ памяти | RAM-дамп Linux | Плагины linux.pslist, linux.netstat, linux.malfind, linux.check_syscall |
| [**The Sleuth Kit**](https://sleuthkit.org) | Анализ ФС | Bodyfile, file system timeline | `fls`, `mactime` — стандарт |
| [**Plaso**](https://plaso.readthedocs.io) | Суперtimeline | Суперtimeline из всех артефактов | `--parsers linux`, интеграция с Timesketch |
| [**Timeline Explorer**](https://ericzimmerman.github.io) | Визуализация | Анализ CSV timeline | Eric Zimmerman |
| [**rkhunter**](https://rkhunter.sourceforge.net) | Детектор руткитов | Проверка целостности системы | Сигнатурная + эвристическая проверка |
| [**chkrootkit**](https://www.chkrootkit.org) | Детектор руткитов | Проверка признаков руткитов | Классический инструмент |
| [**aureport / ausearch**](https://linux.die.net/man/8/aureport) | Анализ auditd | Парсинг и отчёты auditd | Встроены в пакет auditd |

---

## Приложение 4: Ссылки

- [ForensicArtifacts: linux.yaml](https://github.com/ForensicArtifacts/artifacts/blob/main/artifacts/data/linux.yaml) — стандартный каталог Linux артефактов
- [easy_triage — msuhanov](https://github.com/msuhanov/easy_triage) — эталонный IR-скрипт с богатыми эвристиками
- [UAC Documentation](https://tclahr.github.io/uac-docs/) — документация Universal Artifacts Collector
- [Velociraptor Linux Artifacts](https://docs.velociraptor.app/exchange/artifacts/) — готовые VQL артефакты
- [Group-IB: Linux Process Manipulation](https://www.group-ib.com/blog/linux-pro-manipulation/) — /proc манипуляции малвари
- [Linux Forensics Targets (Velociraptor)](https://docs.velociraptor.app/exchange/artifacts/pages/linux.forensics.targets/) — полный список путей из ForensicArtifacts
- [SANS FOR577: Linux Threat Hunting](https://www.sans.org/cyber-security-courses/linux-threat-hunting-and-incident-response/)
- [FHS Standard](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html) — Filesystem Hierarchy Standard
- [Volatility 3 Linux Plugins](https://volatility3.readthedocs.io) — плагины для анализа Linux RAM
- [Tainted Kernel codes](https://kernel.org/doc/html/latest/admin-guide/tainted-kernels.html) — расшифровка кодов kernel taint

---

## Приложение 5: Покрытие артефактов по инструментам

**Обозначения:**
- ✅ — собирает / поддерживает
- ⚠️ — частично (ограничения)
- ❌ — не собирает

---

### 1. Persistence

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 1.1 Systemd units | ✅ | ✅ | ✅ | VR: `Linux.Sys.Services` |
| 1.2 SysVInit / rc.local | ✅ | ✅ | ⚠️ | easy_triage: cp init.d |
| 1.3 Cron / Anacron | ✅ | ✅ | ✅ | VR: `Linux.Persistence.Cron` |
| 1.4 At Jobs | ✅ | ❌ | ❌ | Только UAC |
| 1.5 Shell profile / bashrc | ✅ | ✅ | ⚠️ | easy_triage: /etc/profile, bashrc |
| 1.6 LD_PRELOAD / ld.so.preload | ⚠️ | ✅ | ❌ | easy_triage: ключевая фича |
| 1.7 PAM modules | ❌ | ✅ | ❌ | easy_triage: PAM hashes — уникальная фича |
| 1.8 SSH authorized_keys | ✅ | ❌ | ✅ | VR: `Linux.Sys.SSHAuthorizedKeys` |
| 1.9 MOTD hooks | ❌ | ❌ | ❌ | Ни один |
| 1.10 /etc/environment, environment.d | ✅ | ⚠️ | ❌ | easy_triage: только /etc/environment |

---

### 2. Process

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 2.1 /proc filesystem | ✅ | ✅ | ✅ | easy_triage: exe, cmdline, comm, environ |
| 2.2 Список живых процессов | ✅ | ✅ | ✅ | VR: `Linux.Memory.Maps` |
| 2.3 Хэши исполняемых файлов | ✅ | ✅ | ✅ | easy_triage: file sigs |
| 2.4 lsof / открытые дескрипторы | ✅ | ❌ | ✅ | VR: `Linux.Sys.OpenFiles` |

---

### 3. Network

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 3.1 Активные соединения | ✅ | ✅ | ✅ | VR: `Linux.Network.Netstat` |
| 3.2 ARP-кэш | ✅ | ✅ | ❌ | |
| 3.3 Таблица маршрутизации | ✅ | ✅ | ❌ | |
| 3.4 DNS-кэш | ✅ | ✅ | ❌ | easy_triage: pkill -USR1 systemd-resolve |
| 3.5 /etc/hosts, resolv.conf | ✅ | ✅ | ✅ | |
| 3.6 Netfilter / iptables | ✅ | ❌ | ❌ | Только UAC |

---

### 4. File System

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 4.1 Bodyfile (MACB timestamps) | ✅ | ✅ | ⚠️ | easy_triage: timeline.csv |
| 4.2 /tmp, /var/tmp, /dev/shm | ✅ | ✅ | ✅ | easy_triage: копирует /dev/shm |
| 4.3 SUID/SGID файлы | ⚠️ | ✅ | ✅ | easy_triage: file_suid_sgid.txt |
| 4.4 Linux Capabilities | ❌ | ✅ | ✅ | easy_triage: file_caps.txt |
| 4.5 Скрытые файлы | ✅ | ❌ | ⚠️ | |
| 4.6 World-writable files | ✅ | ❌ | ❌ | Только UAC |

---

### 5. User Activity

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 5.1 Shell history (bash, zsh, fish) | ✅ | ✅ | ✅ | easy_triage: regex-фильтрация |
| 5.2 Vim/редакторы (viminfo) | ✅ | ❌ | ❌ | Только UAC |
| 5.3 DB history (psql, mysql) | ✅ | ❌ | ❌ | Только UAC |

---

### 6. System Logs

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 6.1 auth.log / secure | ✅ | ✅ | ✅ | |
| 6.1 wtmp / btmp / lastlog | ✅ | ✅ | ✅ | easy_triage: lastlog cp --sparse=always |
| 6.2 Systemd Journal | ✅ | ✅ | ✅ | easy_triage: strings из journal |
| 6.3 Syslog / messages | ✅ | ✅ | ✅ | |
| 6.4 Kernel log / dmesg | ✅ | ✅ | ✅ | |
| 6.5 Auditd | ✅ | ✅ | ✅ | |
| 6.6 Package manager logs | ✅ | ✅ | ❌ | |
| 6.7 Cron logs | ✅ | ✅ | ❌ | |
| 6.8 Boot log | ✅ | ❌ | ❌ | Только UAC |
| 6.9 Process accounting (pacct) | ⚠️ | ❌ | ❌ | UAC: если файл существует; по умолчанию выключен |

---

### 7. Authentication

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 7.1 /etc/passwd, /etc/shadow | ✅ | ✅ | ✅ | VR: `Linux.Sys.Users` |
| 7.2 sudoers | ✅ | ✅ | ❌ | |
| 7.3 SSH конфигурация / ключи | ✅ | ❌ | ✅ | VR: `Linux.Sys.SSHAuthorizedKeys` |
| 7.4 Sudo logs | ✅ | ❌ | ✅ | Через auth.log / journal |
| 7.5 /etc/group | ✅ | ❌ | ✅ | |

---

### 8. Applications

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 8.1 Пакетный менеджер (dpkg/rpm) | ✅ | ❌ | ✅ | VR: `Linux.Sys.Packages` |
| 8.2 Веб-серверы (Apache/Nginx) | ✅ | ❌ | ✅ | |
| 8.3 Docker / контейнеры | ❌ | ✅ | ✅ | easy_triage: logs docker |

---

### 9. Security State

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 9.1 Kernel modules | ✅ | ✅ | ✅ | easy_triage: kallsyms, tainted |
| 9.2 Rootkit detection | ❌ | ✅ | ❌ | easy_triage: уникальная фича (omproc, hidden PIDs) |
| 9.3 AppArmor / SELinux | ✅ | ❌ | ✅ | |
| 9.4 Сертификаты | ✅ | ❌ | ❌ | Только UAC |

---

### 10. Memory & Volatile

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 10.1 RAM-дамп | ❌ | ❌ | ❌ | Требует AVML или LiME |
| 10.2 Crash dumps | ❌ | ✅ | ❌ | easy_triage: recent_crash_dumps |

---

### 11. External Devices

| Артефакт | UAC | easy_triage | Velociraptor | Примечания |
|---|:---:|:---:|:---:|---|
| 11.1 USB (kernel log) | ✅ | ❌ | ⚠️ | |
| 11.2 Mounted devices | ✅ | ✅ | ✅ | easy_triage: /proc/mounts |

---

### Сводка по инструментам

| | UAC | easy_triage | Velociraptor |
|---|---|---|---|
| **Тип** | Bash-сборщик | Bash IR-скрипт | Агентный DFIR-фреймворк |
| **Платформа** | Linux, macOS, \*BSD, ESXi и др. | Linux (only) | Windows, Linux, macOS |
| **Режим работы** | Live + офлайн-анализ | Live (CLI) | Агент (live) + offline collector |
| **Сильные стороны** | Максимальный охват, без зависимостей, S3/SFTP | LD_PRELOAD детект, PAM hashes, rootkit-эвристики, Docker, file signatures | VQL-гибкость, fleet-операции, готовые артефакты |
| **Слепые пятна** | Нет PAM-хэшей, нет rootkit-детектирования | Нет Bodyfile, нет At jobs, не масштабируется на флот | Нет PCAP, нет rootkit-детектирования через omproc |
| **Уникальные артефакты** | Bodyfile, world-writable, AT-jobs, cert store | PAM module hashes, LD_PRELOAD per-process, hidden PID detection (rootkit), Docker logs | Packages list, SSHAuthorizedKeys, web server analysis |
| **Деплой** | Скрипт без зависимостей | Скрипт без зависимостей | Агент / offline collector |
