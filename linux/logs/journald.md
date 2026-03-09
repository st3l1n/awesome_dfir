# Systemd Journal (journald)

## Что это
Бинарная система логирования, встроенная в systemd. Пишет логи от всех служб, ядра и системных компонентов в структурированный бинарный формат. Является заменой (и дополнением) syslog на современных системах. `journalctl` — инструмент просмотра. **Важная особенность:** journal хранит больше метаданных, чем syslog (PID, UID, GID, systemd unit). По нему гораздо удобнее выстраивать общий таймлайн действий.

## Пути
```
/var/log/journal/               ← persistent journal (если включён)
/run/log/journal/               ← volatile journal (очищается при перезагрузке)
/run/journal/                   ← альтернативный volatile путь
```

## На какие вопросы отвечает
- Что делали все службы системы в любой момент времени?
- Какие ошибки и краши происходили?
- Какие process/service запускались и завершались?

## Парсинг
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

## Инструменты
- UAC
- easy_triage
- Velociraptor (`Linux.Logs.Journald`)