# Awesome DFIR

> Справочник по сбору и анализу артефактов для специалистов по цифровой криминалистике и реагированию на инциденты (DFIR).

[![GitHub stars](https://img.shields.io/github/stars/st3l1n/awesome_dfir?style=flat-square)](https://github.com/st3l1n/awesome_dfir/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/st3l1n/awesome_dfir?style=flat-square)](https://github.com/st3l1n/awesome_dfir/network)
[![GitHub issues](https://img.shields.io/github/issues/st3l1n/awesome_dfir?style=flat-square)](https://github.com/st3l1n/awesome_dfir/issues)
[![GitHub contributors](https://img.shields.io/github/contributors/st3l1n/awesome_dfir?style=flat-square)](https://github.com/st3l1n/awesome_dfir/graphs/contributors)
[![Last commit](https://img.shields.io/github/last-commit/st3l1n/awesome_dfir?style=flat-square)](https://github.com/st3l1n/awesome_dfir/commits/main)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey?style=flat-square)](LICENSE)

---

## О проекте

**Awesome DFIR** — практический справочник для специалистов по цифровой криминалистике и реагированию на инциденты. Охватывает методы сбора артефактов, команды анализа и инструменты для основных операционных систем. Мы ориентируемся на специфику России и СНГ, но с радостью вберем международный опыт.

Документы строятся вокруг реальных сценариев расследований: от сбора runtime информации на живой системе до анализа образа диска. Каждый раздел содержит:

- **Что это** — описание артефакта и его криминалистической ценности
- **Пути** — местонахождение файлов, разделов реестра, ключей конфигурации
- **На какие вопросы отвечает** — что можно установить по артефакту
- **Обработка** — команды и скрипты для сбора и анализа
- **Инструменты** — рекомендуемые forensic-инструменты (Пока в очень местах TODO)

---

## Платформы

| Платформа | Статус | Справочник | Индекс артефактов | Версия |
|-----------|--------|------------|-------------------|--------|
| Windows | ✅ Готово | [windows/windows.md](windows/windows.md) | [windows/README.md](windows/README.md) | 1.1 |
| Linux | ✅ Готово | [linux/linux.md](linux/linux.md) | [linux/README.md](linux/README.md) | 1.1 |
| macOS | ✅ Готово | [macos/mac.md](macos/mac.md) | [macos/README.md](macos/README.md) | 2.1 |
| Cloud | 🔜 Скоро | — | — | — |
| Containers | 🔜 Скоро | — | — | — |
| Kubernetes | 🔜 Скоро | — | — | — |
| Network | 🔜 Скоро | — | — | — |

---

## Легенда иконок

Во всех документах используется единая система обозначений.

### Приоритет сбора

| Иконка | Значение |
|--------|----------|
| 🔴 | Критичный приоритет — собирать в первую очередь |
| 🟡 | Важный — стандартный IR |
| 🟢 | Дополнительный — при детальном расследовании |

### Характеристики артефакта

| Иконка | Значение |
|--------|----------|
| ⚠️ | Требует повышенных привилегий |
| ⏱️ | Волатильный — исчезает после перезагрузки |
| 🔄 | Ротируется — может быть перезаписан |
| 🔐 | Может быть зашифрован |

---

## Как использовать

### Dive in

В каждом разделе есть файл монолит, например windows/windows.md. Можно пойти туда и использовать эту информацию сразу скопом.

### Изучение конкретного артефакта

Используйте содержание в начале каждого документа для навигации. Каждый раздел независим — можно переходить сразу к нужному артефакту.

---

## Структура проекта

```
awesome_dfir/
├── windows/
│   └── windows.md       # Windows 7/2008 R2 — Windows 11/2022
├── linux/
│   └── linux.md         # Ubuntu, Debian, RHEL/CentOS/AlmaLinux
├── macos/
│   └── mac.md           # macOS 10.15 Catalina — 15 Sequoia
├── cloud/               # Coming soon
├── containers/          # Coming soon
├── k8s/                 # Coming soon
├── network/             # Coming soon
└── dfir.xmind           # Интерактивная mind map
```

---

## Как внести вклад

Мы рады любому вкладу в развитие проекта! Подробности — в [CONTRIBUTING.md](CONTRIBUTING.md).

**Краткий старт:**

1. Форкните репозиторий
2. Создайте ветку: `git checkout -b feature/add-artifact-name`
3. Внесите изменения, соблюдая структуру документов
4. Создайте Pull Request с описанием изменений

**Что можно улучшить:**

- Исправить устаревшие команды или пути
- Добавить артефакты, которых нет в документах
- Улучшить описания или примеры парсинга
- Помочь с разработкой новых разделов (cloud, containers, k8s, network)
- Добавить различные краеугольные кейсы

Баги и предложения отправляйте через [Issues](https://github.com/st3l1n/awesome_dfir/issues).

---

## Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
