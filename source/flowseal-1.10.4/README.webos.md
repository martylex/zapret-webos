# Материалы Flowseal 1.10.4

Источник: [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube).
Это подмножество предоставленной сборки **1.10.4**, используемое адаптацией webOS:

- `general*.bat`: 22 оригинальных описания стратегий, не исполняются на ТВ;
- `lists/*.txt`: оригинальные списки;
- `bin/*.bin`: оригинальные TLS/QUIC/UDP-заготовки;
- `LICENSE.txt`: исходная лицензия и уведомления, без изменений.

Windows EXE, SYS и DLL, служебные скрипты Windows и резервные копии списков
исключены. Содержимое включённых файлов Flowseal не менялось. При сборке
`tools/build_strategies.py` преобразует параметры BAT в JSON-каталог;
`provenance.json` внутри IPK содержит SHA256 включённых материалов.

Благодарность Flowseal и bol-van. Подробнее: [NOTICE.md](../../NOTICE.md).
