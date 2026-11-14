# Публикация на GitHub

Целевой репозиторий: **martylex/zapret-webos**, публичный.

Описание для поля About:

> Неофициальный Zapret для LG webOS с root и Homebrew Channel. 22 стратегии на основе Flowseal 1.10.4; управление с пульта и автозапуск.

Темы: `lg`, `webos`, `zapret`, `flowseal`, `homebrew`, `dpi`, `python`.

## Первый коммит и репозиторий

`.gitignore` исключает личные журналы, сведения о телевизорах, SSH known_hosts,
артефакты сборки и ненужные Windows-бинарники. Перед коммитом проверьте
`git status --short` и `git diff --cached --stat`. Добавляйте исходники без `-f`.

Если репозиторий ещё не создан, создайте на GitHub пустой публичный
`martylex/zapret-webos` без автоматического README/лицензии: они уже есть локально.
Если первого коммита ещё нет, выполните из корня проекта:

```powershell
git add .
git diff --cached --stat
git commit -m "Подготовить публичную адаптацию Zapret для LG webOS"
git branch -M main
```

Затем добавьте remote и отправьте коммит:

```powershell
git remote add origin https://github.com/martylex/zapret-webos.git
git push -u origin main
```

Если `origin` уже существует, проверьте `git remote -v` и используйте его.
Пароли и токены не сохраняйте в исходниках или URL remote.

## Первый релиз

1. Выполните [сборку и проверки](development.md).
2. Создайте тег `v0.2.1` на публикуемом коммите и отправьте его:

```powershell
git tag -a v0.2.1 -m "Первая публичная сборка для LG webOS"
git push origin v0.2.1
```

3. В GitHub Releases создайте релиз **Zapret для LG webOS 0.2.1** по этому тегу.
4. Возьмите описание из [release-0.2.1.md](release-0.2.1.md).
5. Прикрепите `dist/org.flowseal.webos_0.2.1_all.ipk` и одноимённый `.sha256`.
   При желании приложите `dist/package-contents.json`.

IPK размещается в Releases, а не в истории Git. Исходники GitHub упакует
автоматически. `diagnostics/`, `local/` и прежний архив настройки ТВ не публикуются.
