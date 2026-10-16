# Android APK (WebView-обёртка монитора)

Никакого нативного UI: приложение — это полноэкранный WebView, который
открывает UI monitor.exe (по умолчанию http://192.168.0.150:8080) без
адресной строки. Почему не TWA: TWA требует HTTPS, а монитор ходит по
HTTP внутри локальной сети; WebView с `usesCleartextTraffic=true` даёт
HTTP из коробки.

## Собрать шустро (Android Studio)
1. File → Open → папка `android/`.
2. Дождись Gradle Sync (первый раз качает зависимости).
3. Build → Build Bundle(s)/APK(s) → Build APK(s).
4. APK: `android/app/build/outputs/apk/debug/app-debug.apk`.

## Собрать из CLI
Нужен JDK 17 и Android SDK (или `ANDROID_HOME`). Gradle wrapper (gradlew)
отсутствует — используй локальный Gradle 8.7+:
```
cd android
gradle assembleDebug
```
APK: `app/build/outputs/apk/debug/app-debug.apk`.

## CI
`.github/workflows/android.yml` собирает app-debug.apk на каждый push и
unsigned release APK на тегах `v*`; артефакты — в разделе Actions/run.

## Установить на телефон
1. Скопируй APK на телефон (или `adb install app-debug.apk`).
2. Разреши «Установка из неизвестных источников» для папки/браузера.
3. Открой APK → в лаунчере появится «DNS Monitor».
4. Первый экран открывает http://192.168.0.150:8080 (меняется в «Настройки»).

## Отладка
«Настройки» (# шестерёнка в тулбаре): адрес сервера, API-токен (опционально),
«Проверить соединение» (GET /healthz), «Сбросить настройки».
Ошибка «Не могу подключиться» → http-страница с [Повторить][Настройки].

## Подпись релиза
```
keytool -genkeypair -v -keystore monitor.keystore -alias monitor -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks monitor.keystore --out app-release.apk app-release-unsigned.apk
```
Keystore не коммитить (в .gitignore: *.keystore).

## Токен
Если в monitor.yaml задан web_token, укажи его в «Настройках» приложения —
он передаётся как ?token=… при загрузке и как localStorage/X-Auth-Token.
Сервер после валидного ?token= ставит cookie, meta-refresh и ссылки работают.