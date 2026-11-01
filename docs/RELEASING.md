# Публикация релиза

Workflow `.github/workflows/release.yml` собирает пакеты из одного тега,
проверяет Windows-клиент, Android-клиент и сервер, затем публикует GitHub Release.
Исходники должны быть отправлены в `develop-mdv/quantom_vpn`.

1. Согласуйте номер версии с `Cargo.toml` и `omega-android/app/build.gradle.kts`.
2. Добавьте описание и ограничения версии в `docs/releases/vX.Y.Z.md`.
3. Закоммитьте и отправьте изменения, затем создайте и отправьте тег:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Дождитесь успешного workflow **Release Omega VPN** во вкладке Actions.
Релиз появляется публично только после завершения всех сборок и загрузки файлов.
При сбое можно повторно запустить workflow вручную с тем же тегом;
перемещать опубликованные теги на другой коммит не следует.

## Пакеты

- `OmegaVPN-windows-x64-setup.zip`: всё содержимое `installer`, включая .NET runtime и `payload/`.
- `OmegaVPN-windows-x64-portable.zip`: папка `OmegaVPN` с GUI, Rust runtime и Wintun.
- `OmegaVPN-android-debug.apk`: тестовая подписанная debug-сборка для ARM64/x86_64.
- `omega-server-linux-x86_64.tar.gz`, `omega-server-linux-aarch64.tar.gz`: статический musl binary и скрипты настройки systemd/NAT.
- `SHA256SUMS`: контрольные суммы всех перечисленных пакетов.

Android пока распространяется как debug APK. У GitHub runner тестовый ключ
может меняться между сборками, поэтому установка поверх предыдущего APK может
потребовать удаления старой версии. Для постоянных обновлений сначала настройте
release-подпись с сохраняемым keystore; ключ и пароли должны храниться в secrets,
а не в репозитории. Для iOS сборки нет.

## Ручная сборка Windows

Из корня репозитория:

```powershell
powershell -ExecutionPolicy Bypass -File .\omega-client-app\package-windows-client.ps1
Compress-Archive -Path .\omega-client-app\artifacts\windows-client\installer\* -DestinationPath .\OmegaVPN-windows-x64-setup.zip
Compress-Archive -Path .\omega-client-app\artifacts\windows-client\portable\OmegaVPN -DestinationPath .\OmegaVPN-windows-x64-portable.zip
```

Пользователю нужно распаковать весь setup ZIP и запустить `Omega.Client.Setup.exe`.
Нельзя прикреплять только EXE: он использует соседние DLL и `payload/`.
Пакет не должен содержать профили, `app-config*.json`, токены устройств или логи.

## Ручная сборка Android

Потребуются JDK 17, Android SDK 35, NDK 27.1.12297006 и Rust targets:

```bash
rustup target add aarch64-linux-android x86_64-linux-android
cd omega-android
./gradlew :app:assembleDebug :app:testDebugUnitTest
```

На Windows используйте `gradlew.bat`. Устанавливаемый файл:
`omega-android/app/build/outputs/apk/debug/app-debug.apk`.
Gradle сам собирает Rust JNI bridge и включает обе архитектуры в APK.
