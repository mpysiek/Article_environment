@echo off
rem Przebieg kontrolny v2 (z logowaniem remisow) i przebieg v3 -- zob. scripts\run_v3_pipeline.py.
rem Uruchom dwuklikiem. Okno musi pozostac otwarte do konca przebiegu (kilka godzin).
rem Katalog repozytorium wynika z polozenia tego pliku, wiec sciezka z polskimi znakami
rem i myslnikiem nie musi wystepowac w tresci skryptu.
cd /d "%~dp0.."
set PYTHONUNBUFFERED=1
set PYTHONIOENCODING=utf-8
rem Modele z lokalnej pamieci podrecznej Hugging Face, bez sprawdzania nowszych wersji w sieci:
rem przebieg kontrolny ma uzyc dokladnie tych samych wag co przebieg v2.
set HF_HUB_OFFLINE=1
set TRANSFORMERS_OFFLINE=1
".venv\Scripts\python.exe" scripts\run_v3_pipeline.py %*
echo.
echo Koniec potoku. Kod wyjscia: %ERRORLEVEL%
pause
