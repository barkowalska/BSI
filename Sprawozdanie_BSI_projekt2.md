# Sprawozdanie z projektu 2 - E: Log forwarding: Linux

**Cel:** Ustanowienie bezpiecznego, szyfrowanego kanału komunikacji (TLS) pomiędzy maszyną kliencką (Nadawca) a centralnym serwerem logów (Odbiorca), zgodnie z wytycznymi hardeningu CIS. Konfiguracja obejmuje integrację systemu Audit z usługą RSyslog oraz weryfikację zdalnego logowania.

---

## 1. Konfiguracja zaawansowanego auditingu zgodnego z benchmarkami CIS

W ramach realizacji zadania wdrożono zaawansowany auditing oraz bezpieczne przesyłanie logów, spełniając wymagania CIS Benchmark dla RHEL 10.

### 6.1 Integralność i ochrona narzędzi audytu

**6.1.1 Instalacja AIDE**
Zainstalowano system sprawdzania integralności plików.
*Weryfikacja:* `dnf list installed aide`

![Instalacja AIDE](photos/sec1.png)

**6.1.3 Ochrona narzędzi audytu**
Narzędzia takie jak `auditctl` czy `auditd` zostały dodane do bazy AIDE, aby monitorować ich sumy kontrolne SHA512.
*Weryfikacja:* `grep -E "auditctl|auditd" /etc/aide.conf`

![Weryfikacja konfiguracji AIDE](photos/sec2.png)

### 6.2 Przekazywanie zdarzeń do RSyslog

Konfiguracja ta pozwala na przechwycenie logów z dziennika systemowego i wysłanie ich do centralnego serwera.

**6.2.3.2 Aktywność usługi RSyslog**
Usługa jest włączona i przesyła dane w czasie rzeczywistym.
*Weryfikacja:* `systemctl is-active rsyslog`

![Status usługi RSyslog](photos/sec3.png)

**6.2.3.3 Integracja Journald z RSyslog**
Włączono parametr `ForwardToSyslog`, co pozwala RSyslogowi na pobieranie logów z modułu imjournal.
*Weryfikacja:* `grep "^ForwardToSyslog=yes" /etc/systemd/journald.conf`

![Konfiguracja Journald](photos/sec4.png)

**6.2.3.4 Konfiguracja trybu tworzenia plików logów (FileCreateMode)**
Ustawienie uprawnień `0640` chroni lokalne kopie logów przed nieuprawnionym odczytem.
*Weryfikacja:* `grep $FileCreateMode 0640" /etc/rsyslog.conf /etc/rsyslog.d/*.conf`

![Uprawnienia plików logów](photos/sec5.png)

**6.2.3.6 Zdalne logowanie (Log Forwarding)**
Skonfigurowano akcję `omfwd` kierującą logi na IP Odbiorcy przez port 6514.
*Weryfikacja:* `grep "action(type=\"omfwd\"" /etc/rsyslog.conf`

![Konfiguracja omfwd](photos/sec6.png)

### 6.3 Zaawansowane reguły audytu

Reguły audytu zostały zorganizowane tematycznie w osobnych plikach konfiguracyjnych w katalogu `/etc/audit/rules.d/`, zgodnie z zaleceniami CIS Benchmark. Każdy plik odpowiada za inną klasę zdarzeń (zarządzanie użytkownikami, eskalacja uprawnień, integralność systemu). Reguły są ładowane automatycznie przy starcie systemu (augenrules).

Aktywność reguł została potwierdzona poleceniem `auditctl -l`.

![Lista reguł auditctl](photos/sec7.png)

**6.3.1.4 Aktywność usługi Auditd**
Demon audytu działa i generuje wpisy dla zdarzeń systemowych.
*Weryfikacja:* `systemctl is-active auditd`

![Status usługi Auditd](photos/sec8.png)

**6.3.3.10 Monitorowanie poleceń uprzywilejowanych**
Rejestrowane jest każde użycie komendy sudo (i innych uprzywilejowanych).
*Weryfikacja:* `find /etc/audit/rules.d/ -type f -exec grep -l "privileged" {} +`

![Reguły privileged](photos/sec9.png)

**6.3.3.13 Monitorowanie bazy użytkowników**
Każda zmiana w pliku `/etc/passwd` (np. przez useradd) generuje ślad audytowy.
*Weryfikacja:* `grep "passwd" /etc/audit/rules.d/*.rules`

![Monitorowanie passwd](photos/sec10.png)

**6.3.2.2 Zapobieganie automatycznemu usuwaniu logów**
Konfiguracja zapobiega utracie dowodów w przypadku przepełnienia logów (`keep_logs`).
*Weryfikacja:* `grep max_log_file_action /etc/audit/auditd.conf`

![Retencja logów](photos/sec11.png)

**6.3.3.36 Niezmienność konfiguracji**
Zablokowano możliwość zmiany reguł audytu bez restartu systemu (parametr `-e 2`).
*Weryfikacja:* `grep -Ph -- '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules | tail -1`

![Immutable mode config](photos/sec12.png)

---

## 2. Konfiguracja RSyslog do pracy z TLS (Sekcja 6.2.3.6)

Ten etap odpowiada za bezpieczne "wypchnięcie" logów na zewnątrz. Konfiguracja po stronie Nadawcy (Rocky 10) znajduje się w pliku `/etc/rsyslog.d/90-forwarding.conf`.

**Kluczowe elementy konfiguracji:**
* **DefaultNetstreamDriver="gtls":** Użycie sterownika GnuTLS.
* **Certyfikaty:** Wskazanie CA (`ca.crt`) oraz certyfikatu/klucza klienta (`client.crt`, `client.key`).
* **Target:** Adres IP serwera (192.168.0.142), port 6514.
* **StreamDriverMode="1":** Wymuszenie szyfrowania.
* **StreamDriverAuthMode="x509/name":** Weryfikacja tożsamości serwera.

![Plik 90-forwarding.conf](photos/sec13.png)

---

## 3. Przekazywanie zdarzeń audytowych w czasie rzeczywistym

Na maszynie klienckiej skonfigurowano auditd w trybie niezmiennym (immutable).
Poprawność działania potwierdzono poleceniem `auditctl -s` (`enabled = 2`).

![Status auditctl -s](photos/sec14.png)

W celu przekazywania zdarzeń poza system lokalny, wykorzystano plugin `builtin_syslog`.
*Weryfikacja:* Plik `/etc/audit/plugins.d/syslog.conf` (`active = yes`).

![Konfiguracja pluginu syslog](photos/sec15.png)

Zdarzenia są rejestrowane w journald (forwarding włączony):
*Weryfikacja:* `grep "^ForwardToSyslog=yes" /etc/systemd/journald.conf`

![Weryfikacja ForwardToSyslog](photos/sec16.png)

Usługa RSyslog pobiera zdarzenia z journald przy użyciu modułu `imjournal`.
*Weryfikacja:* `grep -R "imjournal" /etc/rsyslog.conf /etc/rsyslog.d/*.conf`

![Moduł imjournal](photos/sec17.png)

---

## 4. Konfiguracja Odbiorcy (RHEL 10)

Odbiorca nasłuchuje na dedykowanym, bezpiecznym porcie 6514/TCP. Konfiguracja znajduje się w `/etc/rsyslog.d/remote.conf`.

**Kluczowe elementy:**
* `module(load="imtcp" ...)`: Obsługa TLS, autoryzacja "anon" (sprawdzenie podpisu CA).
* `input(type="imtcp" port="6514")`: Otwarcie gniazda.
* **Szablony dynamiczne:** Rozdzielanie logów na katalogi per maszyna (`%HOSTNAME%`) i pliki per program (`%PROGRAMNAME%`).

![Plik remote.conf](photos/sec18.png)

---

## 5. Weryfikacja i działania sankcjonowane

Przeprowadzono testy "end-to-end" potwierdzające działanie łańcucha logowania.

### 1. Akcja na Nadawcy: Utworzenie użytkownika
Wykonano komendę: `sudo useradd projekt_bsi`.
*Mechanizm:* Kernel -> Auditd -> Journald -> RSyslog (TLS) -> Odbiorca.
*Weryfikacja u Odbiorcy:* Sprawdzono plik `/var/log/remote/Nadawca-BSI/useradd.log`.

![Log useradd na serwerze](photos/sec19.png)

### 2. Akcja na Nadawcy: Eskalacja uprawnień
Wykonano komendę: `sudo -i`.
*Weryfikacja u Odbiorcy:* Potwierdzono obecność wpisu w pliku `/var/log/remote/Nadawca-BSI/sudo.log`.

![Log sudo na serwerze](photos/sec20.png)

### 3. Akcja na Nadawcy: Test manualny (logger)
Wykonano komendę: `logger -p authpriv.notice "BSI test – zdarzenie audytowe logger"`.
*Weryfikacja u Odbiorcy:* Potwierdzono obecność wpisu testowego w pliku `/var/log/remote/Nadawca-BSI/root.log`.

![Log logger na serwerze](photos/sec21.png)

---

## 6. Wnioski

Zadanie wykonano zgodnie z wymogami bezpieczeństwa. Połączenie jest odporne na podsłuch (szyfrowanie TLS) oraz na próby podszycia się pod serwer logów. Logi są składowane w sposób scentralizowany i uporządkowany, co spełnia rygorystyczne normy CIS.