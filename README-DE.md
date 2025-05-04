Dieser Code implementiert eine Webanwendung mit den folgenden Kernfunktionen:

1.  **Benutzerauthentifizierung:**
    * **Standard-Registrierung:** Benutzer können Konten mit Benutzername, E-Mail und Passwort erstellen. Neue Registrierungen erfordern die Freigabe durch einen Administrator.
    * **Standard-Login:** Registrierte und freigegebene Benutzer können sich mit ihrem Benutzernamen und Passwort anmelden.
    * **Passwort zurücksetzen:** Benutzer können über E-Mail das Zurücksetzen ihres Passworts beantragen. Ein temporäres Passwort wird gesendet, und der Benutzer muss es beim nächsten Login ändern.
    * **Passwort ändern:** Angemeldete Benutzer können ihr Passwort ändern (entweder freiwillig oder erzwungen nach einem Reset).
    * **Logout:** Benutzer können sich sicher abmelden, wodurch ihre Sitzung gelöscht wird.
2.  **Sitzungsverwaltung (Session Management):**
    * Verwendet Flask-Session mit einem Redis-Backend, um Benutzersitzungen sicher zu verwalten.
    * Handhabt die Persistenz und das Ablaufdatum von Sitzungen.
3.  **Benutzerverwaltung (Admin Panel):**
    * Ein Administrator-Dashboard ermöglicht die Anzeige aller Benutzer und ausstehenden Registrierungen.
    * Administratoren können neu registrierte Benutzer freigeben.
    * Administratoren können bestehende Benutzerkonten deaktivieren.
    * Administratoren können anderen Benutzern Administratorrechte erteilen oder entziehen.
4.  **E-Mail-Benachrichtigungen:**
    * Verwendet die Microsoft Graph API zum Senden von E-Mails.
    * Benachrichtigt Administratoren über neue Benutzerregistrierungen, die eine Freigabe erfordern.
    * Benachrichtigt Benutzer, wenn ihr Konto freigegeben wurde, einschließlich eines einmaligen Auto-Login-Links.
    * Benachrichtigt Benutzer mit einem temporären Passwort, wenn sie eine Passwortzurücksetzung beantragen.
5.  **Datenbankinteraktion:**
    * Verbindet sich mit einer PostgreSQL-Datenbank (`psycopg2`), um Benutzerinformationen (Anmeldedaten, Status, Rollen) zu speichern.
    * Enthält Logik zur Schema-Initialisierung/Migration, um notwendige Spalten hinzuzufügen, falls sie nicht existieren.
    * Verwendet Flask-Bcrypt für sicheres Passwort-Hashing.
6.  **Web Framework & Formulare:**
    * Basiert auf dem Flask Web Framework.
    * Verwendet Flask-WTF und WTForms zur Formularerstellung und -validierung (Registrierung, Login, Passwort-Reset/-Änderung).
    * Verwendet Flasks `render_template` zur Anzeige von HTML-Seiten und `flash` für Benutzer-Feedback-Nachrichten.
    * Enthält `ProxyFix`-Middleware, um Deployments hinter Reverse Proxies korrekt zu handhaben.
7.  **Konfiguration:**
    * Verwendet Umgebungsvariablen für sensible Einstellungen wie Secret Keys, Datenbank-Zugangsdaten und Microsoft API-Details, was sichere Konfigurationspraktiken fördert.

**Detaillierte Analyse**

Gehen wir die einzelnen Abschnitte und Funktionen durch.

**Teil 1: Flask Application Code**

1.  **Imports:**
    * `os`: Wird verwendet, um auf Umgebungsvariablen für die Konfiguration zuzugreifen.
    * `redis`: Wird zur Verbindung mit dem Redis-Server für die Sitzungsspeicherung verwendet.
    * `requests`: Wird verwendet, um HTTP-Anfragen an die Microsoft Graph API zu senden.
    * `msal`: Microsoft Authentication Library für Python, wird für OAuth 2.0-Interaktionen verwendet.
    * `datetime.timedelta`: Wird zur Definition der Sitzungslebensdauer verwendet.
    * `Flask`, `render_template`, `request`, `redirect`, `url_for`, `flash`, `session`: Kernkomponenten des Flask-Frameworks zum Erstellen der Webanwendung, zur Handhabung von Anfragen, Antworten, Sitzungen und Benutzerfeedback.
    * `flask_session.Session`: Erweiterung für serverseitiges Sitzungsmanagement.
    * `flask_wtf.FlaskForm`: Basisklasse zum Erstellen von Formularen mit WTForms.
    * `wtforms`: Felder (`StringField`, `PasswordField`, `SubmitField`, `EmailField`) und Validatoren (`DataRequired`, `Email`, `Length`, `EqualTo`, `ValidationError`) für die Formularverarbeitung.
    * `werkzeug.middleware.proxy_fix.ProxyFix`: Middleware, um sicherzustellen, dass Flask korrekte URLs generiert, wenn es hinter einem Reverse Proxy läuft.
    * `models.Database`, `models.User`: Importiert die benutzerdefinierte Datenbankverbindungsklasse und die (vermutlich definierte) User-Modellklasse.

2.  **`AppConfig` Klasse:**
    * **Zweck:** Zentralisiert die Konfigurationseinstellungen der Anwendung. Liest Werte aus Umgebungsvariablen mit sinnvollen Standardwerten.
    * **Attribute:**
        * `SECRET_KEY`: Entscheidend für die Sitzungssicherheit und das Signieren.
        * `SESSION_TYPE`, `SESSION_PERMANENT`, `SESSION_USE_SIGNER`, `SESSION_REDIS`: Konfiguriert Flask-Session zur Verwendung von Redis.
        * `PERMANENT_SESSION_LIFETIME`: Legt fest, wie lange eine Sitzung dauert (1 Tag).
        * `CLIENT_ID`, `CLIENT_SECRET`, `TENANT_ID`, `AUTHORITY`, `SCOPE`, `REDIRECT_PATH`, `ENDPOINT`: Konfiguration spezifisch für die Microsoft Azure AD-Anwendungsregistrierung für OAuth- und Graph-API-Aufrufe.
        * `ADMIN_EMAIL`, `SENDER_EMAIL`: E-Mail-Adressen, die zum Senden von Benachrichtigungen verwendet werden.

3.  **App-Initialisierung:**
    * `app = Flask(__name__)`: Erstellt die Flask-Anwendungsinstanz.
    * `app.config.from_object(AppConfig)`: Lädt die Konfiguration aus der `AppConfig`-Klasse.
    * `Session(app)`: Initialisiert die Flask-Session-Erweiterung.
    * `app.wsgi_app = ProxyFix(...)`: Umhüllt die App mit der `ProxyFix`-Middleware.
    * `db = Database()`: Erstellt eine Instanz der benutzerdefinierten `Database`-Klasse (später definiert).

4.  **`MSALAuth` Klasse:**
    * **Zweck:** Kapselt die Logik für die Interaktion mit der Microsoft Authentication Library (MSAL).
    * **`__init__(self, app_config)`:**
        * **Eingabe:** `app_config` (eine Instanz oder ein Objekt mit Attributen wie `CLIENT_ID`, `CLIENT_SECRET` usw., typischerweise `AppConfig`).
        * **Zweck:** Initialisiert die MSAL `ConfidentialClientApplication`, die für Web-Apps mit einem Backend-Secret geeignet ist. Speichert die notwendige Konfiguration.
    * **`get_auth_url(self, redirect_uri)`:**
        * **Eingabe:** `redirect_uri` (String): Die absolute URL innerhalb *dieser* Anwendung, zu der Microsoft den Benutzer nach der Authentifizierung umleiten soll.
        * **Zweck:** Generiert die Microsoft-Login-URL, zu der der Benutzer umgeleitet werden muss. Enthält die erforderlichen Scopes und die Callback-URI.
        * **Ausgabe:** Ein String, der die Microsoft-Autorisierungs-URL enthält.
    * **`get_token_from_code(self, auth_code, redirect_uri)`:**
        * **Eingabe:**
            * `auth_code` (String): Der Autorisierungscode, der von Microsoft in der Weiterleitungsanfrage empfangen wurde.
            * `redirect_uri` (String): Die gleiche Redirect-URI, die beim Anfordern des Codes verwendet wurde.
        * **Zweck:** Tauscht den empfangenen Autorisierungscode mithilfe der MSAL-Bibliothek gegen ein Zugriffstoken (und möglicherweise ein Refresh-Token) ein. Dieses Token wird benötigt, um die Graph-API im Namen des Benutzers aufzurufen.
        * **Ausgabe:** Ein Dictionary, das die Token-Antwort von MSAL enthält (einschließlich `access_token`, `refresh_token` usw.) oder ein Fehler-Dictionary.
    * **`get_token_for_client(self)`:**
        * **Zweck:** Ruft ein Zugriffstoken mithilfe des Client Credentials Flow ab (Anwendungsberechtigungen, nicht benutzerdelegiert). Dies wird für Aktionen verwendet, die die Anwendung selbst durchführt, wie das Senden von E-Mails von einem Dienstkonto (`SENDER_EMAIL`).
        * **Ausgabe:** Ein String, der das Zugriffstoken enthält, falls erfolgreich, andernfalls `None`.
    * **`logout(self)`:**
        * **Zweck:** Generiert die URL zum Abmelden des Benutzers aus seiner Microsoft-Sitzung. Das Umleiten des Benutzers hierhin hilft sicherzustellen, dass er vollständig von der Microsoft Identity Platform abgemeldet ist.
        * **Ausgabe:** Ein String, der die Microsoft-Logout-URL enthält.
    * **`auth = MSALAuth(AppConfig)`:** Erstellt eine Instanz des `MSALAuth`-Helfers unter Verwendung der Anwendungskonfiguration.

5.  **Formularklassen (`FlaskForm` Unterklassen):**
    * **Zweck:** Definieren die Struktur und Validierungsregeln für HTML-Formulare mithilfe von Flask-WTF.
    * **`RegistrationForm`:** Felder für Benutzername, E-Mail, Passwort und Passwortbestätigung. Enthält benutzerdefinierte Validatoren (`validate_username`, `validate_email`), um zu prüfen, ob der Benutzername oder die E-Mail bereits in der Datenbank vorhanden ist, indem das `User`-Modell abgefragt wird.
    * **`LoginForm`:** Felder für Benutzername und Passwort.
    * **`ResetPasswordRequestForm`:** Feld für die E-Mail-Adresse des Benutzers.
    * **`ChangePasswordForm`:** Felder für das aktuelle Passwort (optional, je nach Kontext), das neue Passwort und die Bestätigung.

6.  **E-Mail-Benachrichtigungsfunktionen:**
    * **`send_admin_notification(user_data)`:**
        * **Eingabe:** `user_data` (dict): Ein Dictionary, das die Details des neu registrierten Benutzers enthält (id, username, email).
        * **Zweck:** Sendet eine E-Mail an den Administrator (`ADMIN_EMAIL`), um ihn über eine neue Benutzerregistrierung zu informieren, die eine Freigabe erfordert. Verwendet die Microsoft Graph API über die `requests`-Bibliothek und ein Anwendungs-Token, das über `auth.get_token_for_client()` bezogen wird. Erstellt und sendet die Nachricht über die Graph API Endpunkte `/users/{sender_email}/messages` und `/send`. Enthält einen "Approve User"-Link im E-Mail-Text.
        * **Ausgabe:** `True`, wenn der E-Mail-Versandprozess erfolgreich erscheint (API gibt 202 Accepted für den Versand zurück), andernfalls `False`. Enthält Print-Anweisungen zum Debuggen.
    * **`send_user_approval_notification(user_data)`:**
        * **Eingabe:** `user_data` (dict): Ein Dictionary, das die Details des freigegebenen Benutzers enthält.
        * **Zweck:** Sendet eine E-Mail an den neu freigegebenen Benutzer. Generiert ein kurzlebiges, sicheres Auto-Login-Token mit `User.generate_login_token()`. Enthält einen Link mit diesem Token (`/auto-login/<token>`) im E-Mail-Text. Verwendet die Graph API ähnlich wie `send_admin_notification`.
        * **Ausgabe:** `True`, wenn der E-Mail-Versandprozess erfolgreich erscheint, andernfalls `False`.
    * **`send_password_reset_email(user_data, new_password)`:**
        * **Eingabe:**
            * `user_data` (dict): Die Benutzerdetails.
            * `new_password` (String): Das generierte temporäre Passwort.
        * **Zweck:** Sendet eine E-Mail an den Benutzer mit seinem temporären Passwort nach einer Reset-Anfrage. Verwendet die Graph API.
        * **Ausgabe:** `True`, wenn der E-Mail-Versandprozess erfolgreich erscheint, andernfalls `False`.

7.  **Flask Routes (`@app.route(...)`)**
    * **`index()` (Route: `/`)**
        * **Zweck:** Rendert die Startseite.
        * **Eingabe:** Keine.
        * **Ausgabe:** Rendert `index.html`.
    * **`register()` (Route: `/register`, Methoden: GET, POST)**
        * **Zweck:** Handhabt die Benutzerregistrierung. Zeigt das Registrierungsformular an (GET) und verarbeitet gesendete Daten (POST).
        * **Eingabe (POST):** Formulardaten von `RegistrationForm`.
        * **Ausgabe:** Rendert `register.html`. Bei erfolgreicher POST-Validierung: erstellt einen *ausstehenden* Benutzer in der DB (`User.create` mit `active=False`), ruft `send_admin_notification` auf, zeigt eine Flash-Nachricht an und leitet zu `login` weiter. Leitet zu `profile` weiter, wenn bereits angemeldet.
    * **`login()` (Route: `/login`, Methoden: GET, POST)**
        * **Zweck:** Handhabt den Standard-Login mit Benutzername/Passwort. Zeigt das Login-Formular an (GET) und verarbeitet Anmeldedaten (POST).
        * **Eingabe (POST):** Formulardaten von `LoginForm`.
        * **Ausgabe:** Rendert `login.html`. Bei erfolgreicher POST-Validierung: holt Benutzerdaten (`User.get_by_username`), prüft Passwort (`User.check_password`), prüft, ob `active`, prüft, ob das `password_reset`-Flag gesetzt ist. Wenn alle Prüfungen erfolgreich sind, speichert `user_id`, `username`, `is_admin` in der Sitzung, zeigt eine Flash-Nachricht an und leitet zu `profile` weiter (oder zu `change_password`, wenn ein Reset erforderlich ist). Leitet zu `profile` weiter, wenn bereits angemeldet.
    * **`reset_password_request()` (Route: `/reset-password`, Methoden: GET, POST)**
        * **Zweck:** Handhabt die Anfrage zum Zurücksetzen eines Passworts. Zeigt das E-Mail-Anfrageformular an (GET) und verarbeitet die E-Mail (POST).
        * **Eingabe (POST):** Formulardaten von `ResetPasswordRequestForm`.
        * **Ausgabe:** Rendert `reset_password.html`. Bei erfolgreicher POST-Validierung: holt Benutzer per E-Mail (`User.get_by_email`), generiert ein zufälliges Passwort (`User.generate_random_password`), aktualisiert den Passwort-Hash des Benutzers und setzt das `password_reset`-Flag (`User.reset_password`), ruft `send_password_reset_email` auf, zeigt eine Flash-Nachricht an und leitet zu `login` weiter. Leitet zu `profile` weiter, wenn bereits angemeldet.
    * **`change_password()` (Route: `/change-password`, Methoden: GET, POST)**
        * **Zweck:** Ermöglicht einem angemeldeten Benutzer, sein Passwort zu ändern. Zeigt das Formular an (GET) und verarbeitet die Änderung (POST). Handhabt sowohl freiwillige Änderungen als auch erzwungene Änderungen nach einem Reset.
        * **Eingabe:** Liest `user_id` aus der Sitzung. Liest das `password_reset`-Flag aus der Sitzung. (POST) Formulardaten von `ChangePasswordForm`.
        * **Ausgabe:** Rendert `change_password.html`. Leitet zu `login` weiter, wenn nicht angemeldet. Modifiziert `ChangePasswordForm`, um das aktuelle Passwort nicht zu erfordern, wenn `password_reset` in der Sitzung true ist. Bei erfolgreicher POST-Validierung: prüft das aktuelle Passwort (wenn keine erzwungene Änderung), aktualisiert den Passwort-Hash und löscht das `password_reset`-Flag (`User.reset_password`), entfernt `password_reset` aus der Sitzung, zeigt Erfolgs-Flash an, leitet zu `profile` weiter.
    * **`ms_login()` (Route: `/ms-login`)**
        * **Zweck:** Startet den Microsoft OAuth Login-Flow.
        * **Eingabe:** Keine.
        * **Ausgabe:** Generiert die Microsoft-Autorisierungs-URL mit `auth.get_auth_url` (einschließlich der Callback-URL für `auth_redirect`) und leitet den Browser des Benutzers dorthin um.
    * **`auth_redirect()` (Route: `/auth/redirect`)**
        * **Zweck:** Handhabt den Callback von Microsoft, nachdem sich der Benutzer authentifiziert hat. Tauscht den Code gegen ein Token und meldet den Benutzer an oder registriert ihn.
        * **Eingabe:** Liest Query-Parameter aus der URL (`code`, `error`, `error_description`).
        * **Ausgabe:** Leitet bei Fehler zu `login` weiter. Bei Erfolg: tauscht Code gegen Token (`auth.get_token_from_code`), holt Benutzerprofil von der Graph API (`requests.get(AppConfig.ENDPOINT)`), prüft, ob Benutzer per E-Mail existiert (`User.get_by_email`). Wenn Benutzer existiert, meldet ihn an (setzt Sitzung). Wenn nicht, erstellt einen neuen, aktiven Benutzer (`User.create` mit `active=True`, `ms_auth=True`) und meldet ihn an. Leitet zu `profile` weiter.
    * **`logout()` (Route: `/logout`)**
        * **Zweck:** Meldet den Benutzer ab.
        * **Eingabe:** Liest die Sitzung.
        * **Ausgabe:** Löscht die Sitzung (`session.clear()`), zeigt eine Flash-Nachricht an, leitet zu `index` weiter. (Hinweis: Leitet nicht zur Microsoft-Logout-URL weiter, d.h. der Benutzer könnte noch bei Microsoft angemeldet sein).
    * **`profile()` (Route: `/profile`)**
        * **Zweck:** Zeigt die Profilseite des Benutzers an.
        * **Eingabe:** Liest `user_id` aus der Sitzung.
        * **Ausgabe:** Rendert `profile.html` und übergibt Benutzerdaten, die über `User.get_by_id` abgerufen wurden. Leitet zu `login` weiter, wenn nicht angemeldet oder Benutzer nicht gefunden.
    * **`admin_dashboard()` (Route: `/admin`)**
        * **Zweck:** Zeigt das Administrator-Dashboard mit Listen der ausstehenden und aller Benutzer an.
        * **Eingabe:** Liest `user_id` und `is_admin` aus der Sitzung.
        * **Ausgabe:** Rendert `admin_dashboard.html` und übergibt Benutzerlisten, die über `User.get_pending_users` und `User.get_all_users` abgerufen wurden. Leitet zu `login` weiter, wenn nicht angemeldet oder kein Admin.
    * **`approve_user(user_id)` (Route: `/admin/approve/<int:user_id>`)**
        * **Zweck:** Endpunkt (wahrscheinlich vom Admin-Dashboard oder aus E-Mail verlinkt), damit ein Admin einen ausstehenden Benutzer freigeben kann.
        * **Eingabe:** `user_id` (Integer aus dem URL-Pfad). Liest Admin-Status aus der Sitzung.
        * **Ausgabe:** Leitet zu `login` weiter, wenn kein Admin. Holt Benutzer (`User.get_by_id`), aktiviert den Benutzer (`User.activate`), sendet Freigabe-E-Mail (`send_user_approval_notification`), zeigt Flash-Nachricht an, leitet zurück zu `admin_dashboard`.
    * **`deactivate_user(user_id)` (Route: `/admin/deactivate/<int:user_id>`)**
        * **Zweck:** Endpunkt für einen Admin, um einen aktiven Benutzer zu deaktivieren.
        * **Eingabe:** `user_id` (Integer aus dem URL-Pfad). Liest Admin-Status und eigene `user_id` aus der Sitzung.
        * **Ausgabe:** Leitet zu `login` weiter, wenn kein Admin. Verhindert Selbst-Deaktivierung. Deaktiviert den Benutzer (`User.deactivate`), zeigt Flash-Nachricht an, leitet zurück zu `admin_dashboard`.
    * **`auto_login(token)` (Route: `/auto-login/<token>`)**
        * **Zweck:** Handhabt den Einmal-Login-Link, der in der Freigabe-E-Mail gesendet wird.
        * **Eingabe:** `token` (String aus dem URL-Pfad).
        * **Ausgabe:** Überprüft das Token (`User.verify_login_token`). Wenn gültig, holt den Benutzer (`User.get_by_id`), prüft, ob aktiv, meldet den Benutzer an (setzt Sitzung), zeigt Flash-Nachricht an und leitet zu `profile` weiter. Wenn Token ungültig/abgelaufen oder Benutzer nicht gefunden/inaktiv, zeigt Fehler-Flash an und leitet zu `login` weiter. Behandelt den Randfall, dass der Benutzer möglicherweise ein initiales Passwort setzen muss.
    * **`make_admin(user_id)` (Route: `/admin/make-admin/<int:user_id>`)**
        * **Zweck:** Endpunkt für einen Admin, um einem anderen Benutzer Admin-Rechte zu erteilen.
        * **Eingabe:** `user_id` (Integer aus dem URL-Pfad). Liest Admin-Status aus der Sitzung.
        * **Ausgabe:** Leitet zu `login` weiter, wenn kein Admin. Aktualisiert das `is_admin`-Flag des Benutzers in der DB (`User.make_admin`), zeigt Flash-Nachricht an, leitet zu `admin_dashboard` weiter.
    * **`remove_admin(user_id)` (Route: `/admin/remove-admin/<int:user_id>`)**
        * **Zweck:** Endpunkt für einen Admin, um einem anderen Benutzer Admin-Rechte zu entziehen.
        * **Eingabe:** `user_id` (Integer aus dem URL-Pfad). Liest Admin-Status und eigene `user_id` aus der Sitzung.
        * **Ausgabe:** Leitet zu `login` weiter, wenn kein Admin. Verhindert Selbst-Entzug. Aktualisiert das `is_admin`-Flag des Benutzers in der DB (`User.remove_admin`), zeigt Flash-Nachricht an, leitet zu `admin_dashboard` weiter.

8.  **Hauptausführungsblock (`if __name__ == '__main__':`)**
    * **Zweck:** Startet den Flask-Entwicklungsserver, wenn das Skript direkt ausgeführt wird.
    * **Eingabe:** Keine.
    * **Ausgabe:** Startet den Webserver, der auf allen Schnittstellen (`0.0.0.0`) auf dem Standard-Flask-Port (5000) lauscht, mit aktiviertem Debugging (`debug=True`).

**Teil 2: Datenbankmodell-Code (`models.py` äquivalent)**

1.  **Imports:**
    * `psycopg2`, `psycopg2.extras`: PostgreSQL-Adapter für Python. `extras` wird wahrscheinlich für `DictCursor` verwendet.
    * `os`: Um Datenbankverbindungsdetails aus Umgebungsvariablen zu erhalten.
    * `random`, `string`: Wird von `User.generate_random_password` verwendet.
    * `flask_bcrypt.Bcrypt`: Wird für das Passwort-Hashing verwendet (`User.create`, `User.check_password`, `User.reset_password`).
    * `secrets`: Wird zur Generierung kryptographisch sicherer Token verwendet (`User.generate_login_token`).
    * `datetime`, `timedelta`: Wird zum Setzen des Token-Ablaufs verwendet (`User.generate_login_token`).
    * `bcrypt = Bcrypt()`: Initialisiert das Bcrypt-Objekt. *Hinweis: Es ist im Allgemeinen besser, Erweiterungen im Flask-App-Kontext zu initialisieren, wenn sie von der App-Konfiguration abhängen, aber hier scheint es eigenständig zu sein.*

2.  **`Database` Klasse:**
    * **Zweck:** Verwaltet die Verbindung zur PostgreSQL-Datenbank.
    * **`__init__(self)`:** Initialisiert `self.conn` auf `None`.
    * **`connect(self)`:**
        * **Zweck:** Stellt eine Verbindung zur Datenbank her, falls noch keine besteht. Liest Verbindungsparameter (Host, Port, DB-Name, Benutzer, Passwort) aus Umgebungsvariablen. Setzt `autocommit=True` (was bedeutet, dass jede SQL-Anweisung in ihrer eigenen Transaktion ausgeführt wird). Ruft `_init_schema` nach dem Verbinden auf.
        * **Ausgabe:** Gibt das aktive `psycopg2`-Verbindungsobjekt zurück.
    * **`_init_schema(self)`:**
        * **Zweck:** Stellt sicher, dass das notwendige Datenbankschema (Tabellen und Spalten) existiert. Prüft das Vorhandensein der Spalten `active`, `is_admin` und `password_reset` in der `users`-Tabelle und fügt sie hinzu, falls sie fehlen (`ALTER TABLE`). Erstellt auch die `user_tokens`-Tabelle, falls sie nicht existiert. Dies macht die Anwendung für diese spezifischen Änderungen gewissermaßen selbstmigrierend.
        * **Eingabe:** Verwendet `self.conn`.
        * **Ausgabe:** Modifiziert das Datenbankschema bei Bedarf. Fängt und druckt `psycopg2.Error`.
    * **`get_cursor(self)`:**
        * **Zweck:** Bequeme Methode, um einen Datenbank-Cursor zu erhalten, wobei sichergestellt wird, dass zuerst eine Verbindung hergestellt wird. Verwendet `DictCursor`, der den Zugriff auf Abfrageergebnisse wie Dictionaries ermöglicht (z. B. `row['username']`).
        * **Ausgabe:** Ein `psycopg2.extras.DictCursor`-Objekt.
    * **`close(self)`:**
        * **Zweck:** Schließt die Datenbankverbindung, falls sie geöffnet ist. *(Hinweis: Die bereitgestellte Implementierung ist unvollständig, sie sollte `self.conn.close()` innerhalb des `if`-Blocks enthalten)*. In einer Web-App werden Verbindungen oft pro Anfrage verwaltet oder über einen Pool, anstatt einer einzigen persistenten Verbindung, wie dies hier impliziert sein könnte.

3.  **`User` Klasse (Abgeleitete Funktionalität):**
    * *(Diese Klasse ist im bereitgestellten Code nicht definiert, aber ihre Methoden werden aufgerufen. Die folgenden Beschreibungen basieren darauf, wie diese Methoden in der Flask-App verwendet werden.)*
    * **Zweck:** Repräsentiert das User-Modell und kapselt alle Datenbankoperationen im Zusammenhang mit Benutzern. Enthält wahrscheinlich statische Methoden, die die `db` (Database-Instanz) als Argument entgegennehmen.
    * **`create(db, username, email, password, active=False, ms_auth=False)`:**
        * **Eingabe:** `db`-Instanz, Benutzerdetails (`username`, `email`), `password` (oder `None` für MS-Auth), `active`-Status, `ms_auth`-Flag.
        * **Zweck:** Fügt einen neuen Benutzerdatensatz in die `users`-Tabelle ein. Hasht das Passwort mit `bcrypt.generate_password_hash()`, falls angegeben. Setzt den `active`-Status (Standard `False` für Standardregistrierung, `True` für MS-Auth). Setzt das `ms_auth`-Flag.
        * **Ausgabe:** Gibt die ID des neuen Benutzers zurück oder `None` bei Fehlschlag.
    * **`get_by_id(db, user_id)`:**
        * **Eingabe:** `db`-Instanz, `user_id`.
        * **Zweck:** Ruft einen Benutzerdatensatz anhand seiner Primärschlüssel-ID aus der `users`-Tabelle ab.
        * **Ausgabe:** Ein Dictionary-ähnliches Objekt (von `DictCursor`), das die Benutzerzeile repräsentiert, oder `None`, wenn nicht gefunden.
    * **`get_by_username(db, username)`:**
        * **Eingabe:** `db`-Instanz, `username`.
        * **Zweck:** Ruft einen Benutzerdatensatz anhand des Benutzernamens ab.
        * **Ausgabe:** Benutzerzeilen-Dictionary oder `None`.
    * **`get_by_email(db, email)`:**
        * **Eingabe:** `db`-Instanz, `email`.
        * **Zweck:** Ruft einen Benutzerdatensatz anhand der E-Mail-Adresse ab.
        * **Ausgabe:** Benutzerzeilen-Dictionary oder `None`.
    * **`check_password(user, password)`:**
        * **Eingabe:** `user` (Benutzerdaten-Dictionary), `password` (Klartextpasswort zum Prüfen).
        * **Zweck:** Überprüft, ob das bereitgestellte `password` mit dem gespeicherten Hash (`user['password_hash']`) übereinstimmt, mithilfe von `bcrypt.check_password_hash()`.
        * **Ausgabe:** `True`, wenn das Passwort übereinstimmt, andernfalls `False`.
    * **`activate(db, user_id)`:**
        * **Eingabe:** `db`-Instanz, `user_id`.
        * **Zweck:** Aktualisiert den Datensatz des Benutzers, um `active = TRUE` zu setzen.
        * **Ausgabe:** `True` bei Erfolg, `False` bei Fehlschlag.
    * **`deactivate(db, user_id)`:**
        * **Eingabe:** `db`-Instanz, `user_id`.
        * **Zweck:** Aktualisiert den Datensatz des Benutzers, um `active = FALSE` zu setzen.
        * **Ausgabe:** `True` bei Erfolg, `False` bei Fehlschlag.
    * **`get_pending_users(db)`:**
        * **Eingabe:** `db`-Instanz.
        * **Zweck:** Ruft alle Benutzerdatensätze ab, bei denen `active = FALSE`.
        * **Ausgabe:** Eine Liste von Benutzerzeilen-Dictionaries.
    * **`get_all_users(db)`:**
        * **Eingabe:** `db`-Instanz.
        * **Zweck:** Ruft alle Benutzerdatensätze ab.
        * **Ausgabe:** Eine Liste von Benutzerzeilen-Dictionaries.
    * **`reset_password(db, user_id, new_password, needs_reset_flag)`:**
        * **Eingabe:** `db`-Instanz, `user_id`, `new_password` (Klartext), `needs_reset_flag` (Boolean).
        * **Zweck:** Aktualisiert den `password_hash` des Benutzers mit dem Hash von `new_password`. Setzt die boolesche Spalte `password_reset` basierend auf `needs_reset_flag`.
        * **Ausgabe:** `True` bei Erfolg, `False` bei Fehlschlag.
    * **`generate_random_password(length=12)`:**
        * **Eingabe:** Optionale `length`.
        * **Zweck:** Generiert eine kryptographisch sichere Zufallszeichenfolge, die sich als temporäres Passwort eignet. Verwendet `random` und `string`.
        * **Ausgabe:** Eine zufällige Passwortzeichenfolge.
    * **`generate_login_token(db, user_id, expires_in=86400)`:**
        * **Eingabe:** `db`-Instanz, `user_id`, optionale Ablaufzeit in Sekunden (Standard 1 Tag).
        * **Zweck:** Generiert ein sicheres, eindeutiges, zeitlich begrenztes Token (mit `secrets.token_urlsafe`). Speichert das Token, seinen Typ ('login'), die Benutzer-ID und den Ablaufzeitstempel in der `user_tokens`-Tabelle.
        * **Ausgabe:** Die generierte Token-Zeichenfolge oder `None` bei Fehlschlag.
    * **`verify_login_token(db, token)`:**
        * **Eingabe:** `db`-Instanz, `token`-String.
        * **Zweck:** Sucht das Token in der `user_tokens`-Tabelle. Prüft, ob es existiert, vom Typ 'login' ist und nicht abgelaufen ist. Wenn gültig, löscht das Token (um es einmalig verwendbar zu machen).
        * **Ausgabe:** Die zugehörige `user_id`, wenn das Token gültig und verifiziert ist, andernfalls `None`.
    * **`make_admin(db, user_id)`:**
        * **Eingabe:** `db`-Instanz, `user_id`.
        * **Zweck:** Aktualisiert den Datensatz des Benutzers, um `is_admin = TRUE` zu setzen.
        * **Ausgabe:** `True` bei Erfolg, `False` bei Fehlschlag.
    * **`remove_admin(db, user_id)`:**
        * **Eingabe:** `db`-Instanz, `user_id`.
        * **Zweck:** Aktualisiert den Datensatz des Benutzers, um `is_admin = FALSE` zu setzen.
        * **Ausgabe:** `True` bei Erfolg, `False` bei Fehlschlag.

**Klassendiagramm (Textuelle Darstellung)**

```
+-----------------+      +--------------------+      +-------------------+
|      Flask      |----->|    AppConfig       |      |      Redis        |
| (Anwendung)     |      | (Konfiguration)    |      | (Session Backend) |
+-----------------+      +--------------------+      +-------------------+
       | 1
       | Verwendet 1..*
       v
+-----------------+      +--------------------+      +-------------------+
| FlaskForm       |<-----| RegistrationForm   |      |      MSALAuth     |
| (WTForms Basis) |      | LoginForm          |----->| (MSAL Wrapper)    |
+-----------------+      | ResetPassword...   |      +-------------------+
                         | ChangePasswordForm |             | 1
                         +--------------------+             | Verwendet
                                                            v
                                                     +-----------------+
                                                     |      msal       |
                                                     | (MS Bibliothek) |
                                                     +-----------------+

+-----------------+      +--------------------+      +-------------------+
|      Flask      |----->|      Session       |      |      Requests     |
| (Routen/Views)  |      | (Benutzerzustand)  |      | (HTTP Client)     |
+-----------------+      +--------------------+      +-------------------+
   |                          ^                             |
   | Verwendet                | Liest/Schreibt              | Ruft MS Graph API auf
   v                          |                             v
+-----------------+           |                  +----------------------+
|      User       |<----------+------------------| send_..._notification|
| (Modell-Logik)  |                              | (E-Mail Funktionen)  |
+-----------------+                              +----------------------+
   | 1                                                  |
   | Verwendet 1                                        | Verwendet
   v                                                    v
+-----------------+                              +-----------------+
|    Database     |----------------------------->|    psycopg2     |
| (DB Verbindung) |                              | (PostgreSQL Treiber)|
+-----------------+                              +-----------------+
   |                                                    ^
   | Verwendet                                          |
   v                                                    |
+-----------------+                                     |
|     Bcrypt      |-------------------------------------+
| (Hashing)       |
+-----------------+
```

**Erklärung des Diagramms:**

* Pfeile zeigen Abhängigkeiten oder Verwendung an (`-->` "verwendet" oder "hängt ab von", `<--` Vererbung/Implementierung).
* Das `Flask`-Anwendungsobjekt ist zentral.
* Es verwendet `AppConfig` für Einstellungen.
* Es interagiert mit `FlaskForm`-Unterklassen zur Handhabung von Webformularen.
* Es verwendet `MSALAuth` (das die `msal`-Bibliothek umhüllt) für den Microsoft-Login.
* Routen innerhalb von `Flask` rufen Methoden des `User`-Modells (Logik) auf.
* E-Mail-Funktionen verwenden ebenfalls `MSALAuth` (für App-Token) und `requests`, um die Graph API aufzurufen.
* Das `User`-Modell verwendet die `Database`-Klasse, um Verbindungen/Cursors zu erhalten.
* Die `Database`-Klasse verwendet `psycopg2`, um mit PostgreSQL zu kommunizieren.
* `Bcrypt` wird (wahrscheinlich) vom `User`-Modell und `psycopg2` für die Passwortbehandlung verwendet.
* `Flask` verwendet `Session` (konfiguriert für `Redis`), um den Benutzerzustand zwischen Anfragen zu speichern.

Diese detaillierte Aufschlüsselung deckt die Funktionen, die Konfiguration, die Komponenten und den Ablauf des bereitgestellten Flask-Anwendungscodes auf Deutsch ab.
