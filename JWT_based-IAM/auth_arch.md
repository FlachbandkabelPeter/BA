# Architektur: JWT-basiertes Identity- und Access-Management mit OIDC-Federation

## 1. Designprinzipien

**Strangler Fig Migration:** Die Auth-Komponente lebt neben dem bestehenden Session-System. Beide Authentifizierungswege (Session und JWT) koexistieren. Neue Endpunkte und externe Services nutzen JWT, bestehende Legacy-Teile können weiterhin Sessions nutzen. Es gibt keinen Big-Bang-Umstieg.

**Framework ist die Authority:** Das firmeninterne Framework bleibt die einzige Instanz, die interne JWTs ausstellt. Externe IdPs (Keycloak, Azure AD, etc.) liefern nur die Identitätsbestätigung – die Token-Hoheit bleibt intern.

**Permission-System unverändert:** Das bestehende ABAC-System mit Orga-Tree wird nicht angefasst. Sobald ein User über JWT identifiziert ist, greift das Permission-System wie bisher per In-Process-Aufruf.

**Microservice-ready:** Jede Architekturentscheidung wird so getroffen, dass ein späteres Herauslösen von Services möglich ist, ohne die Auth-Komponente umzubauen.

---

## 2. Komponentenübersicht

Die Auth-Komponente besteht aus vier Schichten:

```
┌─────────────────────────────────────────────────────┐
│  1. Auth-Middleware (Request Interceptor)            │
│     Entscheidet: JWT-Flow oder Legacy-Session-Flow  │
├─────────────────────────────────────────────────────┤
│  2. Identity Broker Layer                           │
│     Abstrahiert verschiedene Login-Methoden          │
│     (OIDC, LDAP, Local) zu einer einheitlichen      │
│     AuthenticatedIdentity                           │
├─────────────────────────────────────────────────────┤
│  3. Token Service                                   │
│     JWT-Ausstellung, Refresh-Management,            │
│     Revocation                                      │
├─────────────────────────────────────────────────────┤
│  4. Key Management                                  │
│     Schlüsselverwaltung, Rotation, JWKS-Endpoint    │
└─────────────────────────────────────────────────────┘
```

---

## 3. Schicht 1: Auth-Middleware

### Aufgabe

Die Middleware ist der zentrale Einstiegspunkt für jede HTTP-Anfrage. Sie entscheidet anhand des Requests, welcher Authentifizierungsweg genommen wird, und stellt am Ende ein einheitliches `AuthContext`-Objekt bereit, das der restliche Code nutzt.

### Entscheidungslogik

```
Eingehender Request
    │
    ├─ Authorization: Bearer <token> vorhanden?
    │   └─ JA → JWT-Validation-Pipeline
    │          1. Signatur prüfen (Public Key via Key Management)
    │          2. Claims validieren (exp, iat, nbf, iss, aud)
    │          3. jti gegen Blacklist prüfen
    │          4. AuthContext erzeugen aus JWT-Claims
    │
    ├─ Session-Cookie vorhanden?
    │   └─ JA → Legacy-Session-Flow (bestehendes System)
    │          Session laden, AuthContext aus Session erzeugen
    │
    └─ Keins von beiden?
        └─ 401 Unauthorized
```

### AuthContext (einheitliches Ergebnis)

Egal ob JWT oder Session – der restliche Code arbeitet immer mit dem gleichen Objekt:

```php
class AuthContext
{
    public readonly int $userId;
    public readonly int $orgId;
    public readonly string $username;
    public readonly string $authMethod;  // 'jwt', 'session'
    public readonly ?string $idpSource;  // 'local', 'oidc:keycloak', 'ldap'
    public readonly DateTimeImmutable $authenticatedAt;
}
```

### Warum das wichtig ist

Das bestehende Permission-System braucht eine `userId` und eine `orgId`. Solange der AuthContext diese liefert, ist es dem ABAC-System egal, ob der User per JWT oder Session authentifiziert wurde. Das ist der Entkopplungspunkt.

### Integration ins komponentenbasierte Framework

Die Middleware wird als Framework-Komponente registriert, die in der Request-Pipeline vor den Business-Controllern liegt:

```
HTTP Request
  → Routing
    → AuthMiddleware (NEU)
      → PermissionCheck (Bestand)
        → BusinessController (Bestand)
```

Wenn das Framework ein Middleware-/Event-System hat, registriert sich die AuthMiddleware dort. Falls nicht, wird sie als Wrapper um die bestehende Session-Prüfung gelegt – der Legacy-Code wird nicht verändert, nur ergänzt.

---

## 4. Schicht 2: Identity Broker Layer

### Aufgabe

Abstrahiert verschiedene Authentifizierungsmethoden hinter einem einheitlichen Interface. Jeder Provider liefert am Ende eine `AuthenticatedIdentity` – die interne Repräsentation einer erfolgreich bestätigten Identität.

### Provider-Interface

```php
interface IdentityProviderInterface
{
    /**
     * Gibt den eindeutigen Identifier dieses Providers zurück.
     * z.B. 'local', 'oidc:keycloak', 'ldap:main'
     */
    public function getIdentifier(): string;

    /**
     * Prüft ob dieser Provider den gegebenen Login-Request
     * verarbeiten kann.
     */
    public function supports(LoginRequest $request): bool;

    /**
     * Führt die Authentifizierung durch.
     * Liefert eine AuthenticatedIdentity oder wirft eine Exception.
     */
    public function authenticate(LoginRequest $request): AuthenticatedIdentity;
}
```

### AuthenticatedIdentity (Zwischenergebnis)

```php
class AuthenticatedIdentity
{
    public readonly string $providerIdentifier;  // 'oidc:keycloak'
    public readonly string $externalSubject;      // Sub-Claim vom IdP
    public readonly ?string $email;
    public readonly ?string $displayName;
    public readonly array $idpClaims;             // Rohe Claims vom IdP
    public readonly ?int $mappedUserId;           // Null wenn noch nicht gemappt
    public readonly ?int $mappedOrgId;
}
```

### Konkreter Provider: OidcProvider

Der OIDC-Provider implementiert den Authorization Code Flow mit PKCE gegen einen externen Identity Provider.

#### OIDC-Login-Flow im Detail

```
Browser                     Framework                      Keycloak (IdP)
  │                            │                               │
  ├── GET /auth/login/oidc ──►│                               │
  │   ?idp=keycloak            │                               │
  │                            ├── Generiere:                  │
  │                            │   - state (CSRF-Schutz)       │
  │                            │   - code_verifier (random)    │
  │                            │   - code_challenge (S256)     │
  │                            │   - nonce (Replay-Schutz)     │
  │                            │                               │
  │                            ├── Speichere in Session:       │
  │                            │   state, code_verifier, nonce │
  │                            │                               │
  │◄── 302 Redirect ──────────┤                               │
  │    Location: keycloak.     │                               │
  │    example.com/auth?       │                               │
  │    response_type=code&     │                               │
  │    client_id=framework&    │                               │
  │    redirect_uri=           │                               │
  │    /auth/callback/oidc&    │                               │
  │    scope=openid+email+     │                               │
  │    profile&                │                               │
  │    state=...&              │                               │
  │    code_challenge=...&     │                               │
  │    code_challenge_method=  │                               │
  │    S256&                   │                               │
  │    nonce=...               │                               │
  │                            │                               │
  ├── User meldet sich an ────────────────────────────────────►│
  │                            │                               │
  │◄── 302 Redirect ──────────────────────────────────────────┤
  │    Location: /auth/        │                               │
  │    callback/oidc?          │                               │
  │    code=AUTH_CODE&         │                               │
  │    state=...               │                               │
  │                            │                               │
  ├── GET /auth/callback/ ────►│                               │
  │    oidc?code=...&          │                               │
  │    state=...               │                               │
  │                            ├── 1. state validieren         │
  │                            │                               │
  │                            ├── 2. Token Exchange: ────────►│
  │                            │   POST /token                 │
  │                            │   grant_type=                 │
  │                            │   authorization_code          │
  │                            │   code=AUTH_CODE              │
  │                            │   code_verifier=...           │
  │                            │   redirect_uri=...            │
  │                            │                               │
  │                            │◄── id_token + access_token ──┤
  │                            │                               │
  │                            ├── 3. id_token validieren:     │
  │                            │   - Signatur (JWKS vom IdP)   │
  │                            │   - iss, aud, exp, nonce      │
  │                            │                               │
  │                            ├── 4. User-Mapping             │
  │                            │   (siehe Abschnitt 4.3)       │
  │                            │                               │
  │                            ├── 5. Internen JWT ausstellen  │
  │                            │   (Token Service, Schicht 3)  │
  │                            │                               │
  │◄── Set-Cookie: refresh ────┤                               │
  │◄── JSON: { access_token }──┤                               │
  │                            │                               │
```

#### IdP-Konfiguration

Jeder OIDC-IdP wird über eine Konfiguration registriert:

```php
class OidcProviderConfig
{
    public string $identifier;       // 'keycloak', 'azure-ad'
    public string $displayName;      // 'Anmelden mit Firmen-SSO'
    public string $issuer;           // 'https://keycloak.example.com/realms/main'
    public string $clientId;         // 'framework-client'
    public string $clientSecret;     // Verschlüsselt gespeichert
    public string $redirectUri;      // 'https://app.example.com/auth/callback/oidc'
    public array $scopes;            // ['openid', 'email', 'profile']
    public string $userMappingField; // Welches IdP-Claim für das Mapping nutzen
                                     // z.B. 'email', 'preferred_username', 'sub'
}
```

Die Discovery der OIDC-Endpoints (authorization_endpoint, token_endpoint, jwks_uri, etc.) erfolgt automatisch über das OpenID Connect Discovery-Dokument unter `{issuer}/.well-known/openid-configuration`. Dieses wird gecacht (TTL z.B. 24h).

#### IdP-Konfiguration in der Datenbank

```sql
CREATE TABLE idp_configurations (
    id              SERIAL PRIMARY KEY,
    identifier      VARCHAR(50) UNIQUE NOT NULL,    -- 'keycloak'
    display_name    VARCHAR(100) NOT NULL,
    protocol        VARCHAR(20) NOT NULL,           -- 'oidc', 'saml', 'ldap'
    issuer_url      VARCHAR(500),
    client_id       VARCHAR(200),
    client_secret   TEXT,                           -- Verschlüsselt (AES-256-GCM)
    scopes          VARCHAR(500) DEFAULT 'openid email profile',
    user_mapping_field VARCHAR(50) DEFAULT 'email',
    enabled         BOOLEAN DEFAULT true,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);
```

### Konkreter Provider: LocalProvider

Der LocalProvider übernimmt den klassischen Username/Passwort-Login. Er nutzt die bestehende Credential-Prüfung des Frameworks, stellt aber statt einer Session eine `AuthenticatedIdentity` bereit:

```php
class LocalProvider implements IdentityProviderInterface
{
    public function authenticate(LoginRequest $request): AuthenticatedIdentity
    {
        // 1. Bestehende Credential-Prüfung aufrufen
        $user = $this->userRepository->findByUsername($request->username);
        if (!$user || !$this->passwordHasher->verify($request->password, $user->passwordHash)) {
            throw new AuthenticationException('Invalid credentials');
        }

        // 2. AuthenticatedIdentity zurückgeben
        return new AuthenticatedIdentity(
            providerIdentifier: 'local',
            externalSubject: (string) $user->id,
            email: $user->email,
            displayName: $user->displayName,
            idpClaims: [],
            mappedUserId: $user->id,     // Sofort gemappt, ist ja lokal
            mappedOrgId: $user->orgId,
        );
    }
}
```

### 4.3 User-Mapping (Externe Identität → Interner User)

Das Mapping ist die Brücke zwischen der Welt des externen IdP und der internen User-Verwaltung. Es wird nur bei OIDC/externen Logins gebraucht.

#### Mapping-Tabelle

```sql
CREATE TABLE user_identity_links (
    id                SERIAL PRIMARY KEY,
    user_id           INT NOT NULL REFERENCES users(id),
    idp_identifier    VARCHAR(50) NOT NULL,           -- 'keycloak', 'azure-ad'
    external_subject  VARCHAR(255) NOT NULL,           -- sub-Claim vom IdP
    email_at_linking  VARCHAR(255),                    -- Zur Nachvollziehbarkeit
    linked_at         TIMESTAMP DEFAULT NOW(),
    last_login_at     TIMESTAMP,

    UNIQUE(idp_identifier, external_subject)           -- Ein ext. User = ein Mapping
);
```

#### Mapping-Strategien

```
OIDC-Login kommt rein mit: sub="abc123", email="max@firma.de"
    │
    ├── 1. Prüfe user_identity_links:
    │      SELECT user_id FROM user_identity_links
    │      WHERE idp_identifier = 'keycloak'
    │      AND external_subject = 'abc123'
    │   └─ Gefunden? → User-ID steht fest. Fertig.
    │
    ├── 2. Kein Link vorhanden → Erstverknüpfung:
    │      Suche internen User anhand konfigurierbarem Feld:
    │      SELECT id FROM users
    │      WHERE email = 'max@firma.de'
    │   └─ Gefunden? → Link erstellen, User-ID steht fest.
    │
    └── 3. Kein interner User gefunden:
           ├── Option A: Fehler → "Kein Konto verknüpft.
           │              Bitte Administrator kontaktieren."
           └── Option B: Auto-Provisioning (Ausblick,
                         nicht in der BA implementiert)
```

**Bewusste Entscheidung:** Kein Auto-Provisioning im Scope der Bachelorarbeit. User müssen im Framework existieren und werden manuell oder über bestehende Prozesse angelegt. Das Mapping verknüpft nur. Das hält den Scope sauber und vermeidet Fragen wie: "Welche Permissions bekommt ein auto-provisionierter User?"

---

## 5. Schicht 3: Token Service

### Aufgabe

Nimmt eine `AuthenticatedIdentity` entgegen und stellt ein Token-Paar aus: einen kurzlebigen Access JWT und einen langlebigen Refresh Token.

### 5.1 Access JWT (Stateless)

#### Aufbau

```
Header:
{
    "alg": "EdDSA",         // Ed25519 (wie in der Vorarbeit)
    "typ": "JWT",
    "kid": "key-2026-02"    // Key-ID für Rotation
}

Payload:
{
    "iss": "https://app.example.com",           // Issuer: das Framework
    "sub": "user:12345",                        // Interner User-Identifier
    "aud": "https://app.example.com",           // Audience
    "org": "org:678",                           // Organisations-ID
    "iat": 1740000000,                          // Issued At
    "exp": 1740000600,                          // Expires: +10 Minuten
    "nbf": 1740000000,                          // Not Before
    "jti": "550e8400-e29b-41d4-a716-446655440000", // Unique Token ID
    "auth_method": "oidc:keycloak",             // Wie wurde authentifiziert
    "scopes": ["recruitment:read", "hr:read"]   // Grobe Zugriffs-Scopes
                                                // (optional, siehe 7.3)
}
```

#### Warum 10 Minuten Laufzeit?

Die Vorarbeit hatte 120 Sekunden (2 Minuten) – das ist in der Praxis zu kurz und erzeugt zu viele Refresh-Requests. 10 Minuten ist ein guter Kompromiss: kurz genug, dass kompromittierte Tokens schnell ablaufen, lang genug, dass der Client nicht ständig refreshen muss. In der Bachelorarbeit kann man verschiedene Laufzeiten evaluieren und die Trade-offs analysieren (Sicherheit vs. Performance vs. UX).

### 5.2 Refresh Token (Stateful)

Der Refresh Token ist **kein JWT**, sondern ein opaker, zufällig generierter String, dessen Zustand in der Datenbank gespeichert wird.

#### Warum kein JWT als Refresh Token?

- Refresh Tokens müssen revocable sein (z.B. bei Logout, bei Kompromittierung)
- Das geht nur mit serverseitigem Zustand
- JWTs sind per Design stateless – man müsste eine Blacklist führen, was den Vorteil zunichtemacht
- Ein opaker Token mit DB-Lookup ist hier die richtige Wahl

#### Datenbank-Schema

```sql
CREATE TABLE refresh_tokens (
    id              SERIAL PRIMARY KEY,
    token_hash      VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 Hash des Tokens
    user_id         INT NOT NULL REFERENCES users(id),
    family_id       UUID NOT NULL,                -- Für Replay Detection
    issued_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,           -- z.B. +30 Tage
    revoked_at      TIMESTAMP,                    -- NULL = aktiv
    replaced_by     INT REFERENCES refresh_tokens(id),  -- Verkettung
    client_ip       INET,                         -- Für Audit
    user_agent      VARCHAR(500),
    idp_source      VARCHAR(50)                   -- Über welchen IdP eingeloggt
);

CREATE INDEX idx_refresh_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_user ON refresh_tokens(user_id);
```

#### Refresh Token Rotation mit Replay Detection

```
Normaler Refresh-Flow:
═══════════════════════

Client          Token Service               Datenbank
  │                   │                         │
  ├── POST /auth/     │                         │
  │   refresh         │                         │
  │   { refresh_      │                         │
  │     token: RT1 }  │                         │
  │                   ├── hash(RT1) lookup ─────►│
  │                   │◄── RT1 gefunden, ────────┤
  │                   │    gültig, nicht revoked  │
  │                   │                         │
  │                   ├── RT1 als "replaced" ───►│
  │                   │    markieren              │
  │                   │                         │
  │                   ├── Neues Paar erstellen:  │
  │                   │   RT2 (gleiche family_id)│
  │                   │   + neuer Access JWT     │
  │                   │                         │
  │◄── { access_token,│                         │
  │      refresh_token:                         │
  │      RT2 }        │                         │


Replay Detection (Angriff erkannt):
════════════════════════════════════

Angreifer hat RT1 gestohlen, aber Client hat bereits
RT2 erhalten (RT1 wurde rotiert).

Angreifer       Token Service               Datenbank
  │                   │                         │
  ├── POST /auth/     │                         │
  │   refresh         │                         │
  │   { refresh_      │                         │
  │     token: RT1 }  │                         │
  │                   ├── hash(RT1) lookup ─────►│
  │                   │◄── RT1 gefunden, ABER ──┤
  │                   │    replaced_by = RT2     │
  │                   │                         │
  │                   │ ⚠️ REPLAY DETECTED!      │
  │                   │                         │
  │                   ├── ALLE Tokens mit ──────►│
  │                   │   gleicher family_id     │
  │                   │   revoken!               │
  │                   │                         │
  │◄── 401 Token ─────┤                         │
  │    reuse detected  │                         │

→ Ergebnis: Sowohl Angreifer als auch legitimer Client
  müssen sich neu einloggen. Sicher, weil der Angriff
  gestoppt wird.
```

### 5.3 Token-Ausstellungs-Endpunkte

```
POST /auth/token
    Body: { grant_type, ... }

    grant_type=password
        → LocalProvider → AuthenticatedIdentity → Token-Paar

    grant_type=authorization_code
        → OidcProvider → AuthenticatedIdentity → Token-Paar
        (der Callback-Endpunkt ruft dies intern auf)

    grant_type=refresh_token
        → Refresh Token validieren → Neues Token-Paar

POST /auth/revoke
    Body: { token, token_type_hint }
    → Refresh Token revoken (+ optional ganze Family)

POST /auth/logout
    → Alle Refresh Tokens des Users revoken
    → Optional: Access JWT jti auf Blacklist setzen
```

### 5.4 Access Token Revocation (Optional)

Für den seltenen Fall, dass ein Access JWT sofort ungültig gemacht werden muss (z.B. User wird gesperrt), gibt es eine optionale Blacklist:

```sql
CREATE TABLE token_blacklist (
    jti         UUID PRIMARY KEY,
    user_id     INT NOT NULL,
    blacklisted_at TIMESTAMP DEFAULT NOW(),
    expires_at  TIMESTAMP NOT NULL  -- Automatische Bereinigung nach JWT-Ablauf
);

-- Automatisches Cleanup (Cron oder DB-Job):
DELETE FROM token_blacklist WHERE expires_at < NOW();
```

Die Middleware prüft bei jedem Request: Ist die `jti` auf der Blacklist? Da die Liste nur kompromittierte/gesperrte Tokens enthält (nicht alle je ausgestellten), bleibt sie klein. Für noch bessere Performance kann die Blacklist in-memory gecacht werden (TTL = max. Token-Laufzeit, also 10 Minuten).

---

## 6. Schicht 4: Key Management

### 6.1 Schlüsselverwaltung

```sql
CREATE TABLE signing_keys (
    kid                 VARCHAR(50) PRIMARY KEY,    -- z.B. 'key-2026-02-a'
    algorithm           VARCHAR(10) NOT NULL,       -- 'EdDSA'
    curve               VARCHAR(10) NOT NULL,       -- 'Ed25519'
    public_key          TEXT NOT NULL,               -- Base64-encoded
    private_key_enc     TEXT NOT NULL,               -- AES-256-GCM verschlüsselt
    status              VARCHAR(20) NOT NULL,        -- 'active', 'rotated', 'revoked'
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    active_from         TIMESTAMP NOT NULL,
    rotated_at          TIMESTAMP,                   -- Wann auf 'rotated' gesetzt
    revoked_at          TIMESTAMP
);
```

#### Key-Status-Lifecycle

```
    ┌─────────┐       ┌──────────┐       ┌──────────┐
    │ ACTIVE  │──────►│ ROTATED  │──────►│ REVOKED  │
    │         │       │          │       │          │
    │ Signiert│       │ Nur noch │       │ Wird aus │
    │ neue    │       │ Verifi-  │       │ JWKS     │
    │ JWTs    │       │ kation   │       │ entfernt │
    └─────────┘       └──────────┘       └──────────┘
                       Grace Period:
                       = max. JWT-Laufzeit
                       (10 Min + Puffer)
```

**Ablauf einer Key-Rotation:**

1. Neues Schlüsselpaar generieren, Status `active`
2. Altes Schlüsselpaar auf `rotated` setzen
3. JWKS-Endpoint liefert nun beide Keys (alt + neu)
4. Neue JWTs werden mit dem neuen Key signiert (`kid` im JWT-Header)
5. Bestehende JWTs mit altem Key sind noch gültig bis sie ablaufen
6. Nach Grace Period (z.B. 15 Minuten): Alter Key auf `revoked`, aus JWKS entfernen

Es gibt immer genau **einen** Key mit Status `active`. Es kann mehrere Keys mit Status `rotated` geben (während der Grace Period).

### 6.2 JWKS-Endpoint

```
GET /.well-known/jwks.json

Response:
{
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "key-2026-03-a",
            "use": "sig",
            "x": "<Base64url-encoded public key>"
        },
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "key-2026-02-a",
            "use": "sig",
            "x": "<Base64url-encoded public key>"
        }
    ]
}
```

**Wichtig:** Der JWKS-Endpoint liefert nur Public Keys. Externe Microservices rufen diesen Endpoint auf, um JWTs verifizieren zu können – ohne jemals den Private Key zu kennen.

**Caching:** Der JWKS-Response sollte einen `Cache-Control: max-age=300` Header haben (5 Minuten). Services cachen die Keys lokal und refreshen sie, wenn ein JWT mit unbekanntem `kid` auftaucht.

---

## 7. Permission-Schnittstelle (konzeptionell)

Die Autorisierung bleibt in der Bachelorarbeit bewusst konzeptionell. Hier wird die Schnittstelle definiert, die das bestehende ABAC-System überbrückt.

### 7.1 Innerhalb des Monoliths (Ist-Zustand, bleibt)

Im Monolith ändert sich nichts an der Permission-Prüfung. Die Middleware löst den User auf, der AuthContext steht bereit, und das bestehende ABAC-System wird wie bisher In-Process aufgerufen:

```php
// Bestehender Code – bleibt UNVERÄNDERT
$authContext = $request->getAuthContext();  // Kommt jetzt aus JWT statt Session
$allowed = $permissionService->check(
    userId:   $authContext->userId,
    orgId:    $authContext->orgId,
    resource: 'recruitment:candidate:99',
    action:   'edit',
    context:  $environmentContext
);
```

Der einzige Unterschied: `$authContext` wurde früher aus der Session gelesen, jetzt aus dem JWT. Die Permission-Logik merkt davon nichts.

### 7.2 Für zukünftige Microservices (Ausblick)

Wenn ein Service herausgelöst wird, hat er keinen In-Process-Zugriff mehr auf das ABAC-System. Für diesen Fall wird eine Permission-API-Schnittstelle definiert. Dies ist ein konzeptioneller Entwurf und wird in der Bachelorarbeit nicht implementiert.

#### Option A: Zentraler Permission-Check-Endpoint

```
POST /auth/permissions/check

Request:
{
    "subject": "user:12345",
    "org": "org:678",
    "resource": "recruitment:candidate:99",
    "action": "edit",
    "context": {
        "ip": "10.0.1.50",
        "time": "2026-02-25T14:00:00Z"
    }
}

Response:
{
    "allowed": true,
    "decision_time_ms": 12,
    "cache_ttl_seconds": 60
}
```

#### Option B: Batch-Resolve für UI-Rendering

```
POST /auth/permissions/resolve

Request:
{
    "subject": "user:12345",
    "org": "org:678",
    "resource_type": "recruitment:candidate",
    "resource_id": "99"
}

Response:
{
    "permissions": [
        "candidate.view",
        "candidate.edit",
        "candidate.delete"
    ],
    "resolved_at": "2026-02-25T14:00:00Z",
    "cache_until": "2026-02-25T14:05:00Z"
}
```

### 7.3 Grobe Scopes im JWT (optionale Vorstufe)

Als Mittelweg zwischen "keine Permissions im Token" und "alle Permissions im Token" können grobe Scopes bei der Token-Ausstellung in den JWT geschrieben werden:

```
Token-Ausstellung:
    User 12345 hat Zugriff auf Module: Recruitment, HR
    → scopes: ["recruitment:read", "recruitment:write", "hr:read"]

Service-seitige Prüfung (zweistufig):
    1. Quick-Check (JWT-basiert, kein Netzwerk):
       Hat der Token den Scope "recruitment:write"?
       → NEIN: 403 Forbidden (sofort, billig)
       → JA: Weiter zu Schritt 2

    2. Fine-Grained Check (Permission-Lookup):
       Darf User 12345 Kandidat 99 editieren?
       → ABAC-System (In-Process oder API)
```

Der Vorteil: Services können offensichtlich unberechtigte Anfragen sofort ablehnen, ohne den teuren Permission-Lookup zu machen.

---

## 8. Datenbank-Gesamtschema

Zusammenfassung aller neuen Tabellen. Diese werden **neben** den bestehenden Tabellen angelegt, nicht statt ihnen.

```sql
-- ================================================
-- IDENTITY BROKER
-- ================================================

-- IdP-Konfigurationen (welche externen IdPs sind angebunden)
CREATE TABLE idp_configurations (
    id              SERIAL PRIMARY KEY,
    identifier      VARCHAR(50) UNIQUE NOT NULL,
    display_name    VARCHAR(100) NOT NULL,
    protocol        VARCHAR(20) NOT NULL,
    issuer_url      VARCHAR(500),
    client_id       VARCHAR(200),
    client_secret   TEXT,
    scopes          VARCHAR(500) DEFAULT 'openid email profile',
    user_mapping_field VARCHAR(50) DEFAULT 'email',
    enabled         BOOLEAN DEFAULT true,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- Verknüpfung: Externer IdP-User → Interner User
CREATE TABLE user_identity_links (
    id                SERIAL PRIMARY KEY,
    user_id           INT NOT NULL REFERENCES users(id),
    idp_identifier    VARCHAR(50) NOT NULL,
    external_subject  VARCHAR(255) NOT NULL,
    email_at_linking  VARCHAR(255),
    linked_at         TIMESTAMP DEFAULT NOW(),
    last_login_at     TIMESTAMP,
    UNIQUE(idp_identifier, external_subject)
);

-- ================================================
-- TOKEN SERVICE
-- ================================================

-- Refresh Tokens mit Rotation und Replay Detection
CREATE TABLE refresh_tokens (
    id              SERIAL PRIMARY KEY,
    token_hash      VARCHAR(64) NOT NULL UNIQUE,
    user_id         INT NOT NULL REFERENCES users(id),
    family_id       UUID NOT NULL,
    issued_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,
    revoked_at      TIMESTAMP,
    replaced_by     INT REFERENCES refresh_tokens(id),
    client_ip       INET,
    user_agent      VARCHAR(500),
    idp_source      VARCHAR(50)
);

CREATE INDEX idx_rt_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_rt_family ON refresh_tokens(family_id);
CREATE INDEX idx_rt_user ON refresh_tokens(user_id);
CREATE INDEX idx_rt_expires ON refresh_tokens(expires_at);

-- Optional: Access Token Blacklist (für sofortige Revocation)
CREATE TABLE token_blacklist (
    jti             UUID PRIMARY KEY,
    user_id         INT NOT NULL,
    blacklisted_at  TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL
);

-- ================================================
-- KEY MANAGEMENT
-- ================================================

-- Signatur-Schlüsselpaare mit Rotation
CREATE TABLE signing_keys (
    kid             VARCHAR(50) PRIMARY KEY,
    algorithm       VARCHAR(10) NOT NULL DEFAULT 'EdDSA',
    curve           VARCHAR(10) NOT NULL DEFAULT 'Ed25519',
    public_key      TEXT NOT NULL,
    private_key_enc TEXT NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    active_from     TIMESTAMP NOT NULL,
    rotated_at      TIMESTAMP,
    revoked_at      TIMESTAMP
);
```

---

## 9. API-Endpunkte (Übersicht)

### Authentifizierung

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| POST | `/auth/token` | Token ausstellen (grant_type: password, authorization_code, refresh_token) |
| GET | `/auth/login/oidc?idp={id}` | OIDC-Login starten (Redirect zum IdP) |
| GET | `/auth/callback/oidc` | OIDC-Callback (Authorization Code empfangen) |
| POST | `/auth/refresh` | Access Token erneuern (Refresh Token Rotation) |
| POST | `/auth/revoke` | Token widerrufen |
| POST | `/auth/logout` | Alle Tokens des Users widerrufen |

### Key Management

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET | `/.well-known/jwks.json` | Public Keys für JWT-Verifizierung (öffentlich) |

### IdP-Verwaltung (Admin)

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET | `/auth/idps` | Verfügbare IdPs auflisten (für Login-Seite) |
| GET | `/auth/idps/{id}` | IdP-Konfiguration abrufen (Admin) |
| POST | `/auth/idps` | Neuen IdP registrieren (Admin) |

### Permission (Konzeptionell / Ausblick)

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| POST | `/auth/permissions/check` | Einzelne Berechtigungsprüfung |
| POST | `/auth/permissions/resolve` | Alle Berechtigungen für eine Ressource |

---

## 10. Sicherheitsmaßnahmen

### Transport
- Alle Endpunkte ausschließlich über HTTPS
- Refresh Token als `httpOnly`, `Secure`, `SameSite=Strict` Cookie
- Access Token im `Authorization: Bearer` Header (nicht im Cookie)

### Token-Sicherheit
- Access JWT: Kurze Laufzeit (10 Min), EdDSA-Signatur, `jti` für Blacklisting
- Refresh Token: Nur Hash in DB gespeichert, Rotation bei jedem Gebrauch, Family-basierte Replay Detection
- Kein Token enthält Permissions direkt (höchstens grobe Scopes)

### OIDC-Sicherheit
- PKCE (Proof Key for Code Exchange) bei jedem Authorization Code Flow
- `state`-Parameter gegen CSRF
- `nonce` im id_token gegen Replay-Angriffe
- id_token Signatur-Validierung gegen den JWKS des IdP

### Key-Sicherheit
- Private Keys AES-256-GCM verschlüsselt in der Datenbank
- Verschlüsselungsschlüssel aus Umgebungsvariable (nicht im Code)
- Automatische Key-Rotation (konfigurierbar, z.B. monatlich)
- Grace Period bei Rotation verhindert Token-Invalidierung

### Rate Limiting
- Login-Endpunkte: Rate Limiting pro IP und pro Username
- Refresh-Endpunkt: Rate Limiting pro User
- JWKS-Endpoint: Öffentlich, aber gecacht (kein Missbrauch möglich)

---

## 11. Migrationsstrategie

### Phase 1: Auth-Komponente als paralleles System

```
Bestehende Session-Logins funktionieren weiter.
Neue /auth/* Endpunkte werden hinzugefügt.
Auth-Middleware akzeptiert sowohl Session als auch JWT.
OIDC-Provider wird angebunden (Keycloak als Demo).
```

### Phase 2: Schrittweise Umstellung interner Clients

```
Frontend wird angepasst: Login liefert JWT statt Session.
API-Endpunkte werden auf Bearer Token umgestellt.
Session-basierte Authentifizierung bleibt als Fallback.
```

### Phase 3: Externe Services und Microservices

```
Herausgelöste Services nutzen ausschließlich JWT.
JWKS-Endpoint wird ihr einziger Kontaktpunkt zur Auth.
Permission-API wird bei Bedarf implementiert.
Session-System kann perspektivisch entfernt werden.
```

---

## 12. Abgrenzung: Was gehört NICHT in die Bachelorarbeit

| Thema | Status | Begründung |
|-------|--------|------------|
| ABAC-System umbauen / Orga-Tree auflösen | Ausblick | Zu komplex, eigenständiges Projekt |
| Auto-Provisioning von externen Usern | Ausblick | Erfordert Klärung von Permission-Defaults |
| API-Gateway | Ausblick | Eigenständiges Infrastruktur-Thema |
| SAML-Provider im Identity Broker | Ausblick | SAML existiert bereits separat |
| Multi-Tenancy / mandantenfähige Token | Ausblick | Framework-spezifisch, zu viel Scope |
| Vollständige Permission-API (Implementierung) | Ausblick | Nur Interface-Definition in der BA |
| MFA (Multi-Faktor-Authentifizierung) | Ausblick | Wird an den externen IdP delegiert |

---

## 13. Technologie-Entscheidungen

| Entscheidung | Wahl | Begründung |
|---|---|---|
| JWT-Signatur | EdDSA (Ed25519) | Fortführung der Vorarbeit, performant, kompakte Signaturen |
| Refresh Token Format | Opaque (random string) | Muss revocable sein, DB-backed ist einfacher als JWT+Blacklist |
| OIDC Flow | Authorization Code + PKCE | Sicherster Flow für Browser-Clients (kein Implicit) |
| Key Storage | DB (verschlüsselt) | Kein Vault verfügbar, DB ist pragmatisch für den Anfang |
| Token-Laufzeit Access | 10 Minuten | Kompromiss: Security vs. UX (evaluieren in der BA) |
| Token-Laufzeit Refresh | 30 Tage | Üblicher Wert für Web-Apps, konfigurierbar |
| PKCE Method | S256 | SHA-256 Hash, plain ist nicht sicher |
| JWKS Caching | 5 Minuten (Cache-Control) | Kurz genug für schnelle Key-Rotation |
