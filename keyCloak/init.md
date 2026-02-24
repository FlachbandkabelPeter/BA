# Forschungsgrundlage für die Bachelorarbeit: OIDC mit Keycloak und User-Migration

**Die Migration einer monolithischen Benutzerverwaltung zu Keycloak mit OIDC ist ein praxisrelevantes und akademisch gut fundierbares Thema, das an der Schnittstelle von Identity & Access Management, Microservice-Architektur und Software-Modernisierung liegt.** Die Forschungslage zeigt: Während formale Sicherheitsanalysen zu OAuth 2.0/OIDC hervorragend dokumentiert sind (Fett, Küsters & Schmitz, 2016/2017), existiert eine echte Forschungslücke bei der konkreten Migration von „Blob"-basierten Legacy-Userdaten zu strukturierten IAM-Systemen — genau hier kann die Arbeit einen originären Beitrag leisten. Die folgende Recherche identifiziert die zentralen theoretischen Grundlagen, praktischen Ressourcen und eine empfohlene Gliederungsstruktur für die Bachelorarbeit.

---

## 1. Keycloak als zentrale IAM-Plattform

Keycloak ist eine Open-Source Identity-and-Access-Management-Lösung unter CNCF-Stewardship (ehemals Red Hat), die OAuth 2.0, OpenID Connect und SAML 2.0 nativ unterstützt. Die aktuelle Version **26.5.4** (Februar 2026) basiert seit Version 17 auf dem Quarkus-Runtime (statt WildFly), was deutlich schnellere Startzeiten, einen kleineren Footprint und Cloud-native-Optimierungen bietet.

**Die Architektur gliedert sich in Realms** (isolierte Verwaltungseinheiten für Benutzer, Clients, Rollen und Gruppen), **Clients** (Applikationen, die Keycloak zur Authentifizierung nutzen — public, confidential oder bearer-only), **Realm- und Client-Rollen** (globale bzw. applikationsspezifische Berechtigungen), sowie **Groups** (hierarchische Benutzerkollektionen mit vererbten Attributen und Rollenmappings). Für die Thesis besonders relevant ist Keycloaks Fähigkeit als **Identity Broker**: Es kann externe Identity Provider (SAML, OIDC, LDAP) einbinden und gleichzeitig als zentrale Authentifizierungsstelle für Microservices fungieren.

### User Storage SPI als Schlüssel zur Migration

Der **User Storage SPI (Service Provider Interface)** ist das zentrale Werkzeug für die Migration von Legacy-Userdaten. Er ermöglicht es, externe Benutzerdatenbanken in Keycloak zu integrieren, ohne eine sofortige Vollmigration durchzuführen. Der Lookup-Flow funktioniert dreistufig: Keycloak prüft zuerst den Infinispan-Cache, dann die lokale Datenbank und iteriert schließlich über konfigurierte SPI-Provider. Für die Implementierung werden mindestens `UserLookupProvider` und `CredentialInputValidator` benötigt; der Provider wird als JAR in `/opt/keycloak/providers/` deployt.

Zwei Strategien stehen zur Verfügung: **Import** (Benutzer werden bei Erstanmeldung in Keycloaks lokale DB kopiert — empfohlen für die Thesis) und **Federation** (Benutzer verbleiben ausschließlich im externen Store). Das etablierteste Open-Source-Plugin ist **daniel-frak/keycloak-user-migration** (GitHub), das ein REST-API-basiertes Migrationsmodell implementiert: Das Legacy-System exponiert GET- (Benutzerdaten) und POST-Endpoints (Passwortvalidierung), und der Keycloak-Provider migriert Benutzer transparent bei der ersten Anmeldung.

Für den konkreten Blob-Fall empfiehlt sich ein **REST-Facade-Service** (in PHP oder Java), der den Blob deserialisiert, Benutzerfelder extrahiert und als standardisierte Endpunkte bereitstellt. Weitere relevante Implementierungen: Niko Köbler's SPI-Demo (`dasniko/keycloak-user-spi-demo`), Smartling's Zero-Downtime-Ansatz und Inventage/Novatec Custom-User-Storage-Beispiele.

### LDAP-Federation und Organizations

Keycloaks eingebauter LDAP/AD-Provider unterstützt OpenLDAP, Active Directory und weitere Verzeichnisdienste mit konfigurierbaren Edit-Modes (READ_ONLY, WRITABLE, UNSYNCED), **LDAP-Mappern** für Attribute, Gruppen und Rollen sowie periodischer oder On-Demand-Synchronisation. Passwörter werden nie importiert — die Validierung erfolgt immer gegen den LDAP-Server.

Die **Organizations-Feature** (GA seit Keycloak 26) ist direkt auf den Use-Case der Thesis zugeschnitten: Organisationen als First-Class-Entities innerhalb eines Realms, mit Benutzermitgliedschaften, domänenbasiertem IdP-Routing und Identity-First-Login-Flows. Als Alternative steht die ausgereiftere Phase Two Extension (`p2-inc/keycloak-orgs`) mit zusätzlichen Features wie organisationsspezifischen Rollen und Einladungen zur Verfügung.

---

## 2. OIDC, OAuth 2.0 und der Weg weg von SAML

### Protokollgrundlagen und aktuelle Standards

OpenID Connect ist eine Identity-Schicht auf OAuth 2.0, die JSON/REST-basierte Nachrichten und JWT als Token-Format nutzt. Der **Authorization Code Flow mit PKCE** ist seit OAuth 2.1 (Draft, Oktober 2025) und **RFC 9700** (Security Best Current Practice, Januar 2025) der universell empfohlene Flow. Die wichtigsten RFCs für die Thesis:

- **RFC 6749** (OAuth 2.0 Core), **RFC 7636** (PKCE), **RFC 7519** (JWT)
- **RFC 9700** (Security BCP, Januar 2025 — ersetzt RFC 6819)
- **OAuth 2.1 Draft** (draft-ietf-oauth-v2-1-14): Entfernt Implicit Grant und ROPC, erzwingt PKCE für alle Flows
- **OpenID Connect Core 1.0** (openid.net/specs/openid-connect-core-1_0.html)

### SAML vs. OIDC — warum migrieren?

| Aspekt | SAML 2.0 | OIDC |
|--------|----------|------|
| **Einführung** | 2005 | 2014 |
| **Datenformat** | XML/SOAP | JSON/REST |
| **Token-Format** | XML-Assertion | JWT |
| **Mobile/SPA-Support** | Schlecht | Hervorragend |
| **API-Schutz** | Nicht designt | Kernfunktion |
| **Developer Experience** | Komplex | Einfach |
| **Discovery** | Metadata-XML | `.well-known/openid-configuration` |

**Keycloak fungiert als SAML-zu-OIDC-Bridge**: Legacy-Applikationen können weiterhin als SAML-Clients angebunden bleiben, während neue Microservices OIDC nutzen — beide teilen dieselbe Keycloak-SSO-Session. Dies ermöglicht eine schrittweise Migration ohne Downtime. Der Univention Migration Guide (SimpleSAMLPHP zu Keycloak) dokumentiert einen konkreten Schritt-für-Schritt-Prozess.

### Token-basierte Authentifizierung in Microservices

In einer Microservice-Architektur authentifizieren sich Benutzer bei Keycloak und erhalten **JWT Access Tokens**, die jeder Microservice eigenständig validieren kann. Die empfohlene Methode ist **lokale Validierung** über den JWKS-Endpoint (`/realms/{realm}/protocol/openid-connect/certs`) — keine Netzwerk-Calls pro Request nötig. Rollen sind im JWT unter `realm_access.roles` und `resource_access.{client}.roles` verfügbar. Für die PHP-Integration stehen `jumbojett/OpenID-Connect-PHP` und `league/oauth2-client` mit dem Keycloak-Provider (`stevenmaguire/oauth2-keycloak`) zur Verfügung.

### Akademische Sicherheitsanalysen als theoretisches Fundament

Die Arbeiten von **Fett, Küsters & Schmitz** bilden das Fundament für die formale Sicherheitsbetrachtung: Ihre „Comprehensive Formal Security Analysis of OAuth 2.0" (ACM CCS 2016, arXiv:1601.01229) entdeckte vier Angriffe inklusive des IdP-Mix-Up-Attacks und bewies die Sicherheit des korrigierten Protokolls. Die Folgearbeit „The Web SSO Standard OpenID Connect: In-Depth Formal Security Analysis" (IEEE CSF 2017, arXiv:1704.08539) ist die erste tiefgreifende formale Analyse von OIDC und identifiziert OIDC-spezifische Angriffsvektoren (SSRF via Discovery, Injection-Attacks). Diese Papers sind **essenziell** für das Theorie-Kapitel der Bachelorarbeit.

---

## 3. Migrationsmuster vom Monolith zum Microservice

### Strangler Fig Pattern als Leitkonzept

Das von Martin Fowler 2004 eingeführte **Strangler Fig Pattern** ist das zentrale Migrationsmuster für die Thesis. Die Kernidee: „Gradually create a new system around the edges of the old, letting it grow slowly until the old system is strangled." Zhamak Dehghani (Thoughtworks) empfiehlt auf martinfowler.com explizit, den **Authentication-Service als ersten Microservice zu extrahieren**: „The first service can be the 'end user authentication' service that the monolith could call to authenticate the end users."

Der konkrete Ablauf für die Thesis: Ein API-Gateway/Proxy fängt Auth-Requests ab und routet sie entweder zum Monolithen oder zu Keycloak. Die atomaren Schritte sind: (1) Auth-Service bauen (Keycloak deployen), (2) neuen Authentifizierungspfad im Monolith-Backend einführen, (3) alten Session-basierten Auth-Pfad ersetzen, (4) alten Code deaktivieren.

### Ergänzende Migrationsmuster

- **Anti-Corruption Layer (ACL)**: Aus Eric Evans' DDD stammend — eine Übersetzungsschicht zwischen dem PHP-Monolithen-Benutzermodell (Blob) und Keycloaks standardisiertem Identitätsmodell. **Unverzichtbar** für die Thesis.
- **Branch by Abstraction**: Arbeitet *innerhalb* des Monolithen (im Gegensatz zum Strangler Fig, der von *außen* wirkt). Nützlich, wenn Auth-Logik tief im Monolith eingebettet ist.
- **Parallel Run**: Beide Systeme werden gleichzeitig aufgerufen; Ergebnisse verglichen, aber nur eines ist autoritativ. Für die Verifizierungsphase relevant.
- **Database per Service**: Keycloak erhält eine eigene PostgreSQL-Datenbank; Legacy-Blob-Daten werden schrittweise migriert.

### Schlüsselliteratur für Migrationsmuster

Drei Bücher bilden das Fundament: **Sam Newman's „Monolith to Microservices"** (O'Reilly, 2019) behandelt Strangler Fig, Branch by Abstraction, Parallel Run und Database-Decomposition in den Kapiteln 3–5 — das **primäre Referenzwerk**. **Chris Richardson's „Microservices Patterns"** (Manning, 2018) bietet 44 wiederverwendbare Patterns, davon Kapitel 13 explizit zu Refactoring (2. Auflage als MEAP verfügbar). **Eric Evans' „Domain-Driven Design"** (2003) liefert die Grundlage für Bounded-Context-Identifikation und Anti-Corruption Layer.

Akademisch relevant ist die systematische Review von **Abgaz et al. (2023)**: „Decomposition of Monolith Applications Into Microservices Architectures" (IEEE TSE), die 35 Papers analysiert und das M2MDF-Framework einführt. **Li, Ma & Lu (2020)** dokumentieren die praktische Anwendung des Strangler Fig Pattern mit DDD auf das Green Button System (IEEE ICS). Weitere relevante Surveys: Velepucha & Flores (2023, IEEE Access), Fritzsch et al. (2018, arXiv:1807.10059), Wolfart et al. (2021, EASE).

---

## 4. Zugriffssteuerungsmodelle und die ReBAC-Perspektive

### Von RBAC über ABAC zu ReBAC

Keycloak implementiert nativ **RBAC** (Realm-Rollen, Client-Rollen, Composite Roles, Groups) gemäß dem NIST-RBAC-Modell (ANSI/INCITS 359-2004). Die Keycloak Authorization Services erweitern dies um **ABAC**-Fähigkeiten (JavaScript-basierte Policies, die Benutzerattribute, Ressourcenattribute und Kontext evaluieren), bleiben aber relativ basic.

**ReBAC (Relationship-Based Access Control)** ist die interessanteste Erweiterungsperspektive für das optionale Kapitel der Thesis. Das Konzept geht auf **Googles Zanzibar-Paper** (Pang et al., USENIX ATC 2019) zurück, das ein globales Autorisierungssystem beschreibt, welches **Billionen von ACLs** mit **<10ms p95-Latenz** bei 99,999% Verfügbarkeit verwaltet. Das Datenmodell basiert auf Relation Tuples (`namespace:object#relation@subject`).

Open-Source-Implementierungen wie **OpenFGA** (CNCF Sandbox, Auth0/Okta), **SpiceDB** (AuthZed) und **Permify** machen ReBAC praktisch zugänglich. Besonders relevant für die Thesis: Martin Besozzi's `keycloak-openfga-event-publisher` SPI-Extension, die Keycloak-Admin-Events (Rollenzuweisungen, Gruppenmitgliedschaften) automatisch in OpenFGA-Tuples konvertiert. Die Architektur: Keycloak (AuthN + Identity Model) → OpenFGA (AuthZ / ReBAC) → Applikation (PEP).

| Kriterium | RBAC | ABAC | ReBAC |
|-----------|------|------|-------|
| **Komplexität** | Niedrig | Hoch | Mittel-Hoch |
| **Granularität** | Grob | Fein | Fein |
| **Kontextbewusst** | Nein | Ja | Teilweise |
| **Beziehungen** | Nein | Begrenzt | Exzellent |
| **Keycloak-Support** | Nativ | Über Auth Services | Via OpenFGA |

**Empfohlener Evolutionspfad**: Mit RBAC starten (Keycloak-nativ), ABAC-Bedingungen über Authorization Services hinzufügen, dann OpenFGA für ReBAC integrieren, wenn beziehungsbasierte Autorisierung benötigt wird.

---

## 5. User-Migrationsstrategien für den Blob-Fall

### Drei Strategien im Vergleich

| Strategie | Downtime | Risiko | Vollständigkeit | Legacy-Abhängigkeit |
|-----------|----------|--------|-----------------|---------------------|
| **Lazy (SPI)** | Keine | Niedrig | Unvollständig (inaktive User) | Muss weiterlaufen |
| **Big Bang (Bulk-API)** | Ja (Stunden) | Hoch | Vollständig | Kann abgeschaltet werden |
| **Hybrid (Bulk + Lazy)** | Minimal | Mittel-Niedrig | Vollständig | Temporär |

Für die Thesis wird der **Hybrid-Ansatz** empfohlen: Zunächst alle Benutzerkonten via Keycloak Admin-API bulk-migrieren (inklusive gehashter Passwörter über Custom `PasswordHashProvider` SPI), dann den Lazy-Migration-SPI als Fallback für verpasste Benutzer einsetzen. Die Migration sollte organisationsweise phasenweise erfolgen.

### Kritische Herausforderung: Passwort-Hash-Migration

Keycloak unterstützt nativ PBKDF2-SHA256/512. Für PHP-typische Hashes (bcrypt via `password_hash`, MD5, SHA-512) müssen **Custom PasswordHashProvider-SPIs** implementiert werden. Etablierte Plugins: `leroyguillaume/keycloak-bcrypt`, Inventage's `keycloak-password-hashprovider-extension` (Argon2, bcrypt). **Wichtig**: Keycloak rehashed Passwörter automatisch beim nächsten Login auf den konfigurierten Policy-Algorithmus.

### Blob-Deserialisierung als originärer Beitrag

Die spezifische Migration von PHP-serialisierten Benutzerdaten (Blobs) zu Keycloaks strukturiertem Modell ist in der akademischen Literatur **nicht dokumentiert** — dies stellt eine echte Forschungslücke und damit einen originären Beitrag der Thesis dar. Der Prozess: PHP-Script deserialisiert Blobs → extrahiert Benutzerfelder → transformiert zu Keycloak-Attributen → exponiert als REST-Endpunkte für den User Storage SPI.

---

## 6. Empfohlene Gliederung der Bachelorarbeit

### Vorgeschlagene Struktur

**1. Einleitung** (ca. 5 Seiten)
- Motivation und Problemstellung
- Zielsetzung und Forschungsfragen
- Abgrenzung des Scopes
- Methodisches Vorgehen
- Aufbau der Arbeit

**2. Theoretische Grundlagen** (ca. 20–25 Seiten)
- 2.1 Authentifizierung und Autorisierung: Grundbegriffe
- 2.2 OAuth 2.0 und OpenID Connect (Spezifikationen, Flows, Token-Typen)
- 2.3 SAML 2.0 im Vergleich zu OIDC (Migrationsszenarien)
- 2.4 Token-basierte Authentifizierung in Microservice-Architekturen (JWT, JWKS)
- 2.5 Zugriffssteuerungsmodelle (RBAC, ABAC, ReBAC)
- 2.6 Keycloak als IAM-Plattform (Architektur, Realm-Design, User Storage SPI)
- 2.7 Monolith-zu-Microservice-Migration (Strangler Fig, Anti-Corruption Layer, DDD)
- 2.8 User-Migrationsstrategien (Lazy, Big Bang, Hybrid)

**3. Ist-Analyse** (ca. 10–12 Seiten)
- 3.1 Architekturüberblick des bestehenden Systems
- 3.2 Analyse der aktuellen Benutzerverwaltung (Blob-Struktur, LDAP, Gruppen, Berechtigungen)
- 3.3 SAML-Integration und bestehende Identitäten
- 3.4 Organisationsstruktur im Legacy-System
- 3.5 Identifizierte Schwachstellen und Migrationsmotivation

**4. Konzeption** (ca. 12–15 Seiten)
- 4.1 Anforderungsanalyse (funktional und nicht-funktional)
- 4.2 Zielarchitektur mit Keycloak als Identity Service
- 4.3 Realm-Design und Organisationsmapping
- 4.4 Migrationsstrategie (Hybrid: Bulk + Lazy Migration via User Storage SPI)
- 4.5 OIDC-Integrationskonzept für den PHP-Monolithen
- 4.6 Containerisierungsstrategie (Docker/Kubernetes)

**5. Implementierung** (ca. 15–18 Seiten)
- 5.1 Keycloak-Deployment (Docker-Setup, Konfiguration)
- 5.2 Realm- und Client-Konfiguration
- 5.3 User Storage SPI: Blob-Deserialisierung und REST-Facade
- 5.4 LDAP-Federation-Konfiguration
- 5.5 OIDC-Integration in die PHP-Applikation
- 5.6 Passwort-Hash-Migration
- 5.7 Organisationen in Keycloak abbilden

**6. Evaluation und Ergebnisse** (ca. 8–10 Seiten)
- 6.1 Funktionale Tests der Migration
- 6.2 Performance-Bewertung
- 6.3 Sicherheitsbetrachtung
- 6.4 Vergleich Ist- vs. Soll-Zustand

**7. Ausblick: Verbesserung der Zugriffssteuerung mit ReBAC** (ca. 5–8 Seiten, optional)
- 7.1 Limitierungen des aktuellen RBAC-Modells
- 7.2 ReBAC-Konzept mit OpenFGA
- 7.3 Keycloak-OpenFGA-Integrationsarchitektur

**8. Fazit** (ca. 3 Seiten)

---

## 7. Kernliteratur und Suchstrategie

### Die 10 wichtigsten Quellen

1. **Fett, Küsters & Schmitz (2016)** — „A Comprehensive Formal Security Analysis of OAuth 2.0" — ACM CCS, arXiv:1601.01229
2. **Fett, Küsters & Schmitz (2017)** — „The Web SSO Standard OpenID Connect: In-Depth Formal Security Analysis" — IEEE CSF, arXiv:1704.08539
3. **Newman, S. (2019)** — *Monolith to Microservices* — O'Reilly (Strangler Fig, Branch by Abstraction)
4. **Newman, S. (2021)** — *Building Microservices* (2. Aufl.) — O'Reilly
5. **Richardson, C. (2018)** — *Microservices Patterns* — Manning (44 Patterns)
6. **Pang et al. (2019)** — „Zanzibar: Google's Consistent, Global Authorization System" — USENIX ATC
7. **Chatterjee & Prinz (2022)** — „Applying Spring Security with KeyCloak-Based OAuth2 to Protect Microservice APIs" — Sensors 22(5)
8. **Abgaz et al. (2023)** — „Decomposition of Monolith Applications Into Microservices" — IEEE TSE
9. **NIST SP 800-162** — Guide to ABAC (Hu, Ferraiolo, Kuhn)
10. **RFC 9700** (Jan. 2025) — OAuth 2.0 Security Best Current Practice

### Empfohlene Suchbegriffe für die eigene Recherche

**Google Scholar (Englisch):**
- `"Keycloak" "user federation" OR "user storage SPI" migration`
- `"OpenID Connect" formal security analysis`
- `"strangler fig" pattern microservice migration`
- `"monolith decomposition" "identity management"`
- `"relationship-based access control" OR "ReBAC" Zanzibar`
- `"OAuth 2.0" "SAML" comparison migration`
- `"token-based authentication" microservices JWT`
- `"legacy authentication" migration OIDC`

**Google Scholar (Deutsch):**
- `Keycloak Bachelorarbeit OIDC Implementierung`
- `Monolith Microservice Migration Muster`
- `Zugriffskontrolle RBAC ABAC Vergleich`
- `Identitätsmanagement Migration Legacy-System`

**IEEE Xplore:**
- `monolith decomposition microservice architecture`
- `Keycloak identity microservice OAuth`

**arXiv:**
- `OAuth 2.0 security` / `OpenID Connect formal analysis`
- `microservice migration patterns`

### Weitere akademische Papers nach Themenfeld

**Keycloak-spezifisch:** Gamayanto et al. (2025) — Keycloak RBAC Evaluation mit OWASP ASVS; Voicu et al. (2024) — University IAM mit Keycloak; Venčkauskas et al. (2023) — Token-Based Access Control in Microservices.

**Monolith-Migration:** Li, Ma & Lu (2020) — Strangler Fig Pattern Case Study (IEEE ICS); Velepucha & Flores (2023) — Microservice Architecture Survey (IEEE Access); Fritzsch et al. (2018) — Classification of Refactoring Approaches (arXiv:1807.10059); Di Francesco, Lago & Malavolta (2018) — Industrial Migration Survey (IEEE ICSA); Wolfart et al. (2021) — Legacy Modernization Roadmap (EASE).

**Zugriffskontrolle:** Aftab et al. (2022) — Traditional and Hybrid Access Control Models Survey (Wiley); Golightly et al. (2023) — Empirical Security Analysis of Access Control (ACM Computing Surveys); CEUR Vol. 3702 Paper 22 (2024) — RBAC/ABAC/ReBAC Paradigm Comparison.

---

## 8. Identifizierte Forschungslücken und Beitragspotenzial

Die Recherche zeigt vier klare Lücken, die die Thesis adressieren kann. **Erstens** ist die Migration von serialisierten Blob-Benutzerdaten zu strukturierten IAM-Systemen akademisch nicht dokumentiert — hier liegt das größte Potenzial für einen originären Beitrag. **Zweitens** fokussiert die existierende Migrationsliteratur fast ausschließlich auf Java-Ökosysteme; PHP-spezifische Monolith-zu-Microservice-Migration mit Keycloak ist unterrepräsentiert. **Drittens** ist die Kombination von Identity-Management-Extraktion im Kontext von Monolith-Modernisierung akademisch schwach abgedeckt — die meisten Papers behandeln Code-Decomposition und Datenbank-Splitting, nicht Authentifizierungssystem-Migration. **Viertens** ist die Integration von Keycloak mit ReBAC-Systemen wie OpenFGA ein emerging topic mit minimaler akademischer Abdeckung.

Die Thesis sollte diese Lücken ehrlich benennen und als Motivation für den eigenen Beitrag nutzen. Ein pragmatischer Mix aus Peer-Reviewed-Literatur (OAuth/OIDC-Sicherheit, Migrationsmuster), Fachbüchern (Newman, Richardson, Evans), offizieller Dokumentation (Keycloak, RFCs) und qualitativ hochwertiger Grey Literature (Fowler's Blog, Keycloak GitHub, Community-Plugins) ist für eine Bachelorarbeit dieser Ausrichtung sowohl angemessen als auch unvermeidlich.

---

## Schlussbetrachtung: Praktische Empfehlungen für den Scope

Die 11-wöchige Praxisphase sollte sich auf drei Kernziele konzentrieren: **(1)** Keycloak-Deployment mit Docker und Konfiguration eines Realms inklusive LDAP-Federation und Organizations-Mapping, **(2)** Implementierung eines Custom User Storage SPI mit REST-Facade zur Blob-Deserialisierung und Lazy Migration, und **(3)** OIDC-Integration in den PHP-Monolithen über `jumbojett/OpenID-Connect-PHP` oder das League-Ökosystem. Das optionale ReBAC-Konzept (Kapitel 7 der Gliederung) mit OpenFGA-Integration kann als Ausblick konzipiert werden, ohne volle Implementierung — die Keycloak-OpenFGA-Workshop-Materialien von Martin Besozzi bieten dafür eine exzellente Grundlage.

Der Scope ist ambitioniert, aber mit dem Hybrid-Migrationsansatz, den verfügbaren Open-Source-Plugins und der klaren Gliederungsstruktur in 20 Wochen realistisch umsetzbar. Die stärkste Differenzierung liegt im Blob-zu-Keycloak-Migrationspfad — dieser sollte methodisch sauber dokumentiert werden, da er eine genuine praktische und wissenschaftliche Lücke füllt.
