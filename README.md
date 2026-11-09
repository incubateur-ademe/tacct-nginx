# Reverse proxy et WAF de TACCT

Pare-feu applicatif (WAF) et reverse proxy placé devant le site TACCT, hébergé sur Scalingo.

Toutes les requêtes des visiteurs passent par cette application. Elle limite le nombre de requêtes par IP, filtre les requêtes suspectes, puis transmet le reste au vrai site (variable `PRODUCTION_SITE`). Elle repose sur [Caddy](https://caddyserver.com) et le WAF [Coraza](https://coraza.io).

## Parcours d'une requête

```
Visiteur ──> Cloudflare ──> routeur Scalingo ──> cette app (Caddy) ──────────────────────────> PRODUCTION_SITE
                                                   1. rate limiting : 40 requêtes/s par IP
                                                   2. WAF Coraza : CRS OWASP + secrules.conf
                                                   3. compression gzip / zstd
                                                   4. reverse proxy
```

Le Cloudflare de l'ADEME filtre déjà certaines connexions (pays, VPN) et affiche alors une page « Accès refusé » : ces requêtes n'atteignent jamais Caddy.

Pour retrouver l'IP réelle du visiteur, Caddy fait confiance au réseau privé Scalingo et aux plages d'IP de Cloudflare (`trusted_proxies` dans le `Caddyfile`). Si Cloudflare publie de nouvelles plages sur [cloudflare.com/ips](https://www.cloudflare.com/ips/), il faut les ajouter.

## Rôle des fichiers

| Fichier         | Rôle                                                                                                                                                                                                        | À modifier ?                   |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `Caddyfile`     | Configuration du serveur : rate limiting, chargement du WAF, reverse proxy.                                                                                                                                 | Oui                            |
| `crs-setup.conf` | Réglages de la CRS propres au projet (types de contenu autorisés…), chargés avant la CRS. Écrit en SecLang, le langage de règles de ModSecurity que Coraza reprend.                                       | Oui                            |
| `secrules.conf` | Exclusions de règles CRS (faux positifs) et règles propres au projet, chargées après la CRS. Écrit en SecLang.                                                                                             | Oui                            |
| `main.go`       | Programme qui assemble Caddy avec ses deux plugins : Coraza (WAF) et caddy-ratelimit.                                                                                                                       | Rarement                       |
| `go.mod`        | Dépendances Go et leurs versions. Le premier bloc `require` liste les 3 dépendances choisies ; la longue liste marquée `// indirect` contient les dépendances de ces dépendances, ajoutées automatiquement. | Seulement pour une mise à jour |
| `go.sum`        | Empreintes qui garantissent que les dépendances téléchargées n'ont pas été modifiées.                                                                                                                       | Jamais (fichier généré)        |
| `Procfile`      | Commande de démarrage sur Scalingo : lance le binaire compilé avec le `Caddyfile`.                                                                                                                          | Rarement                       |
| `scripts/test-waf.sh` | Tests de bout en bout du WAF en prod (voir « Tester le WAF »).                                                                                                                                       | Pour ajouter un test           |

### Pourquoi des fichiers Go ?

Caddy ne charge pas de plugins au démarrage : ils doivent être compilés dans le binaire. `main.go` déclare donc « Caddy + Coraza + rate limiting ». À chaque déploiement, le buildpack Go de Scalingo compile ce programme dans le dossier `bin/`, et le `Procfile` le lance.

Pour mettre à jour les dépendances (avec Go installé en local) :

```bash
go get github.com/caddyserver/caddy/v2@latest github.com/corazawaf/coraza-caddy/v2@latest github.com/mholt/caddy-ratelimit@latest
go mod tidy
```

## Les règles du WAF

### Ordre de chargement

Coraza charge les fichiers suivants, dans cet ordre (bloc `coraza_waf` du `Caddyfile`) :

1. `@coraza.conf-recommended` : réglages du moteur (lecture du corps des requêtes, taille maximale de 12,5 Mo, rejet des corps illisibles).
2. `@crs-setup.conf.example` : réglages de la CRS (niveau de paranoïa 1, seuil de blocage 5).
3. `crs-setup.conf` : réglages de la CRS propres au projet. Il doit rester **avant** la CRS, qui n'applique ses valeurs par défaut qu'aux variables encore vides.
4. `@owasp_crs/*.conf` : les règles de l'**OWASP Core Rule Set (CRS) 4.25.0**.
5. `secrules.conf` : les exclusions et règles du projet. Il doit rester **en dernier**, car `SecRuleRemoveById` et `SecRuleUpdateTargetBy…` ne s'appliquent qu'à des règles déjà chargées.

Les fichiers qui commencent par `@` ne sont pas dans ce dépôt. Ils sont intégrés au binaire par le module Go `coraza-coreruleset` (sa version est dans `go.mod`). On peut les lire sur [GitHub](https://github.com/corazawaf/coraza-coreruleset/tree/v4.25.0/rules).

### Contenu de la CRS

La CRS est un jeu de règles génériques, maintenu par l'OWASP, qui reconnaît les attaques web courantes. Chaque règle a un niveau de paranoïa (PL) de 1 à 4 : plus il est haut, plus la règle est stricte et risque de bloquer des requêtes légitimes. Seules les règles de niveau 1 sont actives ici.

| Fichier   | Ce qu'il détecte                                                          | Règles actives (PL1)                                                                        |
| --------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| 911       | Méthodes HTTP autres que GET, HEAD, POST, OPTIONS                         | 1                                                                                           |
| 913       | Outils de scan connus (nikto, sqlmap…), repérés par leur User-Agent       | 1                                                                                           |
| 920       | Requêtes HTTP mal formées ou anormales                                    | 40                                                                                          |
| 921       | Attaques sur le protocole (request smuggling, injection d'en-têtes)       | 11                                                                                          |
| 922       | Attaques via les envois de fichiers (multipart)                           | 4                                                                                           |
| 930       | Lecture de fichiers du serveur (`../`, `/etc/passwd`)                     | 5                                                                                           |
| 931       | Inclusion de fichiers distants (URL passée en paramètre)                  | 3                                                                                           |
| 932       | Exécution de commandes système (shell, PowerShell)                        | 19                                                                                          |
| 933       | Injection de code PHP                                                     | 13                                                                                          |
| 934       | Injections génériques : Node.js, SSRF, pollution de prototype JavaScript… | 7                                                                                           |
| 941       | XSS (injection de JavaScript)                                             | 26                                                                                          |
| 942       | Injection SQL                                                             | 20                                                                                          |
| 943       | Fixation de session                                                       | 3                                                                                           |
| 944       | Attaques Java (Log4Shell, désérialisation)                                | 6                                                                                           |
| 950 à 956 | Fuites de données dans les réponses                                       | Aucune : elles analysent le corps des réponses, désactivé ici (`SecResponseBodyAccess Off`) |

Les fichiers 901, 905, 949, 959, 980 et 999 ne détectent rien : ils initialisent la CRS, calculent les scores et décident du blocage.

### Comment la CRS bloque

La CRS fonctionne par score. Chaque règle qui reconnaît une attaque ajoute des points à la requête (5 pour une attaque critique). À la fin, la règle **949110** compare le total au seuil (5) et bloque la requête s'il est atteint.

Jusqu'au 09/11/2026, `secrules.conf` retirait la règle 949110, un héritage de l'ancienne configuration nginx : la CRS détectait les attaques sans les bloquer. Ce jour-là, sur 867 requêtes réelles, 634 auraient été bloquées à tort :

| Règle | Requêtes | Cause | Correction |
| --- | --- | --- | --- |
| 942290 (injection MongoDB) | 618 | Le cookie PostHog contient `$initial_person_info` : `$in` ressemble à un opérateur MongoDB | Cookie exclu de la CRS (`secrules.conf`) |
| 920420 (type de contenu interdit) | 16 | Les Server Actions de Next.js envoient leur corps en `text/plain` | `text/plain` autorisé (`crs-setup.conf`) |

Ces deux faux positifs corrigés, le trafic réel ne déclenchait plus aucune règle CRS, et le blocage a été activé.

### Ce qui est bloqué aujourd'hui

| Requête                                                      | Réponse                                   | Origine                                             |
| ------------------------------------------------------------ | ----------------------------------------- | --------------------------------------------------- |
| Plus de 40 requêtes par seconde depuis une même IP           | 429                                       | `Caddyfile` (`rate_limit`)                          |
| Corps de requête illisible (JSON, XML ou multipart invalide) | 400                                       | `@coraza.conf-recommended`, règles 200002 et 200003 |
| Corps de requête de plus de 12,5 Mo                          | 413                                       | `@coraza.conf-recommended`                          |
| Attaque reconnue par la CRS (score d'anomalie d'au moins 5)  | 403                                       | CRS, règle 949110                                   |

### Modifier les règles

- **Ajouter une règle** (`secrules.conf`) : lui donner un ID entre 1 et 99999, la plage réservée aux règles locales.
- **Corriger un faux positif** (`secrules.conf`) : repérer dans les logs l'ID de la règle et la variable visée (`[id "942290"]`, `found within REQUEST_COOKIES:…`). Exclure de préférence la seule variable (`SecRuleUpdateTargetById 942290 "!REQUEST_COOKIES:nom"`) plutôt que toute la règle (`SecRuleRemoveById 942290`). Noter la raison en commentaire sur la ligne du dessus.
- **Changer un réglage de la CRS** (`crs-setup.conf`) : par exemple les types de contenu ou les méthodes HTTP autorisés.
- **Repasser en détection seule** (faux positifs massifs, en urgence) : décommenter `SecRuleRemoveById 949110` dans `secrules.conf` et redéployer. La CRS continue alors de journaliser, sans bloquer.

## Variables d'environnement (Scalingo)

| Variable          | Valeur                                                             |
| ----------------- | ------------------------------------------------------------------ |
| `BUILDPACK_URL`   | `https://github.com/Scalingo/go-buildpack.git`                     |
| `PRODUCTION_SITE` | URL du site TACCT, **sans `/` final** (sinon Caddy ne démarre pas) |
| `PORT`            | Fournie par Scalingo                                               |

## Déploiement

Scalingo compile l'application avec le buildpack Go à chaque déploiement : « Manual deploy » dans le dashboard, ou `git push` vers le remote Scalingo.

Si le build ou le démarrage échoue, Scalingo garde la version précédente en ligne.

## Tester le WAF

Après chaque déploiement, sans VPN et avec la CLI Scalingo connectée :

```bash
bash scripts/test-waf.sh
```

Le script envoie environ 520 requêtes sur `https://tacct.ademe.fr` : requêtes normales, attaques connues (XSS, injection SQL…), corps invalides, et une rafale de 300 requêtes. Chaque requête porte un identifiant (`waftest=<RUN>-<test>-<n>`). Le script lit ensuite les logs des apps `tacct-nginx` (WAF) et `tacct-prod`, puis affiche pour chaque test :

- les statuts vus par le WAF et par la prod, à côté du résultat attendu : une requête bloquée par le WAF n'apparaît pas dans les logs de la prod ;
- les règles Coraza déclenchées ;
- l'IP du visiteur retenue par Caddy (elle doit être égale à l'en-tête `Cf-Connecting-Ip`).

Pour relire les logs d'un test passé sans renvoyer de requêtes : `bash scripts/test-waf.sh --analyse <RUN>`.

Pour voir ce que le WAF a fait sur le vrai trafic depuis son dernier démarrage (requêtes bloquées, chemins en 403, règles CRS déclenchées) : `bash scripts/test-waf.sh --trafic`. C'est la commande à lancer après chaque modification des règles, pour repérer les faux positifs.
