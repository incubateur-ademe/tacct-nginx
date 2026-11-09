# Reverse proxy et WAF de TACCT

Pare-feu applicatif (WAF) et reverse proxy placé devant le site TACCT, hébergé sur Scalingo.

Toutes les requêtes des visiteurs passent par cette application. Elle limite le nombre de requêtes par IP, filtre les requêtes suspectes, puis transmet le reste au vrai site (variable `PRODUCTION_SITE`). Elle repose sur [Caddy](https://caddyserver.com) et le WAF [Coraza](https://coraza.io).

## Parcours d'une requête

```
Visiteur ──> routeur Scalingo ──> cette app (Caddy) ──────────────────────────> PRODUCTION_SITE
                                   1. rate limiting : 40 requêtes/s par IP
                                   2. WAF Coraza : CRS OWASP + secrules.conf
                                   3. compression gzip / zstd
                                   4. reverse proxy
```

## Rôle des fichiers

| Fichier | Rôle | À modifier ? |
|---|---|---|
| `Caddyfile` | Configuration du serveur : rate limiting, chargement du WAF, reverse proxy. | Oui |
| `secrules.conf` | Règles WAF propres au projet, principalement la désactivation de règles CRS. Écrit en SecLang, le langage de règles de ModSecurity que Coraza reprend. | Oui |
| `main.go` | Programme qui assemble Caddy avec ses deux plugins : Coraza (WAF) et caddy-ratelimit. | Rarement |
| `go.mod` | Dépendances Go et leurs versions. Le premier bloc `require` liste les 3 dépendances choisies ; la longue liste marquée `// indirect` contient les dépendances de ces dépendances, ajoutées automatiquement. | Seulement pour une mise à jour |
| `go.sum` | Empreintes qui garantissent que les dépendances téléchargées n'ont pas été modifiées. | Jamais (fichier généré) |
| `Procfile` | Commande de démarrage sur Scalingo : lance le binaire compilé avec le `Caddyfile`. | Rarement |

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
3. `@owasp_crs/*.conf` : les règles de l'**OWASP Core Rule Set (CRS) 4.25.0**.
4. `secrules.conf` : les règles du projet. Ce fichier doit rester **en dernier**, car `SecRuleRemoveById` ne peut retirer qu'une règle déjà chargée.

Les fichiers qui commencent par `@` ne sont pas dans ce dépôt. Ils sont intégrés au binaire par le module Go `coraza-coreruleset` (sa version est dans `go.mod`). On peut les lire sur [GitHub](https://github.com/corazawaf/coraza-coreruleset/tree/v4.25.0/rules).

### Contenu de la CRS

La CRS est un jeu de règles génériques, maintenu par l'OWASP, qui reconnaît les attaques web courantes. Chaque règle a un niveau de paranoïa (PL) de 1 à 4 : plus il est haut, plus la règle est stricte et risque de bloquer des requêtes légitimes. Seules les règles de niveau 1 sont actives ici.

| Fichier | Ce qu'il détecte | Règles actives (PL1) |
|---|---|---|
| 911 | Méthodes HTTP autres que GET, HEAD, POST, OPTIONS | 1 |
| 913 | Outils de scan connus (nikto, sqlmap…), repérés par leur User-Agent | 1 |
| 920 | Requêtes HTTP mal formées ou anormales | 40 |
| 921 | Attaques sur le protocole (request smuggling, injection d'en-têtes) | 11 |
| 922 | Attaques via les envois de fichiers (multipart) | 4 |
| 930 | Lecture de fichiers du serveur (`../`, `/etc/passwd`) | 5 |
| 931 | Inclusion de fichiers distants (URL passée en paramètre) | 3 |
| 932 | Exécution de commandes système (shell, PowerShell) | 19 |
| 933 | Injection de code PHP | 13 |
| 934 | Injections génériques : Node.js, SSRF, pollution de prototype JavaScript… | 7 |
| 941 | XSS (injection de JavaScript) | 26 |
| 942 | Injection SQL | 20 |
| 943 | Fixation de session | 3 |
| 944 | Attaques Java (Log4Shell, désérialisation) | 6 |
| 950 à 956 | Fuites de données dans les réponses | Aucune : elles analysent le corps des réponses, désactivé ici (`SecResponseBodyAccess Off`) |

Les fichiers 901, 905, 949, 959, 980 et 999 ne détectent rien : ils initialisent la CRS, calculent les scores et décident du blocage.

### Comment la CRS bloque

La CRS fonctionne par score. Chaque règle qui reconnaît une attaque ajoute des points à la requête (5 pour une attaque critique). À la fin, la règle **949110** compare le total au seuil (5) et bloque la requête s'il est atteint.

`secrules.conf` retire la règle 949110 pour éviter les faux positifs. **La CRS détecte donc les attaques et les inscrit dans les logs, mais ne bloque rien.**

### Ce qui est bloqué aujourd'hui

| Requête | Réponse | Origine |
|---|---|---|
| Plus de 40 requêtes par seconde depuis une même IP | 429 | `Caddyfile` (`rate_limit`) |
| Corps de requête illisible (JSON, XML ou multipart invalide) | 400 | `@coraza.conf-recommended`, règles 200002 et 200003 |
| Corps de requête de plus de 12,5 Mo | 413 | `@coraza.conf-recommended` |
| Attaque reconnue par la CRS | Aucune : inscrite dans les logs seulement | CRS, sans la règle 949110 |

### Modifier les règles

Toutes les modifications se font dans `secrules.conf` :

- **Ajouter une règle** : lui donner un ID entre 1 et 99999, la plage réservée aux règles locales.
- **Corriger un faux positif** : repérer l'ID de la règle dans les logs (par exemple `[id "942100"]`), puis ajouter `SecRuleRemoveById 942100`, avec la raison en commentaire sur la ligne du dessus.
- **Faire bloquer la CRS** : supprimer la ligne `SecRuleRemoveById 949110`, après avoir corrigé les faux positifs visibles dans les logs.

## Variables d'environnement (Scalingo)

| Variable | Valeur |
|---|---|
| `BUILDPACK_URL` | `https://github.com/Scalingo/go-buildpack.git` |
| `PRODUCTION_SITE` | URL du site TACCT, **sans `/` final** (sinon Caddy ne démarre pas) |
| `PORT` | Fournie par Scalingo |

## Déploiement

Scalingo compile l'application avec le buildpack Go à chaque déploiement : « Manual deploy » dans le dashboard, ou `git push` vers le remote Scalingo.

Si le build ou le démarrage échoue, Scalingo garde la version précédente en ligne.

## Logs

```bash
scalingo --app <nom-de-l-app> logs -f
```

- **Logs d'accès Caddy** (JSON) : `status`, `client_ip` (IP réelle du visiteur), `remote_ip` (IP du routeur Scalingo).
- **Règles WAF déclenchées** : messages Coraza, avec l'ID de chaque règle (`[id "..."]`).
- **Requête bloquée par le WAF** : message `WAF rule violation detected`, avec l'URI et l'IP du visiteur.
