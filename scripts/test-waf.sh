#!/usr/bin/env bash
# Tests de bout en bout du WAF : Cloudflare -> routeur Scalingo -> Caddy/Coraza -> prod.
#
# Usage :
#   scripts/test-waf.sh [URL]            envoie les requêtes puis analyse les logs
#                                        (URL par défaut : https://tacct.ademe.fr)
#   scripts/test-waf.sh --analyse <RUN>  analyse seulement les logs d'un test passé
#   scripts/test-waf.sh --trafic         vrai trafic depuis le dernier démarrage de Caddy :
#                                        requêtes bloquées et règles CRS déclenchées
# Variables : WAF_APP (tacct-nginx), PROD_APP (tacct-prod), REGION (osc-secnum-fr1)
#
# Prérequis : curl >= 7.83, CLI scalingo connectée, AUCUN VPN (Cloudflare le bloque).
#
# Chaque requête porte "waftest=<RUN>-<test>-<n>" dans l'URL. Le script envoie environ
# 520 requêtes, puis lit les logs Scalingo des deux apps et affiche, pour chaque test,
# les statuts vus par le WAF, ceux vus par la prod, et les règles Coraza déclenchées.
set -u
WAF_APP="${WAF_APP:-tacct-nginx}"
PROD_APP="${PROD_APP:-tacct-prod}"
REGION="${REGION:-osc-secnum-fr1}"
TMP="$(mktemp -d)"
TESTS="base spoof xss sqli lfi rce scanner log4j fpposthog fptemoin fpaction json multipart big jsonvol burst"

# Mode attendu, d'après le secrules.conf local (qui doit être celui déployé) :
# détection si la règle de blocage 949110 est retirée, blocage sinon.
SECRULES="$(cd "$(dirname "$0")/.." && pwd)/secrules.conf"
if grep -q '^SecRuleRemoveById 949110' "$SECRULES" 2>/dev/null; then MODE=détection; else MODE=blocage; fi

compte() { sort | uniq -c | awk '{printf "%sx%s ", $1, $2}'; }

if [ "${1:-}" = "--trafic" ]; then
  # Vrai trafic (hors requêtes de test) depuis le dernier démarrage de Caddy
  # (déploiement ou redémarrage) : ce que le WAF a bloqué, ce que la CRS a détecté.
  scalingo --region "$REGION" --app "$WAF_APP" logs --lines 10000 2>/dev/null > "$TMP/brut.log"
  debut=$(grep 'serving initial configuration' "$TMP/brut.log" | tail -1 | cut -c1-19)
  [ -n "$debut" ] || debut=$(head -1 "$TMP/brut.log" | cut -c1-19)
  awk -v d="$debut" 'substr($0,1,19) >= d' "$TMP/brut.log" > "$TMP/waf.log"
  acces() { grep '"handled request"' "$TMP/waf.log" | grep -v 'waftest=\|rafale='; }
  echo "Depuis le dernier démarrage de Caddy : $debut -> $(tail -1 "$TMP/waf.log" | cut -c1-19)"
  echo "Requêtes réelles : $(acces | wc -l)"
  echo "== Bloquées par le WAF (réponse sans Via), par statut"
  echo "  $(acces | grep -v '"Via":\["2.0 Caddy"\]' | grep -oE '"status":(400|403|413|429)' | cut -d: -f2 | compte)"
  echo "== Requêtes 403 du WAF : chemin (10 plus fréquents)"
  acces | grep -v '"Via":\["2.0 Caddy"\]' | grep '"status":403' | grep -oE '"uri":"[^"?]*' | cut -d'"' -f4 \
    | sort | uniq -c | sort -rn | head -10
  echo "== Règles CRS déclenchées : nombre, id, message (variable visée)"
  grep 'Coraza: ' "$TMP/waf.log" | grep -v 'waftest=\|rafale=' | sed -nE \
    -e 's/.*\[id \\"([0-9]+)\\"\].*\[msg \\"([^\\]{0,50}).*found within ([A-Z_]+(:[A-Za-z_]{0,20})?).*/\1 \2 (\3)/p' -e 't' \
    -e 's/.*\[id \\"([0-9]+)\\"\].*\[msg \\"([^\\]{0,50}).*/\1 \2/p' | sort | uniq -c | sort -rn | head -20
  echo "Logs bruts : $TMP"
  exit 0
fi

if [ "${1:-}" = "--analyse" ]; then
  RUN="${2:?RUN manquant}"
else
  BASE="${1:-https://tacct.ademe.fr}"
  RUN="wt$(date +%H%M%S)"
  FORMAT='%{http_code} via=%header{via}\n'
  # /sitemap.xml : petite page qui existe. Pas /robots.txt : quand le WAF bloque,
  # Cloudflare remplace l'erreur par son propre robots.txt, servi en 200.
  # Les tests sur le User-Agent visent /waf-test (Cloudflare les bloque avant le WAF).
  CIBLE="/sitemap.xml"
  # Contenu typique du cookie PostHog (JSON encodé), qui déclenchait la 942290.
  POSTHOG='%7B%22%24initial_person_info%22%3A%7B%22r%22%3A%22%24direct%22%7D%7D'

  # run <test> <nombre> <parallélisme> <suffixe d'URL> [arguments curl...]
  # Un seul processus curl : avec plusieurs processus, les lignes de sortie
  # s'entremêlent sous Windows. Mode parallèle (-Z) seulement si parallélisme > 1 :
  # en mode parallèle, curl ignore --rate.
  # "via=2.0 Caddy" dans la réponse = la requête a traversé le WAF jusqu'à la prod.
  run() {
    local nom="$1" n="$2" par="$3" extra="$4" i; shift 4
    local cfg="$TMP/$nom.cfg" parallele=()
    [ "$par" -gt 1 ] && parallele=(-Z --parallel-max "$par")
    : > "$cfg"
    for i in $(seq 1 "$n"); do
      printf 'url = "%s"\noutput = "/dev/null"\n' "$BASE$CIBLE?waftest=$RUN-$nom-$i$extra" >> "$cfg"
    done
    printf '  %-10s ' "$nom"
    curl -s --no-progress-meter -g ${parallele[@]+"${parallele[@]}"} --max-time 60 -w "$FORMAT" "$@" -K "$cfg" 2>/dev/null \
      | sort | uniq -c | awk '{$1 = $1; printf "%s   ", $0}'
    echo
  }

  echo "RUN=$RUN ($(date '+%H:%M:%S'))  ->  $BASE  (mode attendu : $MODE)"
  echo "== Réponses reçues par curl"
  run base 3 1 ""
  run spoof 3 1 "" -H "X-Forwarded-For: 1.2.3.4"
  run xss 1 1 "&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
  run sqli 1 1 "&id=1%27%20OR%20%271%27%3D%271"
  run lfi 1 1 "&file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
  run rce 1 1 "&cmd=%3Bcat%20%2Fetc%2Fpasswd"
  CIBLE="/waf-test" run scanner 1 1 "" -A "sqlmap/1.7.2#stable (https://sqlmap.org)"
  CIBLE="/waf-test" run log4j 1 1 "" -H 'X-Api-Version: ${jndi:ldap://127.0.0.1/a}'
  # Faux positifs corrigés : ni le cookie PostHog, ni une Server Action (POST text/plain)
  # ne doivent déclencher de règle. Le témoin (même contenu, autre cookie) doit déclencher la 942290.
  run fpposthog 1 1 "" -H "Cookie: ph_phc_testwaf_posthog=$POSTHOG"
  run fptemoin 1 1 "" -H "Cookie: cookie_temoin=$POSTHOG"
  run fpaction 1 1 "" -X POST -H "Content-Type: text/plain;charset=UTF-8" --data-binary '["test"]'
  run json 1 1 "" -X POST -H "Content-Type: application/json" --data-binary '{"a":'
  run multipart 1 1 "" -X POST -H "Content-Type: multipart/form-data; boundary=xyz" \
    --data-binary $'--xyz\r\nContent-Disposition: form-data; name="a"\r\n\r\nb\r\n'
  head -c 13631488 /dev/zero | tr '\0' a > "$TMP/big.txt"
  run big 1 1 "" -X POST -H "Content-Type: text/plain" --data-binary "@$TMP/big.txt"
  # 20 req/s maximum : sous la limite de 40 req/s, pour mesurer Coraza et non le rate limiting.
  run jsonvol 200 1 "" --rate 20/s -X POST -H "Content-Type: application/json" --data-binary '{"a":'
  sleep 2
  run burst 300 50 ""
  echo "== Attente de 20 s pour l'arrivée des logs"
  sleep 20
fi

echo "== Analyse des logs Scalingo (RUN=$RUN, mode attendu : $MODE)"
scalingo --region "$REGION" --app "$WAF_APP" logs --lines 10000 2>/dev/null > "$TMP/waf.log"
scalingo --region "$REGION" --app "$PROD_APP" logs --lines 10000 2>/dev/null > "$TMP/prod.log"

attendu() {
  local attaque="200 / 200"
  [ "$MODE" = blocage ] && attaque="403 / rien"
  case "$1" in
    base|spoof) echo "200 / 200" ;;
    xss|sqli|lfi|rce) echo "$attaque + règles" ;;
    scanner|log4j) echo "- / - (403 Cloudflare)" ;;
    fpposthog) echo "200 / 200, aucune règle" ;;
    fptemoin) echo "$attaque + 942290" ;;
    fpaction) echo "405 / 405, aucune règle" ;;
    json|multipart|jsonvol) echo "400 / rien" ;;
    big) echo "413 / rien" ;;
    burst) echo "200 et 429 / 200 seuls" ;;
  esac
}
printf '  %-10s %-24s %-24s %-26s %s\n' TEST "WAF" "PROD" "ATTENDU (WAF / PROD)" "RÈGLES CORAZA"
for t in $TESTS; do
  waf=$(grep '"handled request"' "$TMP/waf.log" | grep "waftest=$RUN-$t-" | grep -oE '"status":[0-9]+' | cut -d: -f2 | compte)
  prod=$(grep "waftest=$RUN-$t-" "$TMP/prod.log" | grep -oE ' status=[0-9]+' | cut -d= -f2 | compte)
  ids=$(grep "waftest=$RUN-$t-" "$TMP/waf.log" | grep -oE '\[id \\"[0-9]+\\"\]' | grep -oE '[0-9]+' | sort -u | tr '\n' ' ')
  printf '  %-10s %-24s %-24s %-26s %s\n' "$t" "${waf:--}" "${prod:--}" "$(attendu "$t")" "$ids"
done

echo "== IP du visiteur"
echo "  spoof : $(grep '"handled request"' "$TMP/waf.log" | grep "waftest=$RUN-spoof-" | head -1 \
  | grep -oE '"client_ip":"[^"]+"|"Cf-Connecting-Ip":\["[^"]+"' | tr '\n' ' ')"
echo "          (client_ip doit être égale à Cf-Connecting-Ip, et différente de 1.2.3.4)"
echo "  rafale : $(grep '"handled request"' "$TMP/waf.log" | grep "waftest=$RUN-burst-" \
  | grep -oE '"client_ip":"[^"]+"' | sort -u | tr -d '"' | sed 's/client_ip://' | tr '\n' ' ')"
echo "          (attendu : votre IP seule, ou votre IPv4 et votre IPv6)"

debut=$(grep "waftest=$RUN-" "$TMP/waf.log" | head -1 | cut -c1-19)
fin=$(grep "waftest=$RUN-" "$TMP/waf.log" | tail -1 | cut -c1-19)
bruit=$(awk -v d="$debut" -v f="$fin" 'substr($0,1,19) >= d && substr($0,1,19) <= f && /key not found/' "$TMP/waf.log" | wc -l)
echo "== Avertissements 'key not found' entre $debut et $fin : $bruit (attendu : 0)"
echo "Logs bruts : $TMP"
