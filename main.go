package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/corazawaf/coraza-caddy/v2"
	_ "github.com/mholt/caddy-ratelimit"
)

func main() {
	caddycmd.Main()
}
