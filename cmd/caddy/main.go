package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/0urr-acid/caddy-ts3-awg"
)

func main() { caddycmd.Main() }
