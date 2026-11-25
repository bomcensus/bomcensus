// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Command bomcensus-server is the bomcensus server with the web console and
// the built-in login. See package server for the commands and for building
// a server of your own.
package main

import "github.com/bomcensus/bomcensus/server"

func main() {
	server.Main(server.Options{Console: server.EmbeddedConsole(), Session: &server.Session{}})
}
