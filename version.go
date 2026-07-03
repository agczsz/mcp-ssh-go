package main

// version is overridden at build time via
// -ldflags "-X main.version=...". Defaults to "dev" for local builds.
var version = "dev"
