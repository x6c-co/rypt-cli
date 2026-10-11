//go:build race && unix

package main

func init() { raceEnabled = true }
