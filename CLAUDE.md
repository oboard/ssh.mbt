# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a MoonBit SSH client library entry for the MoonBit 2026 Open Source Competition. The project aims to implement SSH protocol support for the MoonBit ecosystem.

## Commands

MoonBit project commands:
- `moon build --target native` - Build the project
- `moon test --target native` - Run tests
- `moon add <package>` - Add a dependency
- `moon fmt` - Format code
- `moon run cmd/main --target native` - Run the main program

## Architecture

The project follows this structure:
- `cmd/main/main.mbt` - Main program entry point
- `ssh_client.mbt` - Library code
- `ssh_client_test.mbt` - Tests

Currently the transport layer is being implemented with TCP connection support as the foundation for SSH protocol.

## Skills

The `moonbitlang` skill is available for MoonBit development tasks:
- Use when working with MoonBit language features, packages, or tooling
- Invoke via `/moonbitlang` or relevant slash commands

Skill repository: https://github.com/moonbitlang/skills