# Winject
Windows 8.1/10/11 Systemwide / Single Process DLL Injection Tool

## Features

- Single Process Injection injects the DLL into individual processes specified by their PID
- Systemwide Injection injects the DLL into most running processes in parallel
- Obtains SeDebugPrivilege to enable injection into nearly any process(PPL-protected processes cannot not be injected into)


 ## How to build:

  - Download winject folder
  - Open the solution in Visual Studio
  - Build it as either x64 or ARM64 depending on the platform
  - Boom
 
## How to use:

- Open a command prompt running as administrator 
- Run winject.exe \absolute\path\dll -pid # for single mode
- Run winject.exe \absolute\path\dll for systemwide injection

DLLs must match the exe architecture, injecting x64 into ARM64 will not work and vice versa

## Tested Versions:
- Windows 8.1, x64
- Windows 10, x64
- Windows 11, ARM64

## Disclaimer:

This tool is provided for educational purposes only. No compiled binaries will be added to prevent abuse. By using this code, you take full responsibility for how it is used.
The developer is not responsible for any misuse, legal consequences or damages.

