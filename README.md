# Winject
Windows 10/11 Systemwide / Single Process DLL Injection Tool

## Injection Methods

- Single Process Injection into individual processes
- Systemwide Injection into most running processes
- Either can inject into nearly any process

 ## How to build:

  - Download winject folder
  - Open the solution in Visual
  - Build it as either x64 or ARM64 depending on the platform
  - Boom
 
## How to use:

- Open a command prompt running as administrator 
- Run winject.exe \absolute\path\dll -pid # for single mode
- Run winject.exe \absolute\path\dll for systemwide injection

DLLs must match the exe architecture, injecting x64 into ARM64 will not work and vice versa

## Warning:

This tool is provided for educational purposes only. No compiled binaries will be added to prevent abuse. By using this code, you take full responsibility for how it is used.
The developer is not responsible for any misuse, legal consequences or damages.

