Standalone implementation of 3.2 module.

# Overview

In windows, system processes can be identified by checking whether the owner user is "SYSTEM" or domain is "NT AUTHORITY".

### 1. file-memory integrity check

Integrity checks on all System32 processes in the system. We compare on-file equivalent of shellcode loaded in memory to find byte patches.

### 2. signature scans

We look for blacklisted signatures in shellcode of all System32 processes.

### 3. thread execution checks

We check whether threads of all System32 processes are running in valid memory regions.
