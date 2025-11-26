Standalone implementation of 3.2 module.

In windows, system processes can be identified by checking whether the owner user is "SYSTEM" or domain is "NT AUTHORITY".

We get the system process's path and verify whether its file on disk has a valid digital signature using WinVerifyTrust(not all system files in windows have a digital signature).
