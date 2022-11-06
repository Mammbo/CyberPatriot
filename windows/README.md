# Windows Checklist

Applies to both Windows 10 and Windows Server.
The script has been tested on both operating systems without any issues.

## Running

1. Clone the repository with Git, or download as a ZIP file and extract
2. Go to the `windows/` directory in the new folder and run PowerShell
   (With file explorer, you can type `powershell -EP Bypass` in the box for the current file path)
3. Run `Invoke-Script.ps1` (start typing "invoke" and press tab)
4. The script should auto-elevate and prompt you to choose an option

## Managed By Script

- [x] Update Windows
- [x] Enable automatic updates
- [x] Set UAC level to max
- [x] Remove unauthorized users
- [x] Add missing users
- [x] Add/remove users from Administrators group
- [x] Change all passwords
- [x] Enable/disable accounts
- [x] Add missing groups
- [x] Enable/disable remote desktop
- [x] Configure security policy
- [x] List/remove SMB shares
- [x] List running services
- [x] List media files
- [x] Configure firewall
- [x] Confire interactive logon policies
- [x] Configure Windows Defender
  - [x] General settings (which protections to enable, etc.)
  - [ ] Hidden areas of the Security Center

## Not Managed By Script

- [ ] Remove prohibited/unwanted software
- [ ] Lock down browser  
       If the browser is Firefox, basically just set every setting
      to the most strict in the security settings
- [ ] Install recommended programs
