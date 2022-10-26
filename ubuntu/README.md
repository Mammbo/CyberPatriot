# Ubuntu Checklist

## Managed By Script

- [x] Run updates
- [x] Enable & configure UFW
- [x] Configure sshd (enable, disable root login, etc.)
- [x] Remove unauthorized users
- [x] Add missing users
- [x] Add/remove users from sudo group
- [x] Change all passwords
- [x] Lock root account
- [x] Add missing groups
- [x] Disable guest account
- [x] Configure password expiry

## Not Managed By Script

- [ ] Enable auto-updates **through Ubuntu's UI**
  1. Run the Software Updater
  2. Go to Settings
  3. To be continued (I don't have an Ubuntu machine at the time of writing this)
- [ ] Remove prohibited/unwanted software
- [ ] Lock down browser  
       If the browser is Firefox, basically just set every setting
      to the most strict in the security settings
- [ ] Install recommended programs
- [ ] Configure PAM settings
  - Set minimum password length
  - Enforce password complexity
  - Configure account lockout
  - All done through `/etc/pam.d/common-password` or `/etc/pam.d/common-auth`
