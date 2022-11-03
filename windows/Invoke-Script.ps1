# CyberPatriot Scripts - Scripts and checklists for use in CyberPatriot.
# Copyright (C) 2022  Adam Thompson-Sharpe
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

<#
    .SYNOPSIS
    Scripts and checklists for use in CyberPatriot.

    .DESCRIPTION
    A script for use on either Windows 10 or Windows Server
    to automatically do some easily-automated tasks.
#>


# Function taken from https://gitlab.com/MysteryBlokHed/powershell-tools,
# dual-licensed under the Apache 2.0 and MIT licenses
function Get-Prompt {
    <#
        .SYNOPSIS
        Shows a confirmation prompt to the user.

        .DESCRIPTION
        An abstraction for $Host.UI.PromptForChoice to make it much more concise
        to get prompts from the user.

        .PARAMETER Title
        The title of the prompt

        .PARAMETER Prompt
        The prompt to show the user

        .PARAMETER Options
        The options (eg. ('Yes', 'No')).

        .PARAMETER Default
        The default option. Should be an index of the Options array

        .PARAMETER Help
        Help messages to show for each option. Should be the same length as Options

        .PARAMETER StringReturn
        Returns the original options instead of the index.
        More info available in OUTPUTS documentation

        .OUTPUTS
        Returns the index of the user's chosen option by default.
        If -StringReturn is passed, returns the actual string option chosen instead,
        as it was originally passed. For example, if the original option chosen was 'Yes'
        and the user wrote 'y', the return value is 'Yes'.

        .EXAMPLE
        PS> Get-Prompt 'Confirmation' 'Are you sure you want to do that?' 'Yes','No' 0 'Do that','Do not do that'

        Confirmation
        Are you sure you want to do that?
        [Y] Yes  [N] No  [?] Help (default is "Y"): ?
        Y - Do that
        N - Do not do that
        [Y] Yes  [N] No  [?] Help (default is "Y"): Y
        0

        .EXAMPLE
        PS> Get-Prompt 'Confirmation' 'Are you sure you want to do that?' 'Yes','No' 0 'Do that','Do not do that' -StringReturn

        Confirmation
        Are you sure you want to do that?
        [Y] Yes  [N] No  [?] Help (default is "Y"): ?
        Y - Do that
        N - Do not do that
        [Y] Yes  [N] No  [?] Help (default is "Y"): Y
        Yes

        .NOTES
        Written by Adam Thompson-Sharpe.
        Licensed under either of the Apache License, Version 2.0,
        or the MIT license, at your option.

        Source: <https://gitlab.com/MysteryBlokHed/powershell-tools>
    #>

    param(
        [Parameter(Mandatory = $True, Position = 1)]
        [string]$Title,
        [Parameter(Mandatory = $True, Position = 2)]
        [string]$Prompt,
        [Parameter(Mandatory = $True, Position = 3)]
        [string[]]$Options,
        [Parameter(Mandatory = $True, Position = 4)]
        [int]$Default,
        [Parameter(Position = 5)]
        [string[]]$Help,
        [switch]$StringReturn
    )

    if ($Help -and $Options.Length -ne $Help.Length) {
        throw 'Options and Help must be of the same size'
    }

    if ($Default -gt $Options.Length -or $Default -lt 0) {
        throw 'Default exceeds the bounds of the Options array'
    }

    $OptionsChoices = @()

    for ($i = 0; $i -lt $Options.Length; $i++) {
        if (-not $Options[$i].Contains('&')) {
            $Option = "&$($Options[$i])"
        }
        else {
            $Option = $Options[$i]
        }

        if ($Help) {
            $OptionsChoices += New-Object System.Management.Automation.Host.ChoiceDescription $Option, $Help[$i]
        }
        else {
            $OptionsChoices += New-Object System.Management.Automation.Host.ChoiceDescription $Option
        }
    }

    $Response = $Host.UI.PromptForChoice($Title, $Prompt, $OptionsChoices, $Default)

    if ($StringReturn) {
        return $Options[$Response]
    }
    else {
        return $Response
    }
}

# Function taken from https://gitlab.com/MysteryBlokHed/powershell-tools,
# dual-licensed under the Apache 2.0 and MIT licenses
function Get-ReusedVar {
    <#
        .SYNOPSIS
        Prompt the user for a variable while remembering the last value.

        .DESCRIPTION
        Provide a prompt to show to the user as well as the name of the variable to save to.
        If the user provides a value, update the variable.
        If the user provides nothing, use the existing value.
        Returns the new value of the variable.
        Be careful not to use the names of variables created inside this function for the -Name parameter.

        .PARAMETER Prompt
        The prompt to show the user.

        .PARAMETER Name
        The name of the variable to check/update.
        The variable with this name is automatically modified based on the user's response.

        .NOTES
        Written by Adam Thompson-Sharpe.
        Licensed under either of the Apache License, Version 2.0,
        or the MIT license, at your option.

        Source: <https://gitlab.com/MysteryBlokHed/powershell-tools>
    #>
    param(
        [Parameter(Mandatory = $True, Position = 1)]
        [string]$Prompt,
        [Parameter(Mandatory = $True, Position = 2)]
        [string]$Name
    )

    $Current = Get-Variable $Name -ValueOnly -ErrorAction SilentlyContinue
    if ($Current) {
        $Prompt += " [$Current]"
    }

    while ($True) {
        $Value = Read-Host -Prompt $Prompt

        if ($Value) {
            Set-Variable $Name $Value -Visibility Public -Scope Global
            break
        }
        else {
            if (-not $Current) {
                Write-Output 'A value must be provided!'
            }
            else {
                break
            }
        }
    }

    return Get-Variable $Name -ValueOnly
}

Write-Output '
   ______      __
  / ____/_  __/ /_  ___  _____
 / /   / / / / __ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /
\____/\__, /_.___/\___/_/
    _/____/     __       _       __
   / __ \____ _/ /______(_)___  / /_
  / /_/ / __ `/ __/ ___/ / __ \/ __/
 / ____/ /_/ / /_/ /  / / /_/ / /_
/_/    \__,_/\__/_/  /_/\____/\__/

Windows CyberPatriot Script

CyberPatriot Scripts  Copyright (C) 2022  Adam Thompson-Sharpe
Licensed under the GNU General Public License, Version 3.0

Make sure to run this with administrator privileges!'

# Users that probably won't be in the users file provided,
# but that should be allowed on the system
$SafeUsers = ('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')

$Menu = @{
    # Run updates
    1  = {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            $Response = Get-Prompt 'Updates' 'Third-party PSWindowsUpdate module is not installed. Install to run updates programatically?' 'Yes', 'No' 0 -StringReturn
            if ($Response -eq 'Yes') {
                Install-Module PSWindowsUpdate
            }
        }
    
        # Run check again in case user decided not to install the package
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            Write-Output 'Checking for updates'
            $Updates = Get-WindowsUpdate
            if ($Updates) {
                Write-Output 'Updates found:' $Updates
                Install-WindowsUpdate | Out-Null
                Write-Output 'Updates installed'
            }
            else {
                Write-Output 'No updates found'
            }
        }
        else {
            Write-Output 'Skipping updates'
        }
    }

    # Enable automatic updates
    2  = {
        $WUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
        $WUSettings.NotificationLevel = 4
        $WUSettings.save()
        
        # Registry values
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Value 4
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallDay' -Value 0
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallTime' -Value 0
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoRebootWithLoggedOnUsers' -Value 1

        Write-Output 'Automatic updates enabled!'
    }

    # Set UAC to highest
    3  = {
        $SystemPolicies = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Set-ItemProperty -Path $SystemPolicies -Name 'ConsentPromptBehaviorAdmin' -Value 2
        Set-ItemProperty -Path $SystemPolicies -Name 'PromptOnSecureDesktop' -Value 1
        Write-Output 'UAC set to highest'
    }

    # Find/remove unauthorized users
    4  = {
        Get-ReusedVar 'Path to list of allowed usernames' UsersFile
        $Users = (Get-LocalUser).Name
        $AllowedUsers = Get-Content $UsersFile
        $Unauthorized = @()

        foreach ($User in $Users) {
            if ($User -in $SafeUsers) { continue }
            if (-not ($User -in $AllowedUsers)) {
                Write-Output "Unauthorized user: $User"
                $Unauthorized += $User
            }
        }

        if ($Unauthorized) {
            $Response = Get-Prompt 'Unauthorized users' 'Delete found users?' 'Yes', 'No' 0 -StringReturn
            if ($Response -eq 'Yes') {
                foreach ($User in $Unauthorized) {
                    Write-Output "Deleting $User"
                    Remove-LocalUser -Name $User
                }
            }
        }

        Write-Output 'Done!'
    }

    # Add missing users
    5  = {
        Get-ReusedVar 'Path to list of allowed usernames' UsersFile
        $Users = (Get-LocalUser).Name
        $AllowedUsers = Get-Content $UsersFile

        foreach ($User in $AllowedUsers) {
            if (-not ($User -in $Users)) {
                Write-Output "Adding missing user $User"
                New-LocalUser $User -NoPassword
            }
        }

        Write-Output 'Added missing users!'
    }

    # Fix administrators
    6  = {
        Get-ReusedVar 'Path to list of administrators' AdminFile
        Get-ReusedVar 'Path to list of normal users' NormalFile
        $Administrators = (Get-LocalGroupMember Administrators).Name | ForEach-Object { $_.Replace("$env:COMPUTERNAME\", '') }

        $Admins = Get-Content $AdminFile
        $Normal = Get-Content $NormalFile

        Write-Output 'Ensuring admins are part of the Administrators group'

        foreach ($User in $Admins) {
            if (-not ($User -in $Administrators)) {
                Write-Output "User $User doesn't have admin perms, fixing"
                Add-LocalGroupMember -Name Administrators -Member $User
            }
        }

        Write-Output 'Ensuring standard users are not part of the Administrators group'

        foreach ($User in $Normal) {
            if ($User -in $Administrators) {
                Write-Output "User $User has admin perms and shouldn't, fixing"
                Remove-LocalGroupMember -Name Administrators -Member $User
            }
        }

        Write-Output 'Done fixing administrators!'
    }

    # Configure remote desktop
    10 = {
        $Response = Get-Prompt 'Remote Desktop' 'Disable or enable remote desktop?' 'Disable', 'Enable' 0 -StringReturn
        $TerminalServer = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

        if ($Response -eq 'Disable') {
            Set-ItemProperty -Path $TerminalServer -Name 'fDenyTSConnections' -Value 1
            Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'
            Write-Output 'Remote desktop disabled'
        }
        else {
            Set-ItemProperty -Path $TerminalServer -Name 'fDenyTSConnections' -Value 0
            Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
            Write-Output 'Remote desktop enabled'
        }
    }

    # Exit script
    99 = {
        Write-Output 'Good luck and happy hacking!'
        exit
    }
}

function Show-Menu {
    Write-Output '
01) Run updates                         10) Configure remote desktop
02) Enable automatic updates
03) Set UAC to highest
04) Find/remove unauthorized users
05) Add missing users
06) Fix administrators
07) Change all passwords
08) Disable user
09) Add new group

99) Exit script'

    $Option = [int](Read-Host 'Option')

    if ($Menu[$Option]) { . $Menu[$Option] }
    else { Write-Output "Unknown option $Option" }
}

while ($True) { Show-Menu }
