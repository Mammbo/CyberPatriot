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
    Scripts and whatnot for use in CyberPatriot.

    .DESCRIPTION
    A script for use on either Windows 10 or Windows Server
    to automatically do some easily-automated tasks.
#>


# Function taken from https://gitlab.com/-/snippets/2434376
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

        Source: <https://gitlab.com/-/snippets/2434376>
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

Write-Output `
    'Windows CyberPatriot Script

CyberPatriot Scripts  Copyright (C) 2022  Adam Thompson-Sharpe
Licensed under the GNU General Public License, Version 3.0

Make sure to run this with administrator privileges!'

$Menu = @{
    # Run updates
    '1' = {
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
    '2' = {
        $WUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
        $WUSettings.NotificationLevel = 4
        $WUSettings.save()
        Write-Output 'Automatic updates enabled'
    }

    # Set UAC to highest
    '3' = {
        $SystemPolicies = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Set-ItemProperty -Path $SystemPolicies -Name 'ConsentPromptBehaviorAdmin' -Value 2
        Set-ItemProperty -Path $SystemPolicies -Name 'PromptOnSecureDesktop' -Value 1
        Write-Output 'UAC set to highest'
    }

    # Configure remote desktop
    '4' = {
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
    '99' = {
        Write-Output 'Good luck and happy hacking!'
        exit
    }
}

function Show-Menu {
    Write-Output '
1) Run updates
2) Enable automatic updates
3) Set UAC to highest
4) Configure remote desktop

99) Exit script'

    $Input = Read-Host 'Option'

    if ($Menu[$Input]) { . $Menu[$Input] }
    else { Write-Output "Unknown option $Input" }
}

while ($True) { Show-Menu }
