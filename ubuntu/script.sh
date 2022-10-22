#!/usr/bin/env bash
# CyberPatriot Scripts - Scripts and whatnot for use in CyberPatriot.
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
echo 'Ubuntu CyberPatriot Script'
echo
echo 'CyberPatriot Scripts  Copyright (C) 2022  Adam Thompson-Sharpe'
echo 'Licensed under the GNU General Public License, Version 3.0'
echo
echo 'Make sure to run this as root!'
echo

function get_users {
    users=$(awk -F: '{if ($3 >= 1000) print $1}' < /etc/passwd)
}

function prompt {
    if [ "$2" = 'n' ]; then
        prompt_text="$1 [Y/n]: "
    elif [ "$2" = 'n' ]; then
        prompt_text="$1 [y/N]: "
    else
        prompt_text="$1 [y/n]: "
    fi

    while true; do
        read -r -p "$prompt_text" input

        case "$input" in
            [yY][eE][sS]|[yY])
                return 1
                ;;
            [nN][oO]|[nN])
                return 0
                ;;
            "")
                if [ "$2" = "y" ]; then return 1
                elif [ "$2" = "n" ]; then return 0
                else echo "Invalid response"
                fi
                ;;
            *)
                echo "Invalid response"
                ;;
        esac
    done
}

# System updates
prompt 'Run updates?' 'y'
if [ $? = 1 ]; then
    prompt 'Reboot after updates? Recommended if DE crashes during updates' 'n'
    apt-get update
    apt-get upgrade -y
    if [ $? = 1 ]; then reboot; fi
    exit
fi

# Configure UFW
prompt 'Enable and configure UFW?' 'y'
if [ $? = 1 ]; then
    echo Configuring UFW
    apt-get install ufw

    rule='default deny'
    while ! [ "$rule" = '' ]; do
        ufw $rule
        read -r -p 'UFW rule to add, eg. `allow ssh` (leave blank to finish adding rules): ' rule
    done

    echo Enabling UFW
    ufw enable
    echo Done
fi

# Configure SSH
prompt 'Enable and configure sshd?' 'y'
if [ $? = 1 ]; then
    echo Configuring sshd
    apt-get install openssh

    echo Enabling \& starting service

    systemctl enable sshd
    systemctl start sshd

    prompt 'Disable root logins?' 'y'
    if [ $? = 1 ]; then echo 'PermitRootLogin no' >> /etc/ssh/sshd_config; fi

    prompt 'Disallow empty passwords?' 'y'
    if [ $? = 1 ]; then echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config; fi

    echo Restarting service

    systemctl restart sshd

    echo Done
fi

prompt 'Find unauthorized users and add missing ones?' 'y'

if [ $? = 1 ]; then
    echo Checking for unauthorized users

    read -r -p 'Path to list of allowed usernames (should include admins and unadded users): ' users_file

    get_users

    unauthorized=()

    for user in $users; do
        if [ "$user" = 'nobody' ]; then continue; fi
        if ! grep -Fxq "$user" "$users_file"; then
            echo Unauthorized user: $user
            unauthorized+=("$user")
        fi
    done

    if [ $unauthorized ]; then
        prompt 'Delete found users?'

        if [ $? = 1 ]; then
            for user in $unauthorized; do
                echo Deleting $user
                userdel $user
            done
        fi
    fi

    echo Checking for missing users

    get_users

    while read -r user; do
        if ! printf "$users" | grep -wq "$user"; then
            echo Adding missing user $user
            useradd $user
        fi
    done < "$users_file"

    echo Done
fi

prompt 'Fix administrators?' 'y'

if [ $? = 1 ]; then
    echo Fixing administrators

    sudoers='sudo'
    prompt "Is \`sudo\` the name of the sudoers group? (If you don't know, run \`groups\` and look for something like \`sudo\` or \`wheel\`)" 'y'
    if [ $? = 0 ]; then read -r -p 'Sudoers group name: ' sudoers; fi

    read -r -p 'Path to list of intended administrators: ' admin_path
    read -r -p 'Path to list of intended standard users: ' normal_path

    get_users

    echo Ensuring admins are part of the sudo group

    while read -r admin; do
        if ! id -nG "$admin" | grep -qw "$sudoers"; then
            echo User $admin doesn\'t have admin perms, fixing
            usermod -aG "$sudoers" "$admin"
        fi
    done < "$admin_path"

    echo Ensuring standard users are not part of the sudo group

    while read -r normal; do
        if id -nG "$normal" | grep -qw "$sudoers"; then
            echo User $normal has admin perms and shouldn\'t, fixing
            gpasswd --delete "$normal" "$sudoers"
        fi
    done < "$normal_path"

    echo Done
fi
