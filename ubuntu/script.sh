#!/usr/bin/env bash
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

function get_users {
    # The <65534 condition is to skip the nobody user
    users=$(awk -F: '{if ($3 >= 1000 && $3 < 65534) print $1}' < /etc/passwd)
}

# prompt and reprompt_var functions from https://gitlab.com/-/snippets/2434448
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

function reprompt_var {
    local reprompt_text="$1"
    local reprompt_new_val=''
    reprompt_value="${!2}"

    if [ $reprompt_value ]; then reprompt_text+=" [$reprompt_value]: "
    else reprompt_text+=': '; fi

    read -r -p "$reprompt_text" reprompt_new_val

    if [ "$reprompt_new_val" ]; then reprompt_value="$reprompt_new_val"; fi
}

echo 'Ubuntu CyberPatriot Script'
echo
echo 'CyberPatriot Scripts  Copyright (C) 2022  Adam Thompson-Sharpe'
echo 'Licensed under the GNU General Public License, Version 3.0'
echo
echo 'Make sure to run this as root!'
echo "Current user: $(whoami)"

sshd_conf='/etc/ssh/sshd_config.d/mbh.conf'
sudo_group='sudo'

function menu {
    echo
    echo '1) Run updates                        7) Change all passwords'
    echo '2) Enable & Configure UFW             8) Lock account'
    echo '3) Enable & configure sshd            9) Add new group'
    echo '4) Find/remove unauthorized users'
    echo '5) Add missing users'
    echo '6) Fix administrators'
    echo
    echo '99) Exit script'
    read -r -p '> ' input

    case "$input" in
        # Run updates
        '1')
            prompt 'Reboot after updates? Recommended if DE crashes during updates' 'n'
            apt-get update
            apt-get upgrade -y
            if [ $? = 1 ]; then reboot; fi
            echo 'Done updating!'
            ;;

        # Set up UFW
        '2')
            apt-get install ufw -y

            rule='default deny'
            while ! [ "$rule" = '' ]; do
                ufw $rule
                read -r -p 'UFW rule to add, eg. `allow ssh` (leave blank to finish adding rules): ' rule
            done

            ufw enable
            echo 'Done configuring!'
            ;;

        # Set up sshd
        '3')
            apt-get install openssh -y

            echo 'Enabling & starting service'
            systemctl enable sshd
            systemctl start sshd

            rm -f "$sshd_conf"

            prompt 'Permit root logins?' 'y'
            if [ $? = 1 ]; then echo 'PermitRootLogin no' >> "$sshd_conf"
            else echo 'PermitRootLogin yes' >> "$sshd_conf"; fi

            prompt 'Permit empty passwords?' 'y'
            if [ $? = 1 ]; then echo 'PermitEmptyPasswords no' >> "$sshd_conf"
            else echo 'PermitEmptyPasswords yes' >> "$sshd_conf"; fi

            echo Restarting service
            systemctl restart sshd
            echo 'Done configuring!'
            ;;

        # Find and remove unauthorized users
        '4')
            reprompt_var 'Path to list of allowed usernames' 'users_file'
            users_file="$reprompt_value"
            get_users

            unauthorized=()

            for user in $users; do
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

            echo 'Done!'
            ;;

        # Add missing users
        '5')
            reprompt_var 'Path to list of allowed usernames' 'users_file'
            users_file="$reprompt_value"
            get_users

            while read -r user; do
                if ! printf "$users" | grep -wq "$user"; then
                    echo Adding missing user $user
                    useradd $user
                fi
            done < "$users_file"

            echo 'Added missing users!'
            ;;

        # Fix administrators
        '6')
            reprompt_var 'Path to list of administrators' 'admin_file'
            admin_file="$reprompt_value"
            reprompt_var 'Path to list of normal users' 'normal_file'
            normal_file="$reprompt_value"
            reprompt_var 'Name of sudoers group (generally `sudo` or `wheel`)' 'sudo_group'
            sudo_group="$reprompt_value"
            get_users

            echo 'Ensuring admins are part of the sudo group'

            while read -r admin; do
                if ! id -nG "$admin" | grep -qw "$sudo_group"; then
                    echo "User $admin doesn't have admin perms, fixing"
                    usermod -aG "$sudo_group" "$admin"
                fi
            done < "$admin_file"

            echo 'Ensuring standard users are not part of the sudo group'

            while read -r normal; do
                if id -nG "$normal" | grep -qw "$sudo_group"; then
                    echo "User $normal has admin perms and shouldn't, fixing"
                    gpasswd --delete "$normal" "$sudo_group"
                fi
            done < "$normal_file"

            echo 'Done fixing administrators!'
            ;;

        # Change all passwords
        '7')
	    get_users
            echo 'Changing passwords for the following users:'
	    echo $users
	    
            new_pass=''
            new_pass_confirm=''
            while ! [ "$new_pass" = "$new_pass_confirm" ] || [ "$new_pass" = '' ]; do
                read -s -p 'New password: ' new_pass
                read -s -p 'Confirm: ' new_pass_confirm

                if ! [ "$new_pass" = "$new_pass_confirm" ]; then echo 'Passwords do not match!'
                else
                    for user in $users; do
                        echo "Changing for $user..."
                        printf "$new_pass" | passwd --stdin $user
                    done
                fi
            done

            echo 'Done changing passwords!'
            ;;

        # Lock account
        '8')
            read -r -p 'Account to lock [root]: ' lock_account
            if [ "$lock_account" = '' ]; then lock_account='root'; fi
            usermod -L $lock_account
            echo "Locked $lock_account!"
            ;;

        # Add group
        '9')
            read -r -p 'New group to add: ' new_group
            groupadd $new_group
            
            prompt 'Add members to this group?' 'y'
            if [ $? = 1 ]; then
                read -r -p 'Users to add (space-separated): ' new_group_users

                for user in $new_group_users; do
                    usermod -aG $new_group $user
                    echo "Added $user to $new_group"
                done
            fi

            echo 'Done creating new group!'
            ;;

        # Exit
        '99')
            echo 'Good luck and happy hacking!'
            exit 0
            ;;

        # Invalid option
        *)
            echo "Unknown option $input"
            ;;
    esac
}

while true; do menu; done
