# ~/.zshrc — interactive zsh on Oh My Zsh.
# PATH for cargo is set in ~/.zshenv, for ~/.local/bin in ~/.local/bin/env.

# ---- Oh My Zsh ---------------------------------------------------------------
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="agnoster" # set by `omz`

zstyle ':omz:update' mode reminder   # remind about updates instead of prompting at startup
zstyle ':omz:update' frequency 7

# zsh-syntax-highlighting must be the last plugin.
plugins=(git zsh-autosuggestions zsh-syntax-highlighting)

source "$ZSH/oh-my-zsh.sh"

# ---- Environment -------------------------------------------------------------
. "$HOME/.local/bin/env"
typeset -U path PATH   # drop duplicate PATH entries

export EDITOR=vim
export VISUAL=vim

# ---- History -----------------------------------------------------------------
HISTSIZE=999999
SAVEHIST=999999
setopt EXTENDED_HISTORY       # timestamp and duration of each command
setopt SHARE_HISTORY          # history shared between open terminals
setopt HIST_IGNORE_SPACE      # commands starting with a space are not saved
setopt HIST_REDUCE_BLANKS
setopt HIST_IGNORE_DUPS       # skip consecutive duplicates
setopt HIST_FIND_NO_DUPS      # hide duplicates when searching (Ctrl+R, arrows)
setopt HIST_EXPIRE_DUPS_FIRST
setopt HIST_VERIFY            # expand !! and !$ before running

# ---- Aliases -----------------------------------------------------------------
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# ---- Functions ---------------------------------------------------------------

# Update the whole system: apt, Claude Code, ClamAV databases, Rust, locate database.
# An apt failure aborts the run; failures of other steps are listed at the end.
sysupdate() {
    emulate -L zsh
    zmodload zsh/datetime

    local -a failed summary
    local -i n=0 total=5
    local t_all=$EPOCHREALTIME t_step

    # 75 → "1m 15s", 9 → "9s"
    _su_dur() {
        local -i s=$1
        (( s >= 60 )) && print -n "$((s / 60))m $((s % 60))s" || print -n "${s}s"
    }
    _su_begin() {
        t_step=$EPOCHREALTIME
        print -P "%F{cyan}│%f\n%F{cyan}├─▶%f %B[$((++n))/$total] $1%b"
    }
    # $1 — step name, $2 — exit code
    _su_end() {
        local d=$(_su_dur $(( EPOCHREALTIME - t_step )))
        if (( $2 == 0 )); then
            summary+=("%F{green}✓%f $1 %F{242}$d%f")
            print -P "%F{cyan}│%f   %F{green}✓ done%f %F{242}in $d%f"
        else
            failed+=($1)
            summary+=("%F{red}✗%f $1 %F{242}$d%f")
            print -P "%F{cyan}│%f   %F{red}✗ failed, exit code $2%f %F{242}in $d%f"
        fi
    }
    _su_finish() {
        local d=$(_su_dur $(( EPOCHREALTIME - t_all )))
        print -P "%F{cyan}│%f"
        print -P "%F{cyan}╰─%f %BSummary%b %F{242}in $d%f"
        local line
        for line in $summary; do print -P "   $line"; done
        if (( ${#failed} )); then
            print -P "   %F{red}%BFailed:%b ${(j:, :)failed}%f"
        fi
        [[ -f /run/reboot-required ]] && print -P "   %F{yellow}⚠ Reboot required%f"
        if (( $+commands[notify-send] )); then
            if (( ${#failed} )); then
                notify-send -i dialog-warning "sysupdate" "Failed: ${(j:, :)failed}"
            else
                notify-send -i emblem-ok-symbolic "sysupdate" "System updated in $d"
            fi
        fi
    }

    {
        print -P "%F{cyan}╭─%f %B%F{blue}System update%f%b %F{242}$(strftime '%Y-%m-%d %H:%M' $EPOCHSECONDS)%f"
        sudo -v || return 1

        _su_begin "APT"
        sudo apt update && apt list --upgradable 2>/dev/null | tail -n +2 \
            && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean
        _su_end APT $?
        if (( ${#failed} )); then
            print -P "%F{cyan}│%f   %F{red}APT failed, stopping here.%f"
            _su_finish
            return 1
        fi

        _su_begin "Claude Code"
        claude update
        _su_end Claude $?

        _su_begin "ClamAV"
        # freshclam won't run while the service holds the database lock.
        local -i rc=0
        if sudo systemctl stop clamav-freshclam; then
            sudo freshclam || rc=$?
        else
            rc=1
        fi
        sudo systemctl start clamav-freshclam || rc=1
        _su_end ClamAV $rc

        _su_begin "Rust"
        rustup update
        _su_end Rust $?

        _su_begin "UpdateDB"
        sudo updatedb
        _su_end UpdateDB $?

        _su_finish
        return $(( ${#failed} > 0 ))
    } always {
        unfunction _su_dur _su_begin _su_end _su_finish
    }
}

# Battery conservation mode (Lenovo IdeaPad): charging stops at ~60%.
# Usage: batcons [on|off] — without an argument shows the current state.
batcons() {
    local f=/sys/bus/platform/drivers/ideapad_acpi/VPC2004:00/conservation_mode
    local bat=(/sys/class/power_supply/BAT*(N[1]))
    [[ -r $f ]] || { print -P "%F{red}conservation_mode not available%f"; return 1; }
    case $1 in
        on)  print 1 | sudo tee $f >/dev/null || return ;;
        off) print 0 | sudo tee $f >/dev/null || return ;;
        '')  ;;
        *)   print "usage: batcons [on|off]"; return 2 ;;
    esac
    if (( $(<$f) )); then
        print -P "Conservation mode: %F{green}on%f (charging stops at ~60%%)"
    else
        print -P "Conservation mode: %F{yellow}off%f (charging to 100%%)"
    fi
    [[ -n $bat && -r $bat/capacity ]] && print "Battery: $(<$bat/capacity)% ($(<$bat/status))"
}
