# Bash completion script for nullgate-ctl
# NullGate Administrative Control CLI

_nullgate_ctl_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="status ping list-domains query-domain query-pid reload-policy dump-audit"
    local options="-j --json -h --help"

    # Complete options or commands if at first non-option argument
    if [[ $cword -eq 1 ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=($(compgen -W "$options" -- "$cur"))
        else
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        fi
        return 0
    fi

    # Handle completion after subcommand
    case "${prev}" in
        reload-policy)
            # Complete JSON or YAML files
            COMPREPLY=($(compgen -f -X '!*.@(json|yaml|yml)' -- "$cur") $(compgen -d -- "$cur"))
            return 0
            ;;
        query-domain)
            # Domain IDs 0 through 15
            local domain_ids="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15"
            COMPREPLY=($(compgen -W "$domain_ids" -- "$cur"))
            return 0
            ;;
        query-pid)
            # Process IDs from procfs
            COMPREPLY=($(compgen -W "$(ps -eo pid= 2>/dev/null)" -- "$cur"))
            return 0
            ;;
        *)
            ;;
    esac

    # Handle second argument if first was an option
    if [[ "${words[1]}" == -* && $cword -eq 2 ]]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return 0
    fi
}

complete -F _nullgate_ctl_completions nullgate-ctl
