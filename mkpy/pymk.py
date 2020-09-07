# THIS IS NOT PYTHON CODE, it's BASH code installed into /usr/share/bash-completion/completions/
# to enable tab completions.
_pymk()
{
    local cur prev words cword


    # FIXME: Why is there no _init_completion in Brew's bash_complete?
    #_init_completion || return
    COMPREPLY=()
    _get_comp_words_by_ref cur prev words cword

    res="$(./pymk.py --get_completions "$COMP_POINT $COMP_LINE")"
    COMPREPLY=( $( compgen -W '$res' -- "$cur" ) )
    [[ $COMPREPLY ]] || \
        COMPREPLY=( $( compgen -f -- "$cur" ) )
} &&
complete -F _pymk "./pymk.py"

# ex: ts=4 sw=4 et filetype=sh
