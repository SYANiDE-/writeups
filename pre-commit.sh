#!/bin/bash

## Find all referenced pastedimages and add them to docs, renaming spaces to underscore
for item in $(find . -name "*.md"); do 
    found=($(grep -FPo "Pasted image .+.png" $item | tr ' ' '_')); 
    for meti in "${found[@]}"; do 
        if [[ ! -f docs/$meti ]]; then 
            cp ../../"${meti//_/ }" docs/$meti
        fi
    done
done

## change all references from "Pasted image .+png" to "Pasted_image_.+png" replacing any spaces
for item in $(find . -name "*.md"); do 
    IFS=$'\n' found=($(grep -FPo "Pasted image .+.png" $item))
    for meti in "${found[@]}"; do 
        repl="${meti// /_}"
        sed -re "s/$meti/$repl/g" $item -i
    done
done
