#!/usr/bin/env python

from json import loads as json_loads, dumps as json_dumps
from functools import partial
from typing import Type, Any
from itertools import zip_longest

from ecs_py import Base
from ecs_tools_py import merge_ecs_entries

from tshark_ecs.cli import TSharkECSArgumentParser
from tshark_ecs import _LAYER_MAP


def main():
    args: Type[TSharkECSArgumentParser.Namespace] = TSharkECSArgumentParser().parse_args()

    for line in args.file:
        line_dict: dict[str, dict[str, Any]] = json_loads(line)

        if 'layers' not in line_dict:
            continue

        discard_line = False

        frame_layer = line_dict['layers'].pop('frame')

        layer_names: list[str] = list(line_dict['layers'].keys())

        base_entry: Base | None = None

        for spec in args.specs:
            if not all(spec_value in {'', '*', layer_name} for spec_value, layer_name in zip_longest(spec, layer_names)):
                continue

            for i, (layer_name, layer_dict) in enumerate(line_dict['layers'].items()):
                if spec[i] == '':
                    continue

                if spec[i] == '*' or spec[i] == layer_name:
                    if layer_func := _LAYER_MAP[i].get(layer_name):
                        match layer_name:
                            case 'dns':
                                layer_func = partial(layer_func, public_suffix_list_trie=args.public_suffix_list)
                            case 'tls':
                                layer_func = partial(
                                    layer_func,
                                    public_suffix_list_trie=args.public_suffix_list,
                                    include_supported_ciphers=False
                                )
                            case 'icmp':
                                line_base_entry = layer_func(layer_dict, line_dict['layers'])
                                base_entry = merge_ecs_entries(base_entry or Base(), line_base_entry)
                                break

                        line_base_entry: Base | None = layer_func(layer_dict)
                        if not line_base_entry:
                            discard_line = True
                            break

                        base_entry = merge_ecs_entries(base_entry or Base(), line_base_entry)
                else:
                    raise ValueError(f'The spec "{spec}" could not be applied to the layer "{layer_name}".')
            break

        if base_entry and not discard_line:
            print(json_dumps(base_entry.to_dict()))


if __name__ == '__main__':
    main()
