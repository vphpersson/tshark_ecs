#!/usr/bin/env python

from json import loads as json_loads, dumps as json_dumps
from functools import partial
from typing import Type, Any, Final
from itertools import zip_longest
from re import compile as re_compile, Pattern as RePattern

from ecs_py import Base

from tshark_ecs.cli import TSharkECSArgumentParser
from tshark_ecs import _LAYER_MAP, SPEC_LAYER_PATTERN


CONDITION_PATTERN: Final[RePattern] = re_compile(pattern=r'\[(?P<key>[^=]+)=(?P<value>.+?)\]')


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
            spec_layer_names: list[str] = []
            spec_layer_conditions: list[list[tuple[str, str]]] = []
            try_next_spec = True

            for spec_layer_value, layer_name in zip_longest(spec, layer_names, fillvalue=''):
                if spec_layer_value in {'', '*'}:
                    spec_layer_names.append(spec_layer_value)
                    spec_layer_conditions.append([])
                    continue

                if (spec_layer_name := SPEC_LAYER_PATTERN.match(string=spec_layer_value).groupdict()['layer_name']) != layer_name:
                    break
                else:
                    spec_layer_names.append(spec_layer_name)

                spec_layer_conditions.append([
                    (group_dict['key'], group_dict['value'])
                    for match in CONDITION_PATTERN.finditer(string=spec_layer_value)
                    if (group_dict := match.groupdict())
                ])
            else:
                try_next_spec = False

            if try_next_spec:
                continue

            for i, (layer_name, layer_dict) in enumerate(line_dict['layers'].items()):
                if i >= len(spec):
                    discard_line = True
                    break

                if spec_layer_names[i] == '':
                    continue

                if spec_layer_names[i] == '*' or spec_layer_names[i] == layer_name:
                    for condition in spec_layer_conditions[i]:
                        key, value = condition
                        if layer_dict.get(key) != value:
                            discard_line = True
                            break

                    if discard_line:
                        break

                    # Retrieve the function for parsing the current layer.
                    if layer_func := _LAYER_MAP[i].get(layer_name):
                        # Add extra arguments when calling some the parser function for some layers.
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
                                base_entry = base_entry or Base()
                                base_entry |= line_base_entry
                                # TODO: Why?
                                break

                        line_base_entry: Base | None = layer_func(layer_dict)
                        # If no `Base` entry is returned, the packet (line) is deemed uninteresting.
                        if not line_base_entry:
                            discard_line = True
                            break

                        # Merge the current layer's base entry with the one for the previous layers.
                        base_entry = base_entry or Base()
                        base_entry |= line_base_entry
                else:
                    raise ValueError(f'The spec "{spec}" could not be applied to the layer "{layer_name}".')

            # A spec has matched the layers. Do not attempt to parse the layers using another spec.
            break

        if base_entry and not discard_line:
            print(base_entry)


if __name__ == '__main__':
    main()
