#!/usr/bin/env python

from dataclasses import dataclass
from logging import Logger, getLogger, INFO
from logging.handlers import TimedRotatingFileHandler
from json import loads as json_loads
from functools import partial
from typing import Type, Any, Final
from re import compile as re_compile, Pattern as RePattern
from itertools import zip_longest
from datetime import datetime

from ecs_py import Base, Event
from ecs_tools_py import make_log_handler
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie

from tshark_ecs.cli import TSharkECSArgumentParser
from tshark_ecs import _LAYER_MAP, SPEC_LAYER_PATTERN


@dataclass
class Condition:
    key: str
    value: str


@dataclass
class ParseResult:
    base: Base
    extra: dict[str, Any]


LOG: Logger = getLogger(__name__)

log_handler = make_log_handler(
    base_class=TimedRotatingFileHandler,
    provider_name='tshark_ecs',
    generate_field_names=('event.timezone', 'host.name', 'host.hostname')
)(filename='tshark_ecs.log', when='D')

LOG.addHandler(hdlr=log_handler)
LOG.setLevel(level=INFO)

CONDITION_PATTERN: Final[RePattern] = re_compile(pattern=r'\[(?P<key>[^=]+)=(?P<value>.+?)\]')


def _select_spec(specs, layer_name_to_layer_dict: dict[str, dict[str, str]]):
    for spec in specs:
        if len(layer_name_to_layer_dict) > len(spec):
            continue

        spec_matches = False

        for spec_layer_value, layer_name in zip_longest(spec, layer_name_to_layer_dict, fillvalue=''):
            if spec_layer_value in {'', '*'}:
                continue

            spec_layer_name = SPEC_LAYER_PATTERN.match(string=spec_layer_value).groupdict()['layer_name']

            if spec_layer_name != layer_name:
                break

            conditions: list[Condition] = [
                Condition(key=group_dict['key'], value=group_dict['value'])
                for match in CONDITION_PATTERN.finditer(string=spec_layer_value)
                if (group_dict := match.groupdict())
            ]

            layer_dict: dict[str, str] = layer_name_to_layer_dict[layer_name]
            if not all(str(layer_dict.get(condition.key)) == condition.value for condition in conditions):
                break
        else:
            spec_matches = True

        if not spec_matches:
            continue

        return spec

    return None


def handle_tshark_dict(
    tshark_dict: dict[str, Any],
    specs: list[tuple[str, str, str, str]],
    public_suffix_list: PublicSuffixListTrie = None,
    line: str | None = None
) -> ParseResult | None:
    """

    :param tshark_dict:
    :param specs:
    :param public_suffix_list:
    :param line:
    :return:
    """

    if 'layers' not in tshark_dict:
        return None

    layer_name_to_layer_dict: dict[str, dict[str, str] | list] = tshark_dict['layers']

    frame_layer = tshark_dict['layers'].pop('frame')

    spec = _select_spec(specs=specs, layer_name_to_layer_dict=layer_name_to_layer_dict)
    if not spec:
        return None

    base_entry: Base | None = None

    for i, (layer_name, layer_dict) in enumerate(layer_name_to_layer_dict.items()):
        layer_func = _LAYER_MAP[i].get(layer_name)
        if not layer_func:
            continue

        if isinstance(layer_dict, list):
            layer_dict: dict = layer_dict[-1]
            if 'icmp' not in layer_name_to_layer_dict:
                LOG.warning(
                    msg='A TShark JSON line contains a layer with a list rather than dict and does not relate to ICMP.',
                    extra=dict(
                        error=dict(input=line),
                        _ecs_logger_handler_options=dict(merge_extra=True)
                    )
                )

        # Add extra arguments when calling some the parser function for some layers.
        match layer_name:
            case 'dns':
                layer_func = partial(layer_func, public_suffix_list_trie=public_suffix_list)
            case 'tls':
                layer_func = partial(
                    layer_func,
                    public_suffix_list_trie=public_suffix_list,
                    include_supported_ciphers=False
                )
            case 'icmp':
                layer_func = partial(layer_func, layer_name_to_layer_dict=layer_name_to_layer_dict)

        line_base_entry: Base | None = layer_func(layer_dict)
        # If no `Base` entry is returned, the packet (line) is deemed uninteresting.
        if not line_base_entry:
            return None

        # Merge the current layer's base entry with the one for the previous layers.
        base_entry = base_entry or Base()
        base_entry |= line_base_entry

        # If the layer name is `icmp`, any remaining layers are just "metadata".
        if layer_name == 'icmp':
            break

    if base_entry is not None:
        base_entry.event = Event(created=datetime.fromtimestamp(float(frame_layer['frame_frame_time_epoch'])))
        return ParseResult(
            base=base_entry,
            extra=dict(interface=frame_layer['frame_frame_interface_name'])
        )

    return base_entry


def main():
    args: Type[TSharkECSArgumentParser.Namespace] = TSharkECSArgumentParser().parse_args()

    for line in args.file:
        try:
            parse_result: ParseResult | None = handle_tshark_dict(
                tshark_dict=json_loads(line),
                specs=args.specs,
                public_suffix_list=args.public_suffix_list,
                line=line
            )
            if parse_result:
                LOG.info(str(parse_result.base), extra=parse_result.extra)
        except:
            LOG.exception(
                msg='An error occurred when attempting to parse a TShark JSON line.',
                extra=dict(
                    error=dict(input=line),
                    _ecs_logger_handler_options=dict(merge_extra=True)
                )
            )


if __name__ == '__main__':
    main()
