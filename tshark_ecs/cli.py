from argparse import FileType, Action, Namespace, ArgumentParser
from typing import Any, Type
from io import TextIOWrapper
from sys import stdin
from urllib.parse import urlparse, ParseResult, parse_qs
from logging import Handler
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from json import loads as json_loads

from typed_argument_parser import TypedArgumentParser
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie
# TODO: I may want to fork and edit this dependency. It uses external dependencies for functionality now in the standard
#   library.
from rfc5424logging import Rfc5424SysLogHandler
from ecs_tools_py import make_log_handler

from tshark_ecs import LOG


class TSharkECSArgumentParser(TypedArgumentParser):
    class Namespace:
        file: TextIOWrapper
        public_suffix_list: PublicSuffixListTrie | None
        uid_map: dict[str, dict[str, Any]] | None

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            **(
                dict(description='Make ECS entries from TShark JSON `_source` data.') | kwargs
            )
        )

        self.add_argument(
            '-f', '--file',
            nargs='?',
            type=FileType(mode='r'),
            default=stdin,
            help='A file from which to read TShark JSON `_source` data.'
        )

        self.add_argument(
            '--log',
            help='A log specifier specifying how logging is to be performed.',
            action=self._LogAction
        )

        self.add_argument(
            '--public-suffix-list',
            help='The path of a list of Public Suffix rules.',
            action=self._PublicSuffixListAction
        )

        self.add_argument(
            '--uid-map',
            help='The path of a JSON file from which to read a UID mapping.',
            action=self._UidMapAction
        )

    class _LogAction(Action):
        def __call__(self, parser: ArgumentParser, namespace: Namespace, log_specifier: str, option_string: str = None):
            parse_result: ParseResult = urlparse(url=log_specifier)
            log_handler_qs_kwargs: dict[str, list[str]] = parse_qs(qs=parse_result.query)

            provider_name: str = next(
                iter(
                    log_handler_qs_kwargs.get('provider_name', ['tshark_ecs'])
                )
            )
            fields: list[str] = next(
                iter(
                    log_handler_qs_kwargs.get(
                        'fields',
                        [
                            ','.join([
                                'event.timezone',
                                'host.name',
                                'host.hostname'
                            ])
                        ]
                    )
                )
            ).split(',')
            enrichment_map: dict[str, Any] = json_loads(
                next(
                    iter(
                        log_handler_qs_kwargs.get(
                            'enrichment_map',
                            ['{}']
                        )
                    )
                )
            )

            log_handler_base_class: Type[Handler]
            log_handler_kwargs: dict[str, Any]

            match parse_result.scheme:
                case 'udp':
                    log_handler_base_class = Rfc5424SysLogHandler
                    log_handler_kwargs = dict(address=(parse_result.hostname, int(parse_result.port)))
                case 'file' | _:
                    log_handler_base_class = TimedRotatingFileHandler
                    log_handler_kwargs = dict(
                        filename=parse_result.path,
                        when=next(iter(log_handler_qs_kwargs.get('when', ['D'])))
                    )

            log_handler = make_log_handler(
                base_class=log_handler_base_class,
                provider_name=provider_name,
                enrichment_map=enrichment_map,
                generate_field_names=fields
            )(**log_handler_kwargs)

            LOG.addHandler(hdlr=log_handler)

    class _PublicSuffixListAction(Action):
        def __call__(self, parser: ArgumentParser, namespace: Namespace, public_suffix_list, option_string: str = None):
            setattr(
                namespace,
                'public_suffix_list',
                PublicSuffixListTrie.from_public_suffix_list_file(file=public_suffix_list)
            )

    class _UidMapAction(Action):
        def __call__(self, parser: ArgumentParser, namespace: Namespace, uid_map: str, option_string: str = None):
            setattr(
                namespace,
                'uid_map',
                json_loads(Path(uid_map).read_text())
            )
