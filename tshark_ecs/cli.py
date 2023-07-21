from argparse import FileType, Action, Namespace, ArgumentParser
from typing import Any
from io import TextIOWrapper
from sys import stdin
from pathlib import Path
from json import loads as json_loads

from typed_argument_parser import TypedArgumentParser
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie
from ecs_tools_py import make_log_action

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
            action=make_log_action(event_provider='tshark_ecs', log=LOG)
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
