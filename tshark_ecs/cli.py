from io import TextIOWrapper
from argparse import FileType, Action, Namespace, ArgumentParser
from sys import stdin
from pathlib import Path

from typed_argument_parser import TypedArgumentParser
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie

from tshark_ecs import _LAYER_MAP, SPEC_LAYER_PATTERN


class TSharkECSArgumentParser(TypedArgumentParser):

    class Namespace:
        file: TextIOWrapper
        specs: list[tuple[str, str, str, str]]
        public_suffix_list: PublicSuffixListTrie | None
        log_path: str

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
            '--log-path',
            help='The path where log files should be written.',
            default='tshark_ecs.log'
        )

        self.add_argument(
            '--public-suffix-list',
            type=Path,
            help='The path of a list of Public Suffix rules.',
            action=self._PublicSuffixListAction
        )

        self.add_argument(
            'specs',
            nargs='+',
            metavar='SPEC',
            help='',
            action=self._SpecsAction
        )

    class _SpecsAction(Action):
        def __call__(self, parser: ArgumentParser, namespace: Namespace, specs: list[str], option_string: str = None):

            spec_list: list[tuple[str, str, str, str]] = []

            for spec_str in specs:
                spec: list[str] = []

                if '.' not in spec_str:
                    for layer_dict in reversed(_LAYER_MAP):
                        if spec_str in layer_dict:
                            spec.append(spec_str)
                            spec = spec + [''] * (len(_LAYER_MAP) - len(spec))
                            break
                        else:
                            spec.append('')
                    else:
                        parser.error(message=f'The spec string "{spec_str}" does not match anything.')

                else:
                    spec_str_parts: list[str] = spec_str.split('.')

                    if spec_str_parts[-1] == '**':
                        raise NotImplementedError('"**" are not supported at the end of a spec string.')

                    for i, spec_str_part in enumerate(reversed(spec_str_parts), start=1):
                        if spec_str_part == '*':
                            spec.append(spec_str_part)
                        elif spec_str_part == '**':
                            spec = spec + ['*'] * (len(_LAYER_MAP) - len(spec))
                            break
                        elif spec_str_part == '':
                            spec.append('')
                        else:
                            match = SPEC_LAYER_PATTERN.match(string=spec_str_part)
                            if match and match.groupdict()['layer_name'] in _LAYER_MAP[-i]:
                                spec.append(spec_str_part)
                            else:
                                raise parser.error(f'The spec string "{spec_str}" does not match.')

                spec_list.append(tuple(reversed(spec)))

            setattr(namespace, self.dest, spec_list)

    class _PublicSuffixListAction(Action):
        def __call__(self, parser: ArgumentParser, namespace: Namespace, public_suffix_list, option_string: str = None):
            setattr(
                namespace,
                'public_suffix_list',
                PublicSuffixListTrie.from_public_suffix_list_file(file=public_suffix_list)
            )
