#!/usr/bin/env python

from logging import INFO
from json import loads as json_loads

from tshark_ecs.cli import TSharkECSArgumentParser
from tshark_ecs import LOG, ParseResult, handle_tshark_dict


def main():
    try:
        args: TSharkECSArgumentParser.Namespace = TSharkECSArgumentParser().parse_args()
        LOG.setLevel(level=INFO)

        for line in args.file:
            try:
                parse_result: ParseResult | None = handle_tshark_dict(
                    tshark_dict=json_loads(line),
                    public_suffix_list=args.public_suffix_list,
                    uid_map=args.uid_map,
                    line=line
                )
                if parse_result:
                    LOG.info(str(parse_result.base), extra=parse_result.extra)
            except Exception:
                LOG.exception(
                    msg='An error occurred when attempting to parse a TShark JSON line.',
                    extra=dict(
                        error=dict(input=line),
                        _ecs_logger_handler_options=dict(merge_extra=True)
                    )
                )
    except KeyboardInterrupt:
        exit(1)
    except Exception:
        LOG.exception(msg='An unexpected error occurred.')


if __name__ == '__main__':
    main()
