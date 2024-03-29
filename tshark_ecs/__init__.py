from logging import Logger, getLogger
import socket
from typing import Any, Final
from re import compile as re_compile, Pattern as RePattern
from collections import defaultdict
from functools import partial
from datetime import datetime
from dataclasses import dataclass
from itertools import zip_longest
from dataclasses import dataclass

from ecs_py import DNS, DNSAnswer, DNSQuestion, Base, Source, Destination, Network, TLS, TLSClient, TLSServer, ICMP, \
    Client, Server, TCP, Http, HttpRequest, HttpResponse, Observer, Interface, ObserverIngressEgress
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie

LOG: Final[Logger] = getLogger(__name__)


_QUERY_PATTERN: Final[RePattern] = re_compile(
    pattern=r'^(?P<name>.+): type (?P<type>[^,]+)(,\s*class (?P<class>[^,]+)(,(.+ )?(?P<data>.+))?)?$'
)

_RULE_PATTERN: Final[RePattern] = re_compile(pattern=r'^\[((?P<ruleset>[^-]+)-)?(?P<name>[^-]+)-(?P<action>[^]]+)\]$')

OP_CODE_ID_TO_OP_CODE_NAME: Final[dict[int, str]] = {
    0: 'QUERY',
    1: 'IQUERY',
    2: 'STATUS',
    4: 'NOTIFY',
    5: 'UPDATE'
}

RCODE_ID_TO_RCODE_NAME: Final[dict[int, str]] = {
    0: 'NOERROR',
    1: 'FORMERR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    4: 'NOTIMP',
    5: 'REFUSED',
    6: 'YXDOMAIN',
    7: 'YXRRSET',
    8: 'NXRRSET',
    9: 'NOTAUTH',
    10: 'NOTZONE'
}

_PROTO_PREFIX: Final[str] = 'IPPROTO_'

PROTO_ID_TO_PROTO_NAME: Final[dict[int, str]] = {
    num: name[len(_PROTO_PREFIX):].lower()
    for name, num in vars(socket).items()
    if name.startswith(_PROTO_PREFIX)
}


CIPHER_ID_TO_CIPHER_NAME: Final[dict[int, str]] = {
    0x01301: 'TLS_AES_128_GCM_SHA256',
    0x01302: 'TLS_AES_256_GCM_SHA384',
    0x01303: 'TLS_CHACHA20_POLY1305_SHA256',
    0x0C02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    0x0C024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    0x0C00A: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    0x0C02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    0x0C023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    0x0C009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    0x0C007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
    0x0C008: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
    0x0C006: 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
    0x0C030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    0x0C028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    0x0C014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    0x0C02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    0x0C027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    0x0C013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    0x0C011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
    0x0C012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
    0x0C010: 'TLS_ECDHE_RSA_WITH_NULL_SHA',
    0x0CCA8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    0x0CCA9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    0x0009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    0x0003D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    0x00035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    0x0009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    0x0003C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    0x0002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    0x00005: 'TLS_RSA_WITH_RC4_128_SHA',
    0x00004: 'TLS_RSA_WITH_RC4_128_MD5',
    0x0000A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    0x00009: 'TLS_RSA_WITH_DES_CBC_SHA',
    0x0003B: 'TLS_RSA_WITH_NULL_SHA256',
    0x00002: 'TLS_RSA_WITH_NULL_SHA',
    0x00001: 'TLS_RSA_WITH_NULL_MD5',
    0x00000: 'TLS_RSA_WITH_NULL_NULL',
    0x00006: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
    0x00003: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
    0x00062: 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',
    0x00064: 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA'
}

TLS_VERSION_ID_TO_PAIR: Final[dict[int, tuple[str, str]]] = {
    0x0301: ('tls', '1.0'),
    0x0302: ('tls', '1.1'),
    0x0303: ('tls', '1.2'),
    0x0304: ('tls', '1.3'),
}

NETFILTER_HOOK_ID_TO_NAME: Final[dict[int, str]] = {
    0: 'prerouting',
    1: 'input',
    2: 'forward',
    3: 'output',
    4: 'postrouting'
}

CURVE_ID_TO_NAME: Final[dict[int, str]] = {
    1: 'sect163k1',
    2: 'sect163r1',
    3: 'sect163r2',
    4: 'sect193r1',
    5: 'sect193r2',
    6: 'sect233k1',
    7: 'sect233r1',
    8: 'sect239k1',
    9: 'sect283k1',
    10: 'sect283r1',
    11: 'sect409k1',
    12: 'sect409r1',
    13: 'sect571k1',
    14: 'sect571r1',
    15: 'secp160k1',
    16: 'secp160r1',
    17: 'secp160r2',
    18: 'secp192k1',
    19: 'secp192r1',
    20: 'secp224k1',
    21: 'secp224r1',
    22: 'secp256k1',
    23: 'secp256r1',
    24: 'secp384r1',
    25: 'secp521r1',
    26: 'brainpoolP256r1',
    27: 'brainpoolP384r1',
    28: 'brainpoolP512r1',
    29: 'x25519',
    30: 'x448',
    31: 'brainpoolP256r1tls13',
    32: 'brainpoolP384r1tls13',
    33: 'brainpoolP512r1tls13',
    34: 'GC256A',
    35: 'GC256B',
    36: 'GC256C',
    37: 'GC256D',
    38: 'GC512A',
    39: 'GC512B',
    40: 'GC512C',
    41: 'curveSM2',
    256: 'ffdhe2048',
    257: 'ffdhe3072',
    258: 'ffdhe4096',
    259: 'ffdhe6144',
    260: 'ffdhe8192',
    65281: 'arbitrary_explicit_prime_curves',
    65282: 'arbitrary_explicit_char2_curves'
}

ICMP_TYPE_TO_NAME: Final[dict[int, str]] = {
    0: 'Echo reply',
    3: 'Destination unreachable',
    4: 'Source quench',
    5: 'Redirect',
    8: 'Echo',
    9: 'Router advertisement',
    10: 'Router selection',
    11: 'Time exceeded',
    12: 'Parameter problem',
    13: 'Timestamp',
    14: 'Timestamp reply',
    15: 'Information request',
    16: 'Information reply',
    17: 'Address mask request',
    18: 'Address mask reply',
    30: 'Traceroute'
}

ICMP_TYPE_TO_CODE_TO_NAME: Final[dict[int, dict[int, str]]] = {
    3: {
        0: 'Net is unreachable',
        1: 'Host is unreachable',
        2: 'Protocol is unreachable',
        3: 'Port is unreachable',
        4: "Fragmentation is needed and Don't Fragment was set",
        5: 'Source route failed',
        6: 'Destination network is unknown',
        7: 'Destination host is unknown',
        8: 'Source host is isolated',
        9: 'Communication with destination network is administratively prohibited',
        10: 'Communication with destination host is administratively prohibited',
        11: 'Destination network is unreachable for type of service',
        12: 'Destination host is unreachable for type of service',
        13: 'Communication is administratively prohibited',
        14: 'Host precedence violation',
        15: 'Precedence cutoff is in effect'
    },
    5: {
        0: 'Redirect datagram for the network (or subnet)',
        1: 'Redirect datagram for the host',
        2: 'Redirect datagram for the type of service and network',
        3: 'Redirect datagram for the type of service and host'
    },
    11: {
        0: 'Time to Live exceeded in transit',
        1: 'Fragment reassembly time exceeded',
    },
    12: {
        0: 'Pointer indicates the error',
        1: 'Missing a required option',
        2: 'Bad length',
    }
}

EXPERT_INFO_SEVERITY_ID_TO_LEVEL: Final[dict[int, str]] = {
    0x00100000: 'comment',
    0x00200000: 'chat',
    0x00400000: 'note',
    0x00600000: 'warn',
    0x00800000: 'error'
}

EXPERT_INFO_GROUP_ID_TO_MEANING: Final[dict[int, str]] = {
    0x01000000: 'A checksum was invalid.',
    0x02000000: 'A protocol sequence number was suspicious.',
    0x03000000: 'An application response code indicates a potential problem.',
    0x04000000: 'Application request.',
    0x05000000: 'Dissection incomplete or data can’t be decoded for other reasons.',
    0x06000000: 'Problems while reassembling.',
    0x07000000: 'Malformed packet or dissector has a bug.',
    0x08000000: 'Debugging information.',
    0x09000000: 'Violation of a protocol’s specification.',
    0x0a000000: 'Security problem.',
    0x0b000000: 'Packet comment.',
    0x0c000000: 'Decryption issue.',
    0x0d000000: 'The protocol field has incomplete data and was dissected based on assumed value.',
    0x0e000000: 'The protocol field has been deprecated.'
}


def get_expert_info(tshark_layer_dict: dict) -> dict | None:

    expert_dict: dict | None = None

    if '_ws_malformed' in tshark_layer_dict:
        expert_dict = tshark_layer_dict['_ws_malformed'].get('_ws_expert', None)

    if not expert_dict:
        return None

    severity_id = int(expert_dict['_ws_expert__ws_expert_severity'])
    group_id = int(expert_dict['_ws_expert__ws_expert_group'])
    message: str = expert_dict['_ws_expert__ws_expert_message']

    return dict(
        severity=dict(
            id=severity_id,
            level=EXPERT_INFO_SEVERITY_ID_TO_LEVEL.get(severity_id)
        ),
        group_id=dict(
            id=group_id,
            meaning=EXPERT_INFO_GROUP_ID_TO_MEANING.get(group_id)
        ),
        message=message
    )


def entry_from_ip(tshark_ip_layer: dict[str, Any]) -> Base:
    """
    Make a `Base` entry from the `ip` layer of TShark's `json` output.

    :param tshark_ip_layer: The `ip` layer to be parsed.
    :return: An ECS `Base` entry.
    """

    destination_ip: str = tshark_ip_layer['ip_ip_dst']
    source_ip: str = tshark_ip_layer['ip_ip_src']
    protocol_number: str = tshark_ip_layer['ip_ip_proto']

    return Base(
        destination=Destination(address=destination_ip, ip=destination_ip),
        network=Network(
            iana_number=protocol_number,
            transport=PROTO_ID_TO_PROTO_NAME[int(protocol_number)],
            type='ipv4'
        ),
        source=Source(address=source_ip, ip=source_ip)
    )


def entry_from_ipv6(tshark_ipv6_layer: dict[str, Any]) -> Base | None:
    """
    Make a `Base` entry from the `ip` layer of TShark's `json` output.

    :param tshark_ipv6_layer: The `ipv6` layer to be parsed.
    :return: An ECS `Base` entry.
    """

    destination_ip: str | None = tshark_ipv6_layer.get('ipv6_ipv6_dst')
    source_ip: str | None = tshark_ipv6_layer.get('ipv6_ipv6_src')
    protocol_number: str | None = tshark_ipv6_layer.get('ipv6_ipv6_nxt')

    if not destination_ip and not source_ip and not protocol_number:
        return None

    return Base(
        destination=Destination(address=destination_ip, ip=destination_ip),
        network=Network(
            iana_number=protocol_number,
            transport=PROTO_ID_TO_PROTO_NAME[int(protocol_number)],
            type='ipv6'
        ),
        source=Source(address=source_ip, ip=source_ip)
    )


def entry_from_udp(tshark_udp_layer: dict[str, Any]) -> Base:
    """
    Make a `Base` entry from the `udp` layer of TShark's `json` output.

    :param tshark_udp_layer: The `udp` layer to be parsed.
    :return: An ECS `Base` entry.
    """

    return Base(
        destination=Destination(port=int(tshark_udp_layer['udp_udp_dstport'])),
        network=Network(iana_number=str(socket.IPPROTO_UDP), transport='udp'),
        source=Source(port=int(tshark_udp_layer['udp_udp_srcport']))
    )


def _parse_tcp_flags(tshark_tcp_layer: dict[str, str]) -> list[str]:
    """
    Parse the flags of a `tcp` layer.

    :param tshark_tcp_layer: The `tcp` layer to be parsed.
    :return: A list of TCP flags.
    """

    tcp_flags: list[str] = []

    for key, value in tshark_tcp_layer.items():
        if not value:
            continue

        match key:
            case 'tcp_tcp_flags_cwr':
                tcp_flags.append('CWR')
            case 'tcp_tcp_flags_ece':
                tcp_flags.append('ECE')
            case 'tcp_tcp_flags_urg':
                tcp_flags.append('URG')
            case 'tcp_tcp_flags_ack':
                tcp_flags.append('ACK')
            case 'tcp_tcp_flags_push':
                tcp_flags.append('PSH')
            case 'tcp_tcp_flags_reset':
                tcp_flags.append('RST')
            case 'tcp_tcp_flags_syn':
                tcp_flags.append('SYN')
            case 'tcp_tcp_flags_fin':
                tcp_flags.append('FIN')

    return tcp_flags


def entry_from_tcp(tshark_tcp_layer: dict[str, Any]) -> Base:
    """
    Make a `Base` entry from the `tcp` layer of TShark's `json` output.

    :param tshark_tcp_layer: The `tcp` layer to be parsed.
    :return: An ECS `Base` entry.
    """

    return Base(
        destination=Destination(port=int(tshark_tcp_layer['tcp_tcp_dstport'])),
        network=Network(iana_number=str(socket.IPPROTO_TCP), transport='tcp'),
        source=Source(port=int(tshark_tcp_layer['tcp_tcp_srcport'])),
        tcp=TCP(
            flags=_parse_tcp_flags(tshark_tcp_layer=tshark_tcp_layer) or None,
            sequence_number=(int(seq_num) if (seq_num := tshark_tcp_layer.get('tcp_tcp_seq_raw', None)) else None),
            acknowledgement_number=(int(ack_num) if (ack_num := tshark_tcp_layer.get('tcp_tcp_ack_raw', None)) else None)
        )
    )


def _parse_dns_header_flags(tshark_dns_flags_tree: dict[str, str]) -> list[str]:
    """
    Parse the `dns` layer's `dns.flags_tree` object in accordance with ECS `dns.header_flags`.

    :param tshark_dns_flags_tree: The `dns.flags_tree` object to be parsed.
    :return: A list of DNS header flags.
    """

    dns_flags: list[str] = []

    for key, value in tshark_dns_flags_tree.items():
        if not value:
            continue

        match key:
            case 'dns_flags_authoritative':
                dns_flags.append('AA')
            case 'dns_flags_truncated':
                dns_flags.append('TC')
            case 'dns_flags_recdesired':
                dns_flags.append('RD')
            case 'dns_flags_recavail':
                dns_flags.append('RA')
            case 'dns_flags_authenticated':
                dns_flags.append('AD')
            case 'dns_flags_checkdisabled':
                dns_flags.append('CD')
        # TODO: The documentation also mentions a "DO" flag, but I do not know what it maps to.

    return dns_flags


def _parse_dns_summary_string(summary_string: str) -> tuple[str, str, str | None, str | None] | None:
    """
    Extract values from the summary string used in keys of the `Answers` and `Queries` objects in the `dns` layer.

    :param summary_string: The summary string to be parsed.
    :return: The name, type, and class as present in the summary string.
    """

    if match := _QUERY_PATTERN.match(string=summary_string):
        query_match_dict = match.groupdict()
        return (
            query_match_dict['name'],
            query_match_dict['type'],
            query_match_dict.get('class'),
            query_match_dict.get('data')
        )


def entry_from_dns(
    tshark_dns_layer: dict[str, Any],
    public_suffix_list_trie: PublicSuffixListTrie | None = None,
    hide_opt: bool = True
) -> Base:
    """
    Make a `Base` entry from the `dns` layer of TShark's `json` output.

    :param tshark_dns_layer: The `dns` layer to be parsed.
    :param public_suffix_list_trie:
    :param hide_opt: Whether to hide OPT records.
    :return: An ECS `Base` entry.
    """

    dns_question: DNSQuestion | None = None
    answers: list[DNSAnswer] = []

    if 'text' in tshark_dns_layer:
        # Parse the question.

        tshark_dns_layer['text'] = (
            [text_value] if not isinstance(text_value := tshark_dns_layer['text'], list) else text_value
        )

        if tshark_dns_layer['text'][0] == 'Queries':
            dns_question_summary: tuple[str, str, str | None, str | None] | None = _parse_dns_summary_string(
                summary_string=next(iter(tshark_dns_layer['text'][1:]))
            )
            if dns_question_summary:
                question_name, question_type, question_class, _ = dns_question_summary

                if public_suffix_list_trie and (domain_properties := public_suffix_list_trie.get_domain_properties(domain=question_name)):
                    extra_question_params = dict(
                        registered_domain=domain_properties.registered_domain or None,
                        subdomain=domain_properties.subdomain or None,
                        top_level_domain=domain_properties.effective_top_level_domain or None
                    )
                else:
                    extra_question_params = dict()

                dns_question = DNSQuestion(
                    class_=question_class, name=question_name, type=question_type, **extra_question_params
                )

        # Parse the answers.

        if len(tshark_dns_layer['text']) > 2:
            if ttl_value := tshark_dns_layer.get('dns_dns_resp_ttl'):
                tshark_dns_layer['dns_dns_resp_ttl'] = ([ttl_value] if not isinstance(ttl_value, list) else ttl_value)
            else:
                tshark_dns_layer['dns_dns_resp_ttl'] = []

            for i, answer_summary_string in enumerate(tshark_dns_layer['text'][2:]):
                if answer_summary_string in {'Extraneous data', 'Additional records'}:
                    continue

                answer_result: tuple[str, str, str, str] | None = _parse_dns_summary_string(
                    summary_string=answer_summary_string
                )

                if not answer_result:
                    continue

                answer_name, answer_type, answer_class, answer_data = answer_result

                if answer_type == 'OPT' and hide_opt:
                    continue

                answer_ttl: int | None
                try:
                    answer_ttl = int(tshark_dns_layer['dns_dns_resp_ttl'][i])
                except IndexError:
                    answer_ttl = None

                answers.append(
                    DNSAnswer(class_=answer_class, data=answer_data, name=answer_name, ttl=answer_ttl, type=answer_type)
                )

    # Make the entry.

    return Base(
        dns=DNS(
            answers=answers or None,
            header_flags=_parse_dns_header_flags(
                tshark_dns_flags_tree={
                    key.removeprefix('dns_'): value
                    for key, value in tshark_dns_layer.items()
                    if key.startswith('dns_dns_flags')
                }
            ),
            id=str(int(tshark_dns_layer['dns_dns_id'], 16)),
            op_code=OP_CODE_ID_TO_OP_CODE_NAME.get(int(tshark_dns_layer['dns_dns_flags_opcode']), None),
            question=dns_question,
            resolved_ip=[answer.data for answer in answers if answer.type in {'A', 'AAAA'}] or None,
            response_code=(
                RCODE_ID_TO_RCODE_NAME[int(rcode_value)]
                if (rcode_value := tshark_dns_layer.get('dns_dns_flags_rcode')) is not None
                else None
            ),
            type='answer' if 'dns_dns_response_to' in tshark_dns_layer else 'query'
        ),
        network=Network(protocol='dns')
    )


def entry_from_http(tshark_http_layer: dict[str, Any]) -> Base | None:
    """
    Make a `Base` entry from the `http` layer of TShark's `json` output.

    :param tshark_http_layer: The `http` layer to be parsed.
    :return:
    """

    if 'http_http_request' in tshark_http_layer:
        headers: dict[str, list[str]] = defaultdict(list)

        http_header_strings: str | list[str] = tshark_http_layer.get('http_http_request_line', [])
        if isinstance(http_header_strings, str):
            http_header_strings = [http_header_strings]

        for line in http_header_strings:
            name: str
            value: str
            name, value = line.split(sep=': ', maxsplit=1)
            headers[name.replace('-', '_').lower()].append(value.removesuffix('\r\n'))
        headers = dict(headers)

        base = Base(
            http=Http(
                request=HttpRequest(
                    bytes=int(content_length) if (content_length := tshark_http_layer.get('http_http_content_length') is not None) else None,
                    headers=headers or None,
                    method=tshark_http_layer.get('http_http_request_method'),
                    referrer=(
                        next(iter(referrer_headers), None) if (referrer_headers := headers.get('referrer')) else None
                    ),
                    content_type=headers.get('content_type')
                ),
                version=tshark_http_layer.get('http_http_request_version', '').removeprefix('HTTP/') or None
            ),
            network=Network(protocol='http')
        )

        if full_url := tshark_http_layer.get('http_http_request_full_uri'):
            base.assign(
                value_dict={
                    'url.full': full_url,
                    'url.path': tshark_http_layer.get('http_http_request_uri')
                }
            )

        if user_agent := tshark_http_layer.get('http_http_user_agent'):
            base.set_field_value(field_name='user_agent.original', value=user_agent)

    elif 'http_http_response' in tshark_http_layer:
        headers: dict[str, list[str]] = defaultdict(list)
        for line in tshark_http_layer.get('http_http_response_line', []):
            name: str
            value: str
            name, value = line.split(sep=': ', maxsplit=1)
            headers[name.replace('-', '_').lower()].append(value.removesuffix('\r\n'))
        headers = dict(headers)

        base = Base(
            http=Http(
                response=HttpResponse(
                    bytes=int(content_length) if (content_length := tshark_http_layer.get('http_http_content_length') is not None) else None,
                    headers=headers or None,
                    content_type=headers.get('content_type'),
                    status_code=int(status_code) if (status_code := tshark_http_layer.get('http_http_response_code')) else None,
                    reason_phrase=tshark_http_layer.get('http_http_response_code')
                ),
                version=tshark_http_layer.get('http_http_request_version', '').removeprefix('HTTP/') or None
            ),
            network=Network(protocol='http')
        )

        if full_url := tshark_http_layer.get('http_http_response_for_uri'):
            base.set_field_value(field_name='url.full', value=full_url)
    else:
        return None

    return base


def entry_from_tls(
    tshark_tls_layer: dict[str, Any],
    public_suffix_list_trie: PublicSuffixListTrie | None = None,
    include_supported_ciphers: bool = True
) -> Base | None:
    """

    :param tshark_tls_layer: The `tls` layer to be parsed.
    :param public_suffix_list_trie:
    :param include_supported_ciphers
    :return:
    """

    server_name: str | None = None

    match tshark_tls_layer.get('tls_tls_handshake_type'):
        # "1" corresponds to a "ClientHello" message.
        case '1':
            server_name = tshark_tls_layer.get('tls_tls_handshake_extensions_server_name')

            ja3_ssl_version: str | None = None
            ja3_cipher: str | None = None
            ja3_ssl_extension: str | None = None
            ja3_elliptic_curve: str | None = None
            ja3_elliptic_curve_point_format: str | None = None

            ja3_full = tshark_tls_layer.get('tls_tls_handshake_ja3_full')
            if ja3_full:
                (
                    ja3_ssl_version,
                    ja3_cipher,
                    ja3_ssl_extension,
                    ja3_elliptic_curve,
                    ja3_elliptic_curve_point_format
                ) = ja3_full.split(',')

            supported_ciphers: list[str] | None = None
            if include_supported_ciphers:
                cipher_ids: list[str] = (
                    v if isinstance(v := tshark_tls_layer.get('tls_tls_handshake_ciphersuite', []), list) else [v]
                )
                supported_ciphers: list[str] | None = [
                    CIPHER_ID_TO_CIPHER_NAME.get(int(cipher_id, 16), cipher_id)
                    for cipher_id in cipher_ids
                ] or None

            client_server_params = dict(
                client=TLSClient(
                    server_name=server_name,
                    ja3=tshark_tls_layer.get('tls_tls_handshake_ja3'),
                    ja3_full=ja3_full,
                    ja3_ssl_version=ja3_ssl_version,
                    ja3_cipher=ja3_cipher,
                    ja3_ssl_extension=ja3_ssl_extension,
                    ja3_elliptic_curve=ja3_elliptic_curve,
                    ja3_elliptic_curve_point_format=ja3_elliptic_curve_point_format,
                    supported_ciphers=supported_ciphers
                )
            )
        # "2" corresponds to a "ServerHello" message.
        case '2':
            cipher_id = tshark_tls_layer.get('tls_tls_handshake_ciphersuite')
            curve_id = tshark_tls_layer.get('tls_tls_handshake_extensions_key_share_selected_group')

            client_server_params = dict(
                cipher=CIPHER_ID_TO_CIPHER_NAME.get(int(cipher_id, 16), cipher_id) if cipher_id is not None else None,
                curve=CURVE_ID_TO_NAME.get(int(curve_id), curve_id) if curve_id is not None else None,
                server=TLSServer(
                    ja3s=tshark_tls_layer.get('tls_tls_handshake_ja3s')
                )
            )
        case _:
            return None

    if public_suffix_list_trie and (domain_properties := public_suffix_list_trie.get_domain_properties(domain=server_name or '')):
        extra_destination_params = dict(
            registered_domain=domain_properties.registered_domain or None,
            subdomain=domain_properties.subdomain or None,
            top_level_domain=domain_properties.effective_top_level_domain or None
        )
    else:
        extra_destination_params = dict()

    if handshake_version := tshark_tls_layer.get('tls_tls_handshake_version'):
        tls_version_protocol, tls_version = TLS_VERSION_ID_TO_PAIR.get(int(handshake_version, 16), (None, None))
    else:
        tls_version_protocol, tls_version = None, None

    next_protocol = tshark_tls_layer.get('tls_tls_handshake_extensions_alps_alpn_str')

    # if next_protocol := tshark_tls_layer.get('tls_tls_handshake_extensions_alps_alpn_str'):
    #     next_protocol = [next_protocol] if not isinstance(next_protocol, list) else next_protocol

    return Base(
        destination=Destination(
            domain=server_name,
            **extra_destination_params
        ),
        tls=TLS(
            next_protocol=next_protocol,
            version=tls_version,
            version_protocol=tls_version_protocol,
            **client_server_params
        ),
        network=Network(protocol='tls')
    )


def entry_from_icmp(tshark_icmp_layer: dict[str, Any], layer_name_to_layer_dict: dict[str, Any]) -> Base:
    """

    :param tshark_icmp_layer:
    :param layer_name_to_layer_dict:
    :return:
    """

    version: str | None = None
    transport: str | None = None
    application: str | None = None

    extra_parameters = dict()

    if 'ip' in tshark_icmp_layer:
        if 'udp' in tshark_icmp_layer:
            udp_base: Base = entry_from_udp(tshark_icmp_layer['udp'])
            client_port = udp_base.source.port
            server_port = udp_base.destination.port
        elif 'tcp' in tshark_icmp_layer:
            tcp_base: Base = entry_from_tcp(tshark_icmp_layer['tcp'])
            client_port = tcp_base.source.port
            server_port = tcp_base.destination.port
        else:
            client_port = None
            server_port = None

        ip_base: Base = entry_from_ip(tshark_ip_layer=tshark_icmp_layer['ip'])

        transport = ip_base.network.transport

        extra_parameters = dict(
            client=Client(address=ip_base.source.address, ip=ip_base.source.ip, port=client_port),
            server=Server(address=ip_base.destination.address, ip=ip_base.destination.ip, port=server_port)
        )

        if (last_layer_name := list(layer_name_to_layer_dict.keys())[-1]) != 'icmp':
            application = last_layer_name

    if 'ip' in layer_name_to_layer_dict:
        version = layer_name_to_layer_dict['ip']['ip_ip_version'].removeprefix('ipv')

    icmp_type = int(tshark_icmp_layer['icmp_icmp_type'])
    icmp_code = int(tshark_icmp_layer['icmp_icmp_code'])

    code_to_name = ICMP_TYPE_TO_CODE_TO_NAME.get(icmp_type)

    return Base(
        icmp=ICMP(
            version=version,
            type=icmp_type,
            type_str=ICMP_TYPE_TO_NAME.get(icmp_type),
            code=icmp_code,
            code_str=code_to_name.get(icmp_code) if code_to_name else None,
            transport=transport,
            application=application
        ),
        network=Network(transport='icmp'),
        **extra_parameters
    )

# TODO: Add `dhcpv4` based on Pocketbeat schemas.


def entry_from_nflog(tshark_nflog_layer: dict[str, Any], uid_map: dict[str, dict[str, Any]] | None = None) -> Base | None:
    """
    Make a `Base` entry from the `nflog` layer of TShark's `json` output.

    :param tshark_nflog_layer: The `nflog` layer to be parsed.
    :param uid_map: A map of user id to enrichment information.
    :return: An ECS `Base` entry.
    """

    netfilter_hook: str = NETFILTER_HOOK_ID_TO_NAME[int(tshark_nflog_layer['nflog_nflog_hook'])]

    base = Base(
        observer=Observer(
            egress=ObserverIngressEgress(
                interface=(
                    Interface(id=out_index, name=socket.if_indextoname(int(out_index)))
                    if (out_index := tshark_nflog_layer.get('nflog_nflog_ifindex_outdev'))
                    else None
                )
            ),
            ingress=ObserverIngressEgress(
                interface=(
                    Interface(id=in_index, name=socket.if_indextoname(int(in_index)))
                    if (in_index := tshark_nflog_layer.get('nflog_nflog_ifindex_indev'))
                    else None
                )
            ),
            hook=netfilter_hook
        )
    )

    prefix: str | None
    if prefix := tshark_nflog_layer.get('nflog_nflog_prefix'):
        if match := _RULE_PATTERN.match(string=prefix.rstrip()):
            match_groupdict: dict[str, str] = match.groupdict()

            rule_ruleset: str | None = match_groupdict.get('ruleset')
            if not rule_ruleset:
                match netfilter_hook:
                    case 'input':
                        rule_ruleset = netfilter_hook.upper() + (
                            f'_{name.upper()}'
                            if (name := base.get_field_value(field_name='observer.ingress.interface.name'))
                            else ''
                        )
                    case 'output':
                        rule_ruleset = netfilter_hook.upper() + (
                            f'_{name.upper()}'
                            if (name := base.get_field_value(field_name='observer.egress.interface.name'))
                            else ''
                        )
                    case 'prerouting' | 'forward' | 'postrouting':
                        rule_ruleset = netfilter_hook.upper()

            rule_name: str = match_groupdict['name']

            base.get_field_value(field_name='rule', create_namespaces=True).assign(
                dict(
                    id=f'{rule_ruleset}-{rule_name}' if rule_ruleset else None,
                    ruleset=rule_ruleset,
                    name=rule_name
                )
            )

            event_action: str | None
            event_type: str | None
            match match_groupdict['action']:
                case 'A':
                    event_action = 'accept'
                    event_type = 'allowed'
                case 'D':
                    event_action = 'drop'
                    event_type = 'denied'
                case 'R':
                    event_action = 'reject'
                    event_type = 'denied'
                case 'U':
                    event_action = 'unknown'
                    event_type = None
                case _:
                    event_action = None
                    event_type = None

            if event_action or event_type:
                base.get_field_value(field_name='event', create_namespaces=True).assign(
                    dict(
                        action=event_action,
                        type=['connection'] + ([event_type] if event_type else [])
                    )
                )

    if user_id := tshark_nflog_layer.get('nflog_nflog_uid'):
        user_name: str | None = None
        try:
            from pwd import getpwuid
            user_name = getpwuid(int(user_id)).pw_name
        except:
            pass

        base.assign(
            value_dict={
                'user.id': int(user_id),
                'user.name': user_name
            }
        )

        if user_enrichment_dict := (uid_map or {}).get(user_id):
            for field_name, field_value in user_enrichment_dict.items():
                base.set_field_value(field_name=field_name, value=field_value, create_namespaces=True)

    if group_id := tshark_nflog_layer.get('nflog_nflog_gid'):
        group_name: str | None = None
        try:
            from grp import getgrgid
            group_name = getgrgid(int(group_id)).gr_name
        except:
            pass

        base.assign(
            value_dict={
                'user.group.id': int(group_id),
                'user.group.name': group_name
            }
        )

    return base if base else None


LAYER_TO_FUNC = dict(
    nflog=entry_from_nflog,
    ip=entry_from_ip,
    ipv6=entry_from_ipv6,
    udp=entry_from_udp,
    tcp=entry_from_tcp,
    icmp=entry_from_icmp,
    dns=entry_from_dns,
    tls=entry_from_tls,
    http=entry_from_http
)


@dataclass
class ParseResult:
    base: Base
    extra: dict[str, Any]


def handle_tshark_dict(
    tshark_dict: dict[str, Any],
    public_suffix_list: PublicSuffixListTrie = None,
    uid_map: dict[str, dict[str, Any]] | None = None,
    line: str | None = None
) -> ParseResult | None:
    """

    :param tshark_dict:
    :param public_suffix_list:
    :param uid_map: A map of UIDs to enrichment information.
    :param line: The original TShark line, provided for logging purposes.
    :return:
    """

    if 'layers' not in tshark_dict:
        return None

    layer_name_to_layer_dict: dict[str, dict[str, str] | list] = tshark_dict['layers']

    frame_layer: dict[str, Any] = tshark_dict['layers'].pop('frame')

    base_entry: Base | None = None

    for i, (layer_name, layer_dict) in enumerate(layer_name_to_layer_dict.items()):
        layer_dict_list = layer_dict if isinstance(layer_dict, list) else [layer_dict]

        if layer_name == 'quic':
            effective_layer_names: list[str] = []
            effective_layer_dicts: list[dict] = []

            for quic_layer_dict in layer_dict_list:
                if name := next((name for name in quic_layer_dict.keys() if name in LAYER_TO_FUNC), None):
                    quic_layer_dict_inner: dict | list[dict] = quic_layer_dict[name]
                    if isinstance(quic_layer_dict_inner, list):
                        for d in quic_layer_dict_inner:
                            effective_layer_names.append(name)
                            effective_layer_dicts.append(d)
                    else:
                        effective_layer_names.append(name)
                        effective_layer_dicts.append(quic_layer_dict_inner)
            if not effective_layer_names:
                continue
        else:
            effective_layer_names = [layer_name]
            effective_layer_dicts = layer_dict_list

        for effective_layer_name, effective_layer_dict in zip_longest(effective_layer_names, effective_layer_dicts, fillvalue=effective_layer_names[0]):
            layer_func = LAYER_TO_FUNC.get(effective_layer_name)
            if not layer_func:
                continue

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
                case 'nflog':
                    layer_func = partial(layer_func, uid_map=uid_map)

            line_base_entry: Base | None = layer_func(effective_layer_dict)
            if line_base_entry:
                break
        else:
            continue

        # Merge the current layer's base entry with the one for the previous layers.
        base_entry = base_entry or Base()
        base_entry |= line_base_entry

        # If the layer name is `icmp`, any remaining layers are just "metadata".
        if layer_name == 'icmp':
            break

    if base_entry is not None:
        timestamp: datetime
        try:
            timestamp = datetime.fromtimestamp(float(frame_layer['frame_frame_time_epoch']))
        except ValueError:
            timestamp = datetime.fromisoformat(frame_layer['frame_frame_time_epoch'])

        base_entry.set_field_value(field_name='event.created', value=timestamp)

        extra_dict = dict(
            interface=frame_layer['frame_frame_interface_name'],
            protocols=frame_layer['frame_frame_protocols'].split(':'),
            expert_info=get_expert_info(tshark_layer_dict=tshark_dict['layers']),
        )

        if nflog_timestamp := layer_name_to_layer_dict.get('nflog', {}).get('nflog_nflog_timestamp', None):
            # NOTE: The timestamp seems to always have `.000`... Seems like a bug?
            extra_dict['timestamp'] = nflog_timestamp.replace('.000', '.')

        return ParseResult(base=base_entry, extra=extra_dict)

    return base_entry
