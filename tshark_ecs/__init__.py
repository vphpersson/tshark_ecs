import socket
from typing import Any, Final
from re import compile as re_compile, Pattern as RePattern

from ecs_py import DNS, DNSAnswer, DNSQuestion, Base, Source, Destination, Network, TLS, TLSClient, TLSServer, ICMP, Client, Server
from public_suffix.structures.public_suffix_list_trie import PublicSuffixListTrie

SPEC_LAYER_PATTERN: Final[RePattern] = re_compile(pattern='^(?P<layer_name>[A-Za-z]+)')

_QUERY_PATTERN: Final[RePattern] = re_compile(
    pattern=r'^(?P<name>.+): type (?P<type>.+)(,\s*class (?P<class>[^,]+)(,.+ (?P<data>.+))?)?$'
)

OP_CODE_ID_TO_OP_CODE_NAME: Final[dict[int, str]] = {0: 'QUERY'}
RCODE_ID_TO_RCODE_NAME: Final[dict[int, str]] = {
    0: 'NOERROR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    5: 'REFUSED'
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


def entry_from_ip(tshark_ip_layer: dict[str, Any]) -> Base:
    """
    Make a `Base` entry from the `ip` layer of TShark's `json` output.

    :param tshark_ip_layer: The `ip` layer to be parsed.
    :return: An ECS `Base` entry.
    """

    destination_ip: str = tshark_ip_layer['ip_ip_dst']
    source_ip: str = tshark_ip_layer['ip_ip_src']
    protocol_number: str = tshark_ip_layer['ip_ip_proto']

    # TODO: Move.
    # TODO: The documentation mentions other values for network type; not sure how those are derived.
    network_type: str | None = None
    match tshark_ip_layer.get('ip_ip_version'):
        case '4':
            network_type = 'ipv4'
        case '6':
            network_type = 'ipv6'

    return Base(
        destination=Destination(address=destination_ip, ip=destination_ip),
        network=Network(
            iana_number=protocol_number,
            transport=PROTO_ID_TO_PROTO_NAME[int(protocol_number)],
            type=network_type
        ),
        source=Source(address=source_ip, ip=source_ip),
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


def entry_from_tcp(tshark_tcp_layer: dict[str, Any]) -> Base:
    """
    Make a `Base` entry from the `tcp` layer of TShark's `json` output.

    :param tshark_tcp_layer: The `tcp` layer to be parsed.
    :return: An ECS `Base` entry.
    """

    return Base(
        destination=Destination(port=int(tshark_tcp_layer['tcp_tcp_dstport'])),
        network=Network(iana_number=str(socket.IPPROTO_TCP), transport='tcp'),
        source=Source(port=int(tshark_tcp_layer['tcp_tcp_srcport']))
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


def _parse_dns_summary_string(summary_string: str) -> tuple[str, str, str | None, str | None]:
    """
    Extract values from the summary string used in keys of the `Answers` and `Queries` objects in the `dns` layer.

    :param summary_string: The summary string to be parsed.
    :return: The name, type, and class as present in the summary string.
    """

    query_match_dict: dict[str, str] = _QUERY_PATTERN.match(string=summary_string).groupdict()
    return query_match_dict['name'], query_match_dict['type'], query_match_dict.get('class'), query_match_dict.get('data')


def entry_from_dns(
    tshark_dns_layer: dict[str, Any],
    public_suffix_list_trie: PublicSuffixListTrie | None = None
) -> Base:
    """
    Make a `Base` entry from the `dns` layer of TShark's `json` output.

    :param tshark_dns_layer: The `dns` layer to be parsed.
    :param public_suffix_list_trie:
    :return: An ECS `Base` entry.
    """

    # Parse the question.

    tshark_dns_layer['text'] = (
        [text_value] if not isinstance(text_value := tshark_dns_layer['text'], list) else text_value
    )

    question_name, question_type, question_class, _ = _parse_dns_summary_string(
        summary_string=next(iter(tshark_dns_layer['text']))
    )

    if public_suffix_list_trie and (domain_properties := public_suffix_list_trie.get_domain_properties(domain=question_name)):
        extra_question_params = dict(
            registered_domain=domain_properties.registered_domain or None,
            subdomain=domain_properties.subdomain or None,
            top_level_domain=domain_properties.effective_top_level_domain or None
        )
    else:
        extra_question_params = dict()

    # Parse the answers.

    answers: list[DNSAnswer] = []

    if len(tshark_dns_layer['text']) > 1:
        if ttl_value := tshark_dns_layer.get('dns_dns_resp_ttl'):
            tshark_dns_layer['dns_dns_resp_ttl'] = ([ttl_value] if not isinstance(ttl_value, list) else ttl_value)

        for i, answer_summary_string in enumerate(tshark_dns_layer['text'][1:]):
            answer_name, answer_type, answer_class, answer_data = _parse_dns_summary_string(
                summary_string=answer_summary_string
            )

            answer_ttl: int | None = (
                int(tshark_dns_layer['dns_dns_resp_ttl'][i]) if 'dns_dns_resp_ttl' in tshark_dns_layer
                else None
            )

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
            op_code=OP_CODE_ID_TO_OP_CODE_NAME[int(tshark_dns_layer['dns_dns_flags_opcode'])],
            question=DNSQuestion(
                class_=question_class, name=question_name, type=question_type, **extra_question_params
            ),
            resolved_ip=[answer.data for answer in answers if answer.type in {'A', 'AAAA'}] or None,
            response_code=(
                RCODE_ID_TO_RCODE_NAME[int(rcode_value)]
                if (rcode_value := tshark_dns_layer.get('dns_dns_flags_rcode')) is not None
                else None
            ),
            type='answer' if 'dns_dns_response_to' in tshark_dns_layer else 'question'
        )
    )


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

    # "22" corresponds to a handshake record.
    if tshark_tls_layer.get('tls_tls_record_content_type') != '22':
        return None

    server_name: str | None = None

    match tshark_tls_layer.get('tls_tls_handshake_type'):
        # "1" corresponds to a "ClientHello" message.
        case '1':
            server_name = tshark_tls_layer.get('tls_tls_handshake_extensions_server_name')
            client_server_params = dict(
                client=TLSClient(
                    server_name=server_name,
                    ja3=tshark_tls_layer.get('tls_tls_handshake_ja3'),
                    supported_ciphers=([
                        CIPHER_ID_TO_CIPHER_NAME.get(int(cipher_id, 16), cipher_id)
                        for cipher_id in tshark_tls_layer.get('tls_tls_handshake_ciphersuite', [])
                    ] or None) if include_supported_ciphers else None
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
        )
    )


def entry_from_icmp(tshark_icmp_layer: dict[str, Any], layers: dict[str, Any]) -> Base:
    """

    :param tshark_icmp_layer:
    :param layers:
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

        if (last_layer_name := list(layers.keys())[-1]) != 'icmp':
            application = last_layer_name

    if 'ip' in layers:
        version = layers['ip']['ip_ip_version'].removeprefix('ipv')

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


_LAYER_MAP = [
    dict(),
    {'ip': entry_from_ip},
    {'udp': entry_from_udp, 'tcp': entry_from_tcp, 'icmp': entry_from_icmp},
    {'dns': entry_from_dns, 'tls': entry_from_tls}
]
