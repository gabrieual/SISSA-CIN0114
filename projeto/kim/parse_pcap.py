"""
Extração de mensagens SOME/IP a partir dos arquivos pcap do dataset de Kim et al. (2026).

Objetivo
--------
Converter cada captura (.pcap) em uma tabela com uma linha por mensagem SOME/IP, no mesmo
formato do arquivo data/raw/data.csv usado pelo SISSA. A tabela resultante pode então passar
pelo mesmo pré-processamento do artigo original (one-hot, normalização e janelas).

Formato de saída (colunas na ordem do data.csv do SISSA)
-------------------------------------------------------
    time          instante de captura do pacote, em segundos (época Unix)
    src, dst      endereços IPv4 de origem e destino, como texto
    method        Method ID do cabeçalho SOME/IP
    length        campo Length do cabeçalho SOME/IP
    client        Client ID
    session       Session ID
    protocol      Protocol Version
    interface     Interface Version
    message_type  tipo da mensagem como texto (REQUEST, REQUEST_NO_RETURN, NOTIFICATION,
                  RESPONSE, ERROR), conforme preprocess/utils.py do SISSA
    err_code      Return Code como texto (E_OK, E_NOT_OK, ...), conforme preprocess/utils.py

Colunas auxiliares (não utilizadas pelo SISSA; servem à rotulagem e à análise)
-----------------------------------------------------------------------------
    frame         número do pacote na captura (iniciando em 1, como no Wireshark)
    transport     'UDP' ou 'TCP'
    service       Service ID do cabeçalho SOME/IP
    is_sd         True para mensagens SOME/IP-SD (Service ID 0xFFFF, Method ID 0x8100)

Decisões de extração
--------------------
- São considerados apenas quadros Ethernet com IPv4 e transporte UDP ou TCP. Pacotes de
  outros protocolos (por exemplo, IGMP e ARP) são descartados, pois não transportam SOME/IP.
- Um mesmo segmento UDP ou TCP pode conter várias mensagens SOME/IP; cada uma gera uma linha.
- Segmentos sem carga útil (por exemplo, confirmações TCP) não geram linhas.
- Mensagens cujo cabeçalho não é válido (versão de protocolo diferente de 1) ou que estão
  incompletas no segmento (fragmentadas entre segmentos TCP) são contabilizadas e descartadas.
- Tipos de mensagem e códigos de retorno fora dos conjuntos reconhecidos pelo SISSA são
  mantidos com valor nulo e contabilizados, para que a política de descarte seja decidida
  e documentada na etapa seguinte.

A leitura do arquivo pcap é feita diretamente sobre os bytes (formato pcap clássico), sem
dependências externas, para reduzir o tempo de processamento em capturas com milhões de pacotes.
"""

from __future__ import annotations

import collections
import socket
import struct

import pandas as pd

# Tipos de mensagem reconhecidos pelo SISSA (preprocess/utils.py, message_type_i2s).
# Os bits 0x20 (TP, segmentação) e 0x40 (ACK) não são tratados pelo SISSA; mensagens com
# esses bits ficam com tipo nulo.
MESSAGE_TYPES = {
    0x00: "REQUEST",
    0x01: "REQUEST_NO_RETURN",
    0x02: "NOTIFICATION",
    0x80: "RESPONSE",
    0x81: "ERROR",
}

# Códigos de retorno reconhecidos pelo SISSA (preprocess/utils.py, err_code_i2s).
RETURN_CODES = {
    0x00: "E_OK",
    0x01: "E_NOT_OK",
    0x02: "E_UNKNOWN_SERVICE",
    0x03: "E_UNKNOWN_METHOD",
    0x04: "E_NOT_READY",
    0x05: "E_NOT_REACHABLE",
    0x06: "E_TIMEOUT",
    0x07: "E_WRONG_PROTOCOL_VERSION",
    0x08: "E_WRONG_INTERFACE_VERSION",
    0x09: "E_MALFORMED_MESSAGE",
    0x0A: "E_WRONG_MESSAGE_TYPE",
}

SISSA_COLUMNS = [
    "time", "src", "dst", "method", "length", "client", "session",
    "protocol", "interface", "message_type", "err_code",
]
AUX_COLUMNS = ["frame", "transport", "service", "is_sd"]

SOMEIP_HEADER_LEN = 16
SD_SERVICE_ID = 0xFFFF
SD_METHOD_ID = 0x8100

# Tipos de enlace suportados (cabeçalho global do pcap, campo "network").
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113


def _read_pcap(path: str):
    """
    Percorre um arquivo pcap clássico e produz, para cada pacote, a tupla
    (número do quadro, instante em segundos, tipo de enlace, bytes do quadro).

    Suporta as duas ordens de bytes e as variantes com resolução de microssegundos
    e de nanossegundos. Arquivos pcapng não são suportados e geram ValueError.
    """
    with open(path, "rb") as f:
        header = f.read(24)
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, ts_div = "<", 1e6
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, ts_div = ">", 1e6
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, ts_div = "<", 1e9
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, ts_div = ">", 1e9
        else:
            raise ValueError(f"{path}: formato não suportado (esperado pcap clássico; pcapng não é aceito)")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        record = struct.Struct(endian + "IIII")

        frame = 0
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig_len = record.unpack(rec)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            frame += 1
            yield frame, ts_sec + ts_frac / ts_div, linktype, data


def _ipv4_offset(linktype: int, data: bytes) -> int | None:
    """Retorna a posição do cabeçalho IPv4 no quadro, ou None se o quadro não for IPv4."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = data[12:14]
        offset = 14
        # Quadros com marcação VLAN (802.1Q): o EtherType real vem 4 bytes depois.
        if ethertype == b"\x81\x00" and len(data) >= 18:
            ethertype = data[16:18]
            offset = 18
        return offset if ethertype == b"\x08\x00" else None
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        return 16 if data[14:16] == b"\x08\x00" else None
    return None


def parse_pcap(path: str) -> tuple[pd.DataFrame, dict]:
    """
    Extrai as mensagens SOME/IP de um arquivo pcap.

    Parâmetros
    ----------
    path : caminho do arquivo .pcap.

    Retorna
    -------
    tabela : DataFrame com as colunas SISSA_COLUMNS seguidas de AUX_COLUMNS, uma linha por
             mensagem SOME/IP, em ordem de captura.
    estatisticas : dicionário com as contagens de cada situação de descarte, para validação
                   e documentação na seção de metodologia.
    """
    stats = collections.Counter()
    rows = []
    unpack_header = struct.Struct(">HHIHHBBBB").unpack_from

    for frame, ts, linktype, data in _read_pcap(path):
        stats["pacotes"] += 1

        ip = _ipv4_offset(linktype, data)
        if ip is None:
            stats["descartados_nao_ipv4"] += 1
            continue

        ihl = (data[ip] & 0x0F) * 4
        proto = data[ip + 9]
        frag = struct.unpack_from(">H", data, ip + 6)[0]
        if frag & 0x1FFF:
            # Fragmento IP que não é o primeiro: não contém cabeçalho de transporte.
            stats["descartados_fragmento_ip"] += 1
            continue

        l4 = ip + ihl
        if proto == 17:
            transport = "UDP"
            payload_start = l4 + 8
        elif proto == 6:
            transport = "TCP"
            payload_start = l4 + (data[l4 + 12] >> 4) * 4
        else:
            stats[f"descartados_protocolo_{proto}"] += 1
            continue

        # O fim da carga útil é definido pelo tamanho total do datagrama IP, o que exclui
        # eventuais bytes de preenchimento (padding) do quadro Ethernet.
        ip_total_len = struct.unpack_from(">H", data, ip + 2)[0]
        payload_end = min(ip + ip_total_len, len(data))
        if payload_end - payload_start <= 0:
            stats[f"segmentos_{transport}_sem_carga"] += 1
            continue

        src = socket.inet_ntoa(data[ip + 12: ip + 16])
        dst = socket.inet_ntoa(data[ip + 16: ip + 20])

        # Percorre as mensagens SOME/IP contidas no segmento.
        offset = payload_start
        while offset < payload_end:
            if payload_end - offset < SOMEIP_HEADER_LEN:
                stats["mensagens_incompletas"] += 1
                break
            (service, method, length, client, session,
             protocol, interface, mtype, rcode) = unpack_header(data, offset)
            if protocol != 1:
                stats["cargas_sem_cabecalho_someip_valido"] += 1
                break
            total = 8 + length  # o campo Length conta os bytes a partir do Request ID
            if offset + total > payload_end:
                stats["mensagens_incompletas"] += 1
                break

            message_type = MESSAGE_TYPES.get(mtype)
            err_code = RETURN_CODES.get(rcode)
            if message_type is None:
                stats[f"tipo_desconhecido_0x{mtype:02x}"] += 1
            if err_code is None:
                stats[f"codigo_retorno_desconhecido_0x{rcode:02x}"] += 1

            is_sd = service == SD_SERVICE_ID and method == SD_METHOD_ID
            rows.append((ts, src, dst, method, length, client, session, protocol, interface,
                         message_type, err_code, frame, transport, service, is_sd))
            stats["mensagens"] += 1
            offset += total

    tabela = pd.DataFrame(rows, columns=SISSA_COLUMNS + AUX_COLUMNS)
    return tabela, dict(stats)
