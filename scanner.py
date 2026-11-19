import socket
import argparse
import ctypes
import os
import select
import struct
import sys
import time
import zlib

SO_ATTACH_FILTER = 26

# Pre-compiled native struct codecs for zero-allocation serialization
S_H = struct.Struct("!H")
S_HI = struct.Struct("!HI")
S_I = struct.Struct("!I")
S_Q = struct.Struct("!Q")
S_BPF_INSN = struct.Struct("HBBI")
S_BPF_PROG = struct.Struct("HP")
S_IP_FRAG = struct.Struct("!BBHHH")
S_TCP_RX = struct.Struct("!HHIIBB")
S_ICMP_HDR = struct.Struct("!BB")
S_INNER_IP = struct.Struct("!BBHHHBBH4s4s")
S_INNER_TCP = struct.Struct("!HHI")

# Pre-shifted IPv4 slice [Flags/Frag(DF=0x4000) | TTL(64=0x40) | Proto(TCP=0x06) | Pad(0x0000)]
IP_MID_CONST_SHIFTED = 0x400040060000

ICMP_UNREACH_CODES = {
    0: "NET_UNREACHABLE",
    1: "HOST_UNREACHABLE",
    2: "PROTO_UNREACHABLE",
    3: "CLOSED (ICMP Port Unreachable)",
    9: "FILTERED (Net Admin Prohibited)",
    10: "FILTERED (Host Admin Prohibited)",
    13: "FILTERED (Comm Admin Prohibited)",
}


def get_route_source_ip(dst_ip: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((dst_ip, 80))
        return s.getsockname()[0]


def raw_words_sum(data: bytes | bytearray) -> int:
    if len(data) & 1:
        data = bytes(data) + b"\x00"
    return sum(struct.unpack(f"!{len(data) >> 1}H", data))


def fold_checksum(s: int) -> int:
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s & 0xFFFF) or 0xFFFF


def attach_tcp_l3_l4_bpf(
    sock: socket.socket, target_ip: str, local_port: int
) -> None:
    """Attaches classic BPF filter dropping packets where IP.src != target_ip

    or TCP.dst != local_port. Dynamic IHL resolution via BPF_MSH.
    """
    ip_int = int.from_bytes(socket.inet_aton(target_ip), "big")
    insns = b"".join((
        # BPF_LD | BPF_W | BPF_ABS: A = Pkt[12..15] (IPv4 Src IP)
        S_BPF_INSN.pack(0x20, 0, 0, 12),
        # BPF_JMP | BPF_JEQ | BPF_K: if (A == target_ip) continue else drop
        S_BPF_INSN.pack(0x15, 0, 4, ip_int),
        # BPF_LDX | BPF_B | BPF_MSH: X = 4 * (Pkt[0] & 0x0F) (Variable IHL offset)
        S_BPF_INSN.pack(0xB1, 0, 0, 0),
        # BPF_LD | BPF_H | BPF_IND: A = Pkt[X + 2 .. X + 3] (TCP Dst Port)
        S_BPF_INSN.pack(0x48, 0, 0, 2),
        # BPF_JMP | BPF_JEQ | BPF_K: if (A == local_port) accept else drop
        S_BPF_INSN.pack(0x15, 0, 1, local_port),
        # BPF_RET | BPF_K: Accept (snaplen=0xFFFF)
        S_BPF_INSN.pack(0x06, 0, 0, 0xFFFF),
        # BPF_RET | BPF_K: Drop (snaplen=0)
        S_BPF_INSN.pack(0x06, 0, 0, 0x0000),
    ))
    buf = ctypes.create_string_buffer(insns, len(insns))
    fprog = S_BPF_PROG.pack(7, ctypes.addressof(buf))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


class FastPacketFactory:
    __slots__ = (
        "src_addr",
        "dst_addr",
        "src_port",
        "_syn_buf",
        "_rst_buf",
        "_base_ip_syn_sum",
        "_base_tcp_syn_sum",
        "_base_ip_rst_sum",
        "_base_tcp_rst_sum",
    )

    def __init__(self, src_ip: str, dst_ip: str, src_port: int):
        self.src_addr = socket.inet_aton(src_ip)
        self.dst_addr = socket.inet_aton(dst_ip)
        self.src_port = src_port

        # Template SYN: 60 bytes (IPv4=20B + TCP=40B with MSS, SACK-Permitted, TS, WScale)
        self._syn_buf = bytearray(60)
        struct.pack_into(
            "!BBHHHBBH4s4s",
            self._syn_buf,
            0,
            0x45,
            0x00,
            60,
            0,
            0x4000,
            64,
            socket.IPPROTO_TCP,
            0,
            self.src_addr,
            self.dst_addr,
        )
        self._base_ip_syn_sum = raw_words_sum(self._syn_buf[0:20])

        struct.pack_into(
            "!HHIIBBHHH",
            self._syn_buf,
            20,
            src_port,
            0,
            0,
            0,
            (10 << 4),
            0x02,
            64240,
            0,
            0,
        )
        struct.pack_into(
            "!BBHBBBBIIBBBB",
            self._syn_buf,
            40,
            2,
            4,
            1460,
            4,
            2,
            8,
            10,
            0,
            0,
            1,
            3,
            3,
            7,
        )
        pseudo_syn = struct.pack(
            "!4s4sBBH", self.src_addr, self.dst_addr, 0, socket.IPPROTO_TCP, 40
        )
        self._base_tcp_syn_sum = raw_words_sum(pseudo_syn) + raw_words_sum(
            self._syn_buf[20:60]
        )

        # Template RST: 40 bytes (IPv4=20B + TCP=20B minimal, no options)
        self._rst_buf = bytearray(40)
        struct.pack_into(
            "!BBHHHBBH4s4s",
            self._rst_buf,
            0,
            0x45,
            0x00,
            40,
            0,
            0x4000,
            64,
            socket.IPPROTO_TCP,
            0,
            self.src_addr,
            self.dst_addr,
        )
        self._base_ip_rst_sum = raw_words_sum(self._rst_buf[0:20])

        struct.pack_into(
            "!HHIIBBHHH",
            self._rst_buf,
            20,
            src_port,
            0,
            0,
            0,
            (5 << 4),
            0x04,
            0,
            0,
            0,
        )
        pseudo_rst = struct.pack(
            "!4s4sBBH", self.src_addr, self.dst_addr, 0, socket.IPPROTO_TCP, 20
        )
        self._base_tcp_rst_sum = raw_words_sum(pseudo_rst) + raw_words_sum(
            self._rst_buf[20:40]
        )

    def build_syn_fast(
        self, dst_port: int, isn: int, ts_val: int
    ) -> bytearray:
        buf = self._syn_buf
        isn_hi, isn_lo = isn >> 16, isn & 0xFFFF
        ip_id = (isn_hi ^ isn_lo) or 1

        ip_chk = fold_checksum(self._base_ip_syn_sum + ip_id)
        tcp_chk = fold_checksum(
            self._base_tcp_syn_sum
            + dst_port
            + isn_hi
            + isn_lo
            + (ts_val >> 16)
            + (ts_val & 0xFFFF)
        )

        # 64-bit atomic store across offsets 4..11: [IP_ID:16 | Flags/Frag:16 | TTL/Proto:16 | IP_Chk:16]
        S_Q.pack_into(
            buf, 4, (ip_id << 48) | IP_MID_CONST_SHIFTED | ip_chk
        )
        S_HI.pack_into(buf, 22, dst_port, isn)
        S_H.pack_into(buf, 36, tcp_chk)
        S_I.pack_into(buf, 48, ts_val)
        return buf

    def build_rst_fast(self, dst_port: int, seq_num: int) -> bytearray:
        buf = self._rst_buf
        seq_hi, seq_lo = seq_num >> 16, seq_num & 0xFFFF
        ip_id = (seq_hi ^ seq_lo) or 1

        ip_chk = fold_checksum(self._base_ip_rst_sum + ip_id)
        tcp_chk = fold_checksum(
            self._base_tcp_rst_sum + dst_port + seq_hi + seq_lo
        )

        S_Q.pack_into(
            buf, 4, (ip_id << 48) | IP_MID_CONST_SHIFTED | ip_chk
        )
        S_HI.pack_into(buf, 22, dst_port, seq_num)
        S_H.pack_into(buf, 36, tcp_chk)
        return buf


class UltimaZeroScanner:

    def __init__(self, dst_ip: str, ports: list[int], timeout: float = 2.0):
        self.dst_ip = socket.gethostbyname(dst_ip)
        self.src_ip = get_route_source_ip(self.dst_ip)
        self.ports = set(ports)
        self.timeout = timeout
        self.results: dict[int, str] = {}

        # Ephemeral port reservation: pins the port in Linux TCP/IP stack to prevent port allocation collisions
        self._port_lock_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._port_lock_sock.bind((self.src_ip, 0))
        self.src_port = self._port_lock_sock.getsockname()[1]

        self.factory = FastPacketFactory(
            self.src_ip, self.dst_ip, self.src_port
        )

        seed = int.from_bytes(os.urandom(4), "big")
        prefix = struct.pack(
            "!4s4sHI",
            self.factory.src_addr,
            self.factory.dst_addr,
            self.src_port,
            seed,
        )
        self._base_crc = zlib.crc32(prefix)

        self._rx_buf = bytearray(65536)
        self._rx_view = memoryview(self._rx_buf)

    def _fast_isn(self, dst_port: int) -> int:
        return zlib.crc32(S_H.pack(dst_port), self._base_crc) & 0xFFFFFFFF

    def _handle_tcp_rx(self, nbytes: int, send_fn) -> None:
        if nbytes < 40:
            return
        buf = self._rx_view
        ver_ihl, _, _, _, frag_word = S_IP_FRAG.unpack_from(buf, 0)
        if (ver_ihl >> 4) != 4 or (frag_word & 0x3FFF) != 0:
            return

        ihl = (ver_ihl & 0x0F) << 2
        if ihl < 20 or nbytes < ihl + 20:
            return

        r_sport, r_dport, r_seq, r_ack, _, flags = S_TCP_RX.unpack_from(
            buf, ihl
        )
        if (
            r_dport != self.src_port
            or r_sport not in self.ports
            or r_sport in self.results
        ):
            return

        expected_isn = self._fast_isn(r_sport)
        expected_ack = (expected_isn + 1) & 0xFFFFFFFF

        # RFC 793/5961: Validate RST sequence. Strict matching against ISN space for bare-RST edge cases
        if flags & 0x04:
            if flags & 0x10:
                if r_ack != expected_ack:
                    return
            else:
                if r_seq not in (0, expected_isn, expected_ack):
                    return
            self.results[r_sport] = "CLOSED (TCP RST)"
            return

        # Target SYN-ACK ingress: acknowledge state and issue immediate RST to release target TCB allocation
        if (flags & 0x12) == 0x12 and r_ack == expected_ack:
            self.results[r_sport] = "OPEN (SYN-ACK)"
            send_fn(self.factory.build_rst_fast(r_sport, r_ack))

    def _handle_icmp_rx(self, nbytes: int) -> None:
        if nbytes < 56:
            return
        buf = self._rx_view
        ver_ihl, _, _, _, frag_word = S_IP_FRAG.unpack_from(buf, 0)
        if (ver_ihl >> 4) != 4 or (frag_word & 0x3FFF) != 0:
            return

        ihl_out = (ver_ihl & 0x0F) << 2
        if ihl_out < 20 or nbytes < ihl_out + 36:
            return

        icmp_type, icmp_code = S_ICMP_HDR.unpack_from(buf, ihl_out)
        if icmp_type != 3:
            return

        inner_ip_off = ihl_out + 8
        in_ver_ihl, _, _, _, _, _, in_proto, _, _, in_dst = (
            S_INNER_IP.unpack_from(buf, inner_ip_off)
        )
        ihl_in = (in_ver_ihl & 0x0F) << 2

        if in_proto != socket.IPPROTO_TCP or in_dst != self.factory.dst_addr:
            return
        if nbytes < inner_ip_off + ihl_in + 8:
            return

        orig_sport, orig_dport, orig_seq = S_INNER_TCP.unpack_from(
            buf, inner_ip_off + ihl_in
        )
        if (
            orig_sport != self.src_port
            or orig_dport not in self.ports
            or orig_dport in self.results
        ):
            return

        if orig_seq == self._fast_isn(orig_dport):
            self.results[orig_dport] = ICMP_UNREACH_CODES.get(
                icmp_code, f"FILTERED (ICMP Code {icmp_code})"
            )

    def _drain_fd(
        self,
        fd: int,
        tcp_fd: int,
        tcp_sock: socket.socket,
        icmp_sock: socket.socket,
        send_fn,
    ) -> None:
        sock = tcp_sock if fd == tcp_fd else icmp_sock
        is_tcp = fd == tcp_fd
        rx_buf = self._rx_buf
        while True:
            try:
                nbytes = sock.recv_into(rx_buf)
            except BlockingIOError:
                break
            # Guard against zero-byte spin-lock on peer teardown / interface de-registration
            if not nbytes:
                break
            if is_tcp:
                self._handle_tcp_rx(nbytes, send_fn)
            else:
                self._handle_icmp_rx(nbytes)

    def execute(self) -> dict[int, str]:
        try:
            with (
                socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
                ) as tcp_sock,
                socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
                ) as icmp_sock,
                select.epoll() as epoll,
            ):
                tcp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                tcp_sock.setblocking(False)
                icmp_sock.setblocking(False)

                attach_tcp_l3_l4_bpf(tcp_sock, self.dst_ip, self.src_port)

                # Connect raw socket: binds kernel peer address, offloading routing cache lookup to send()
                tcp_sock.connect((self.dst_ip, 0))

                tcp_fd = tcp_sock.fileno()
                icmp_fd = icmp_sock.fileno()
                epoll.register(tcp_fd, select.EPOLLIN)
                epoll.register(icmp_fd, select.EPOLLIN)

                build_syn = self.factory.build_syn_fast
                fast_isn = self._fast_isn
                send = tcp_sock.send
                ts_val = int(time.monotonic() * 1000) & 0xFFFFFFFF

                # TX loop: burst egress transmission interleaved with ingress drains to prevent ring buffer drops
                for idx, dport in enumerate(self.ports, 1):
                    send(build_syn(dport, fast_isn(dport), ts_val))

                    if (idx & 63) == 0:
                        ts_val = int(time.monotonic() * 1000) & 0xFFFFFFFF
                        for fd, _ in epoll.poll(0.0):
                            self._drain_fd(
                                fd, tcp_fd, tcp_sock, icmp_sock, send
                            )

                # RX collection phase: wait on epoll event loop until results converge or timeout expires
                deadline = time.monotonic() + self.timeout
                total_ports = len(self.ports)
                while len(self.results) < total_ports:
                    rem = deadline - time.monotonic()
                    if rem <= 0:
                        break
                    events = epoll.poll(rem)
                    if not events:
                        break
                    for fd, _ in events:
                        self._drain_fd(fd, tcp_fd, tcp_sock, icmp_sock, send)
        finally:
            self._port_lock_sock.close()

        for p in sorted(self.ports):
            self.results.setdefault(p, "FILTERED (Timeout)")

        return dict(sorted(self.results.items()))


def parse_ports(port_spec: str) -> list[int]:
    res = set()
    for part in port_spec.split(","):
        if "-" in part:
            a, b = map(int, part.split("-"))
            res.update(range(a, b + 1))
        else:
            res.add(int(part))
    return sorted(res)


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[!] Требуются права root (sudo) для SOCK_RAW и SO_ATTACH_FILTER.")

    parser = argparse.ArgumentParser(description="Ultima Absolute Zero Raw Scanner")
    parser.add_argument("target", help="Целевой хост или IP")
    parser.add_argument("-p", "--ports", default="21,22,80,443,3306,8080", help="Порты (напр. 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Дедлайн ожидания (сек)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    scanner = UltimaZeroScanner(args.target, ports, timeout=args.timeout)

    print(f"[*] Target: {scanner.dst_ip} | Locked Ephemeral Source: {scanner.src_ip}:{scanner.src_port}")
    t0 = time.perf_counter()
    res = scanner.execute()
    dt = (time.perf_counter() - t0) * 1000

    for port, state in res.items():
        if "OPEN" in state or len(ports) <= 30:
            print(f"Port {port:<5} | {state}")
    print(f"[+] Scanned {len(ports)} ports in {dt:.2f} ms")
