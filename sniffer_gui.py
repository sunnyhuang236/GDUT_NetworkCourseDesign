import socket
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import subprocess
from datetime import datetime
import ctypes
import sys
import time


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


class Packet:
    def __init__(self, number, timestamp, relative_time, raw_data, eth_info, ip_info, transport_info, info):
        self.number = number
        self.timestamp = timestamp
        self.relative_time = relative_time
        self.raw_data = raw_data
        self.eth_info = eth_info
        self.ip_info = ip_info
        self.transport_info = transport_info
        self.info = info


class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("网络嗅探器 - Network Sniffer")
        self.root.geometry("1400x900")
        self.root.configure(bg='#1e1e2e')
        
        self.sniffing = False
        self.packet_count = 0
        self.packets = []
        self.sniffer_thread = None
        self.start_time = None
        
        self.setup_ui()
        
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Title.TLabel', foreground='#cdd6f4', background='#1e1e2e', font=('Microsoft YaHei', 16, 'bold'))
        style.configure('Info.TLabel', foreground='#bac2de', background='#1e1e2e', font=('Microsoft YaHei', 9))
        style.configure('Button.TButton', foreground='#1e1e2e', background='#a6e3a1', font=('Microsoft YaHei', 10, 'bold'), padding=10)
        style.map('Button.TButton', background=[('active', '#94e2d5')])
        style.configure('Stop.TButton', foreground='#1e1e2e', background='#f38ba8', font=('Microsoft YaHei', 10, 'bold'), padding=10)
        style.map('Stop.TButton', background=[('active', '#eba0ac')])
        style.configure('Treeview', background='#313244', foreground='#cdd6f4', fieldbackground='#313244', font=('Consolas', 9))
        style.configure('Treeview.Heading', background='#45475a', foreground='#cdd6f4', font=('Microsoft YaHei', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#89b4fa')])
        style.configure('Treeview', rowheight=22)
        
        header_frame = tk.Frame(self.root, bg='#1e1e2e', padx=20, pady=15)
        header_frame.pack(fill=tk.X)
        
        title_label = ttk.Label(header_frame, text="网络嗅探器 - Network Sniffer", style='Title.TLabel')
        title_label.pack(side=tk.LEFT)
        
        self.stats_labels = {}
        stats = [("总计", "#89b4fa"), ("TCP", "#a6e3a1"), ("UDP", "#fab387"), ("ICMP", "#f38ba8")]
        for name, color in stats:
            frame = tk.Frame(header_frame, bg='#313244', padx=15, pady=5)
            frame.pack(side=tk.RIGHT, padx=5)
            tk.Label(frame, text=name, fg=color, bg='#313244', font=('Microsoft YaHei', 9)).pack()
            label = tk.Label(frame, text="0", fg='#cdd6f4', bg='#313244', font=('Microsoft YaHei', 14, 'bold'))
            label.pack()
            self.stats_labels[name] = label
        
        self.status_label = ttk.Label(header_frame, text="状态: 未启动", style='Info.TLabel')
        self.status_label.pack(side=tk.RIGHT, padx=10)
        
        control_frame = tk.Frame(self.root, bg='#1e1e2e', padx=20, pady=10)
        control_frame.pack(fill=tk.X)
        
        self.start_btn = ttk.Button(control_frame, text="开始嗅探", style='Button.TButton', command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="停止嗅探", style='Stop.TButton', command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(control_frame, text="清空列表", style='Button.TButton', command=self.clear_packets)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(control_frame, text="导出捕获", style='Button.TButton', command=self.export_capture)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        filter_frame = tk.Frame(self.root, bg='#1e1e2e', padx=20, pady=5)
        filter_frame.pack(fill=tk.X)
        
        ttk.Label(filter_frame, text="协议筛选:", style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="ALL")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, values=["ALL", "TCP", "UDP", "ICMP"], state="readonly", width=10)
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind("<<ComboboxSelected>>", self.apply_filter)
        
        ttk.Label(filter_frame, text="  搜索:", style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<KeyRelease>', self.apply_filter)
        
        ping_frame = tk.Frame(self.root, bg='#1e1e2e', padx=20, pady=5)
        ping_frame.pack(fill=tk.X)
        
        ttk.Label(ping_frame, text="Ping工具:", style='Info.TLabel').pack(side=tk.LEFT, padx=5)
        self.ping_entry = ttk.Entry(ping_frame, width=25, font=('Consolas', 10))
        self.ping_entry.pack(side=tk.LEFT, padx=5)
        self.ping_entry.insert(0, '8.8.8.8')
        self.ping_entry.bind('<Return>', lambda e: self.start_ping())
        
        self.ping_btn = ttk.Button(ping_frame, text="Ping", style='Button.TButton', command=self.start_ping)
        self.ping_btn.pack(side=tk.LEFT, padx=5)
        
        self.ping_clear_btn = ttk.Button(ping_frame, text="清空", style='Stop.TButton', command=self.clear_ping)
        self.ping_clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.ping_loading_label = ttk.Label(ping_frame, text="", style='Info.TLabel')
        self.ping_loading_label.pack(side=tk.LEFT, padx=10)
        
        ping_result_frame = tk.Frame(self.root, bg='#1e1e2e', padx=20, pady=5)
        ping_result_frame.pack(fill=tk.X)
        
        self.ping_text = scrolledtext.ScrolledText(ping_result_frame, height=6, bg='#313244', fg='#a6e3a1',
                                                    font=('Consolas', 10), insertbackground='#cdd6f4')
        self.ping_text.pack(fill=tk.X)
        
        list_frame = tk.Frame(self.root, bg='#1e1e2e', padx=20, pady=10)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('num', 'time', 'src', 'dst', 'protocol', 'length', 'info')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=8)
        
        self.tree.heading('num', text='No.')
        self.tree.heading('time', text='Time')
        self.tree.heading('src', text='Source')
        self.tree.heading('dst', text='Destination')
        self.tree.heading('protocol', text='Protocol')
        self.tree.heading('length', text='Length')
        self.tree.heading('info', text='Info')
        
        self.tree.column('num', width=60, anchor=tk.CENTER)
        self.tree.column('time', width=120, anchor=tk.CENTER)
        self.tree.column('src', width=180, anchor=tk.W)
        self.tree.column('dst', width=180, anchor=tk.W)
        self.tree.column('protocol', width=80, anchor=tk.CENTER)
        self.tree.column('length', width=70, anchor=tk.CENTER)
        self.tree.column('info', width=500, anchor=tk.W)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        detail_frame = tk.Frame(self.root, bg='#1e1e2e', padx=20, pady=10)
        detail_frame.pack(fill=tk.BOTH, expand=True)
        
        detail_paned = tk.PanedWindow(detail_frame, orient=tk.HORIZONTAL, bg='#1e1e2e', sashwidth=5)
        detail_paned.pack(fill=tk.BOTH, expand=True)
        
        left_frame = tk.Frame(detail_paned, bg='#1e1e2e')
        detail_paned.add(left_frame, width=600)
        
        ttk.Label(left_frame, text="Packet Details", style='Info.TLabel').pack(anchor=tk.W, pady=5)
        
        self.detail_tree = ttk.Treeview(left_frame, show='tree', height=10)
        detail_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.detail_tree.yview)
        self.detail_tree.configure(yscrollcommand=detail_scroll.set)
        self.detail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        right_frame = tk.Frame(detail_paned, bg='#1e1e2e')
        detail_paned.add(right_frame)
        
        ttk.Label(right_frame, text="Packet Bytes", style='Info.TLabel').pack(anchor=tk.W, pady=5)
        
        self.hex_text = scrolledtext.ScrolledText(right_frame, height=10, bg='#313244', fg='#cdd6f4', 
                                                    font=('Consolas', 10), insertbackground='#cdd6f4')
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        
        self.update_stats()
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return '0.0.0.0'
    
    def parse_arp_header(self, data):
        if len(data) < 28:
            return None
        arp_header = struct.unpack('!HHBBH', data[:8])
        hardware_type = arp_header[0]
        protocol_type = arp_header[1]
        hardware_len = arp_header[2]
        protocol_len = arp_header[3]
        operation = arp_header[4]
        
        sender_mac = ':'.join('{:02x}'.format(b) for b in data[8:14]).upper()
        sender_ip = socket.inet_ntoa(data[14:18])
        target_mac = ':'.join('{:02x}'.format(b) for b in data[18:24]).upper()
        target_ip = socket.inet_ntoa(data[24:28])
        
        op_str = 'Request' if operation == 1 else 'Reply' if operation == 2 else f'Unknown({operation})'
        
        return hardware_type, protocol_type, hardware_len, protocol_len, operation, sender_mac, sender_ip, target_mac, target_ip, op_str
    
    def parse_ip_header(self, data):
        if len(data) < 20:
            return None
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        source_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        total_length = ip_header[2]
        return version, ihl, ttl, protocol, source_ip, dest_ip, total_length, data[ihl:]
    
    def parse_tcp_header(self, data):
        if len(data) < 20:
            return None
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        source_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence = tcp_header[2]
        acknowledgement = tcp_header[3]
        offset_res = tcp_header[4]
        tcp_offset = (offset_res >> 4) * 4
        flags = tcp_header[5]
        return source_port, dest_port, sequence, acknowledgement, tcp_offset, flags, data[tcp_offset:]
    
    def parse_udp_header(self, data):
        if len(data) < 8:
            return None
        udp_header = struct.unpack('!HHHH', data[:8])
        source_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        checksum = udp_header[3]
        return source_port, dest_port, length, checksum, data[8:]
    
    def parse_icmp_header(self, data):
        if len(data) < 8:
            return None
        icmp_type = data[0]
        icmp_code = data[1]
        checksum = struct.unpack('!H', data[2:4])[0]
        return icmp_type, icmp_code, checksum, data[4:]
    
    def get_protocol_name(self, protocol):
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return protocols.get(protocol, 'Unknown')
    
    def get_tcp_flags(self, flags):
        flag_str = []
        if flags & 0x01: flag_str.append('FIN')
        if flags & 0x02: flag_str.append('SYN')
        if flags & 0x04: flag_str.append('RST')
        if flags & 0x08: flag_str.append('PSH')
        if flags & 0x10: flag_str.append('ACK')
        if flags & 0x20: flag_str.append('URG')
        return ','.join(flag_str) if flag_str else 'None'
    
    def generate_info(self, protocol, ip_info, transport_info, arp_info):
        if protocol == 0:
            if arp_info:
                return f"{arp_info[9]}: Who has {arp_info[8]}? Tell {arp_info[7]}" if arp_info[9] == 'Request' else f"{arp_info[7]} is at {arp_info[6]}"
        elif protocol == 6 and transport_info:
            flags = self.get_tcp_flags(transport_info[5])
            return f"{transport_info[0]} -> {transport_info[1]} [{flags}] Seq={transport_info[2]} Ack={transport_info[3]}"
        elif protocol == 17 and transport_info:
            return f"{transport_info[0]} -> {transport_info[1]} Len={transport_info[2]}"
        elif protocol == 1 and transport_info:
            icmp_types = {0: 'Echo Reply', 3: 'Destination Unreachable', 5: 'Redirect', 8: 'Echo Request', 11: 'Time Exceeded'}
            return f"ICMP {icmp_types.get(transport_info[0], f'Type={transport_info[0]}')}"
        return ''
    
    def start_sniffing(self):
        try:
            self.sniffing = True
            self.start_time = time.time()
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text="状态: 正在嗅探...")
            
            self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniffer_thread.start()
        except Exception as e:
            messagebox.showerror("错误", f"启动嗅探器失败: {str(e)}\n请以管理员身份运行程序！")
            self.stop_sniffing()
    
    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="状态: 已停止")
    
    def clear_packets(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packets = []
        self.packet_count = 0
        self.start_time = None
        self.update_stats()
        self.detail_tree.delete(*self.detail_tree.get_children())
        self.hex_text.delete(1.0, tk.END)
    
    def start_ping(self):
        host = self.ping_entry.get().strip()
        if not host:
            messagebox.showwarning("提示", "请输入Ping目标地址")
            return
        self.ping_btn.config(state=tk.DISABLED)
        self.ping_loading_label.config(text="Pinging...")
        self.ping_text.delete(1.0, tk.END)
        self.ping_text.insert(tk.END, f"正在 Ping {host} ...\n\n")
        ping_thread = threading.Thread(target=self.do_ping, args=(host,), daemon=True)
        ping_thread.start()
    
    def do_ping(self, host):
        try:
            cmd = ['ping', '-n', '4', host]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='gbk', errors='replace')
            stdout, stderr = process.communicate(timeout=30)
            
            self.root.after(0, self.ping_text.insert, tk.END, stdout if stdout else '')
            if stderr:
                self.root.after(0, self.ping_text.insert, tk.END, stderr)
            
            self.root.after(0, self.ping_btn.config, {'state': tk.NORMAL})
            self.root.after(0, self.ping_loading_label.config, {'text': '完成'})
        except subprocess.TimeoutExpired:
            self.root.after(0, self.ping_text.insert, tk.END, 'Ping 请求超时\n')
            self.root.after(0, self.ping_btn.config, {'state': tk.NORMAL})
            self.root.after(0, self.ping_loading_label.config, {'text': '超时'})
        except Exception as e:
            self.root.after(0, self.ping_text.insert, tk.END, f'Ping 失败: {str(e)}\n')
            self.root.after(0, self.ping_btn.config, {'state': tk.NORMAL})
            self.root.after(0, self.ping_loading_label.config, {'text': '失败'})
    
    def clear_ping(self):
        self.ping_text.delete(1.0, tk.END)
        self.ping_loading_label.config(text="")
    
    def apply_filter(self, event=None):
        filter_proto = self.filter_var.get()
        search_text = self.search_var.get().lower()
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for packet in self.packets:
            proto_name = self.get_protocol_name(packet.ip_info[3]) if packet.ip_info and packet.ip_info[3] != 0 else 'ARP'
            
            if filter_proto != "ALL" and filter_proto != proto_name:
                continue
            
            if search_text:
                info_str = f"{packet.number} {packet.timestamp} {proto_name} {packet.info}".lower()
                if search_text not in info_str:
                    continue
            
            self.add_packet_to_tree(packet, proto_name, None, None, None, None, None, None, False)
        
        self.update_stats()
    
    def update_stats(self):
        total = len(self.packets)
        tcp = sum(1 for p in self.packets if p.ip_info and p.ip_info[3] == 6)
        udp = sum(1 for p in self.packets if p.ip_info and p.ip_info[3] == 17)
        icmp = sum(1 for p in self.packets if p.ip_info and p.ip_info[3] == 1)
        
        self.stats_labels["总计"].config(text=str(total))
        self.stats_labels["TCP"].config(text=str(tcp))
        self.stats_labels["UDP"].config(text=str(udp))
        self.stats_labels["ICMP"].config(text=str(icmp))
    
    def sniff_packets(self):
        host = self.get_local_ip()
        sock = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            while self.sniffing:
                try:
                    raw_data, addr = sock.recvfrom(65536)
                    self.packet_count += 1
                    
                    if len(raw_data) < 20:
                        continue
                    
                    version = (raw_data[0] >> 4) & 0xF
                    
                    arp_info = None
                    ip_info = None
                    transport_info = None
                    protocol = -1
                    src_addr = 'Unknown'
                    dst_addr = 'Unknown'
                    src_port = '-'
                    dst_port = '-'
                    length = len(raw_data)
                    protocol_name = 'Unknown'
                    info = ''
                    eth_type = 0x0800
                    
                    if version == 4:
                        ip_info = self.parse_ip_header(raw_data)
                        if ip_info:
                            ver, ihl, ttl, proto, source_ip, dest_ip, total_length, ip_data = ip_info
                            protocol = proto
                            src_addr = source_ip
                            dst_addr = dest_ip
                            protocol_name = self.get_protocol_name(protocol)
                            
                            if protocol == 6:
                                transport_info = self.parse_tcp_header(ip_data)
                                if transport_info:
                                    src_port = str(transport_info[0])
                                    dst_port = str(transport_info[1])
                            elif protocol == 17:
                                transport_info = self.parse_udp_header(ip_data)
                                if transport_info:
                                    src_port = str(transport_info[0])
                                    dst_port = str(transport_info[1])
                            elif protocol == 1:
                                transport_info = self.parse_icmp_header(ip_data)
                            
                            info = self.generate_info(protocol, ip_info, transport_info, None)
                    elif version == 6:
                        protocol_name = 'IPv6'
                        src_addr = addr[0]
                        dst_addr = 'Unknown'
                        info = 'IPv6 Packet'
                    else:
                        protocol_name = f'Unknown(0x{raw_data[0]:02x})'
                        info = 'Unknown packet'
                    
                    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                    relative_time = f"{time.time() - self.start_time:.6f}"
                    eth_info = ('N/A', 'N/A', eth_type)
                    
                    packet = Packet(self.packet_count, timestamp, relative_time, raw_data, eth_info, ip_info, transport_info, info)
                    self.packets.append(packet)
                    
                    self.root.after(0, self.add_packet_to_tree, packet, protocol_name, src_addr, dst_addr, src_port, dst_port, length, info)
                    
                except Exception as e:
                    if not self.sniffing:
                        break
                    continue
                    
        except Exception as e:
            if self.sniffing:
                self.root.after(0, lambda: messagebox.showerror("错误", f"嗅探错误: {str(e)}"))
        finally:
            if sock:
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except:
                    pass
                try:
                    sock.close()
                except:
                    pass
            self.root.after(0, self.stop_sniffing)
    
    def add_packet_to_tree(self, packet, protocol_name, src_addr=None, dst_addr=None, src_port=None, dst_port=None, length=None, info=None, update_stats=True):
        filter_proto = self.filter_var.get()
        if filter_proto != "ALL" and filter_proto != protocol_name:
            if update_stats:
                self.update_stats()
            return
        
        if src_addr is None:
            if packet.ip_info and packet.ip_info[3] == 0:
                src_addr = packet.eth_info[1]
                dst_addr = packet.eth_info[0]
            else:
                src_addr = packet.ip_info[4] if packet.ip_info else 'Unknown'
                dst_addr = packet.ip_info[5] if packet.ip_info else 'Unknown'
        
        if length is None:
            length = len(packet.raw_data)
        
        if info is None:
            info = packet.info
        
        tags = ()
        if protocol_name == 'TCP':
            tags = ('tcp',)
        elif protocol_name == 'UDP':
            tags = ('udp',)
        elif protocol_name == 'ICMP':
            tags = ('icmp',)
        elif protocol_name == 'ARP':
            tags = ('arp',)
        
        self.tree.insert('', 0, values=(
            packet.number, packet.relative_time, src_addr, dst_addr, protocol_name, length, info), tags=tags)
        
        if update_stats:
            self.update_stats()
    
    def on_packet_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        
        item = self.tree.item(selected[0])
        packet_num = item['values'][0]
        packet = next((p for p in self.packets if p.number == packet_num), None)
        
        if packet:
            self.show_packet_detail(packet)
    
    def show_packet_detail(self, packet):
        for item in self.detail_tree.get_children():
            self.detail_tree.delete(item)
        self.hex_text.delete(1.0, tk.END)
        
        raw_data = packet.raw_data
        eth_type = packet.eth_info[2]
        
        frame_node = self.detail_tree.insert('', 'end', text=f"Frame {packet.number}: {len(raw_data)} bytes on wire")
        self.detail_tree.insert(frame_node, 'end', text=f"  Arrival Time: {packet.timestamp}")
        self.detail_tree.insert(frame_node, 'end', text=f"  Frame Length: {len(raw_data)} bytes")
        self.detail_tree.insert(frame_node, 'end', text=f"  Capture Length: {len(raw_data)} bytes")
        
        if eth_type == 0x0806:
            self.show_arp_detail(packet)
        elif eth_type == 0x0800:
            self.show_ip_detail(packet)
        
        self.show_hex_dump(raw_data)
    
    def show_arp_detail(self, packet):
        arp_info = self.parse_arp_header(packet.raw_data[14:])
        if not arp_info:
            return
        
        hw_type_names = {1: 'Ethernet'}
        proto_type_names = {0x0800: 'IPv4'}
        
        arp_node = self.detail_tree.insert('', 'end', text=f"Address Resolution Protocol ({arp_info[9]})")
        self.detail_tree.insert(arp_node, 'end', text=f"  Hardware type: {hw_type_names.get(arp_info[0], 'Unknown')} ({arp_info[0]})")
        self.detail_tree.insert(arp_node, 'end', text=f"  Protocol type: {proto_type_names.get(arp_info[1], 'Unknown')} (0x{arp_info[1]:04x})")
        self.detail_tree.insert(arp_node, 'end', text=f"  Hardware size: {arp_info[2]}")
        self.detail_tree.insert(arp_node, 'end', text=f"  Protocol size: {arp_info[3]}")
        self.detail_tree.insert(arp_node, 'end', text=f"  Opcode: {arp_info[9]} ({arp_info[4]})")
        self.detail_tree.insert(arp_node, 'end', text=f"  Sender MAC address: {arp_info[5]}")
        self.detail_tree.insert(arp_node, 'end', text=f"  Sender IP address: {arp_info[6]}")
        self.detail_tree.insert(arp_node, 'end', text=f"  Target MAC address: {arp_info[7]}")
        self.detail_tree.insert(arp_node, 'end', text=f"  Target IP address: {arp_info[8]}")
    
    def show_ip_detail(self, packet):
        ip_info = packet.ip_info
        if not ip_info:
            return
        
        version, ihl, ttl, protocol, source_ip, dest_ip, total_length, ip_data = ip_info
        protocol_name = self.get_protocol_name(protocol)
        
        ip_node = self.detail_tree.insert('', 'end', text=f"Internet Protocol Version {version}, Src: {source_ip}, Dst: {dest_ip}")
        self.detail_tree.insert(ip_node, 'end', text=f"  Version: {version}")
        self.detail_tree.insert(ip_node, 'end', text=f"  Header Length: {ihl} bytes")
        self.detail_tree.insert(ip_node, 'end', text=f"  Total Length: {total_length}")
        self.detail_tree.insert(ip_node, 'end', text=f"  Time to Live: {ttl}")
        self.detail_tree.insert(ip_node, 'end', text=f"  Protocol: {protocol_name} ({protocol})")
        self.detail_tree.insert(ip_node, 'end', text=f"  Source Address: {source_ip}")
        self.detail_tree.insert(ip_node, 'end', text=f"  Destination Address: {dest_ip}")
        
        if protocol == 6 and packet.transport_info:
            self.show_tcp_detail(packet)
        elif protocol == 17 and packet.transport_info:
            self.show_udp_detail(packet)
        elif protocol == 1 and packet.transport_info:
            self.show_icmp_detail(packet)
    
    def show_tcp_detail(self, packet):
        ti = packet.transport_info
        src_port = ti[0]
        dst_port = ti[1]
        seq = ti[2]
        ack = ti[3]
        offset = ti[4]
        flags = ti[5]
        flags_str = self.get_tcp_flags(flags)
        
        port_names = {80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 53: 'DNS', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 3306: 'MySQL', 3389: 'RDP'}
        src_name = port_names.get(src_port, '')
        dst_name = port_names.get(dst_port, '')
        
        tcp_node = self.detail_tree.insert('', 'end', text=f"Transmission Control Protocol, Src Port: {src_port}{(' (' + src_name + ')' if src_name else '')}, Dst Port: {dst_port}{(' (' + dst_name + ')' if dst_name else '')}")
        self.detail_tree.insert(tcp_node, 'end', text=f"  Source Port: {src_port}")
        self.detail_tree.insert(tcp_node, 'end', text=f"  Destination Port: {dst_port}")
        self.detail_tree.insert(tcp_node, 'end', text=f"  Sequence Number: {seq}")
        self.detail_tree.insert(tcp_node, 'end', text=f"  Acknowledgment Number: {ack}")
        self.detail_tree.insert(tcp_node, 'end', text=f"  Header Length: {offset} bytes")
        self.detail_tree.insert(tcp_node, 'end', text=f"  Flags: {flags_str}")
        
        if flags & 0x02: self.detail_tree.insert(tcp_node, 'end', text=f"    SYN: Set")
        if flags & 0x10: self.detail_tree.insert(tcp_node, 'end', text=f"    ACK: Set")
        if flags & 0x01: self.detail_tree.insert(tcp_node, 'end', text=f"    FIN: Set")
        if flags & 0x04: self.detail_tree.insert(tcp_node, 'end', text=f"    RST: Set")
        if flags & 0x08: self.detail_tree.insert(tcp_node, 'end', text=f"    PSH: Set")
    
    def show_udp_detail(self, packet):
        ti = packet.transport_info
        src_port = ti[0]
        dst_port = ti[1]
        length = ti[2]
        checksum = ti[3]
        
        port_names = {53: 'DNS', 67: 'DHCP', 68: 'DHCP', 123: 'NTP', 161: 'SNMP', 500: 'IKE', 514: 'Syslog', 1900: 'UPnP'}
        src_name = port_names.get(src_port, '')
        dst_name = port_names.get(dst_port, '')
        
        udp_node = self.detail_tree.insert('', 'end', text=f"User Datagram Protocol, Src Port: {src_port}{(' (' + src_name + ')' if src_name else '')}, Dst Port: {dst_port}{(' (' + dst_name + ')' if dst_name else '')}")
        self.detail_tree.insert(udp_node, 'end', text=f"  Source Port: {src_port}")
        self.detail_tree.insert(udp_node, 'end', text=f"  Destination Port: {dst_port}")
        self.detail_tree.insert(udp_node, 'end', text=f"  Length: {length}")
        self.detail_tree.insert(udp_node, 'end', text=f"  Checksum: 0x{checksum:04x}")
    
    def show_icmp_detail(self, packet):
        ti = packet.transport_info
        icmp_type = ti[0]
        icmp_code = ti[1]
        checksum = ti[2]
        
        type_names = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            12: 'Parameter Problem'
        }
        code_names = {
            (3, 0): 'Network Unreachable',
            (3, 1): 'Host Unreachable',
            (3, 2): 'Protocol Unreachable',
            (3, 3): 'Port Unreachable',
            (11, 0): 'TTL Expired in Transit',
            (11, 1): 'Fragment Reassembly Time Exceeded'
        }
        
        type_name = type_names.get(icmp_type, 'Unknown')
        code_name = code_names.get((icmp_type, icmp_code), '')
        
        icmp_node = self.detail_tree.insert('', 'end', text=f"Internet Control Message Protocol")
        self.detail_tree.insert(icmp_node, 'end', text=f"  Type: {icmp_type} ({type_name})")
        self.detail_tree.insert(icmp_node, 'end', text=f"  Code: {icmp_code}{' (' + code_name + ')' if code_name else ''}")
        self.detail_tree.insert(icmp_node, 'end', text=f"  Checksum: 0x{checksum:04x}")
    
    def show_hex_dump(self, data):
        self.hex_text.delete(1.0, tk.END)
        
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            offset = f"{i:04x}"
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_part = hex_part.ljust(47)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{offset}  {hex_part}  {ascii_part}")
        
        self.hex_text.insert(tk.END, '\n'.join(lines))
    
    def export_capture(self):
        if not self.packets:
            messagebox.showinfo("提示", "没有可导出的数据包")
            return
        
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="导出捕获数据"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"网络嗅探器捕获数据\n")
                    f.write(f"导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"数据包总数: {len(self.packets)}\n")
                    f.write("="*100 + "\n\n")
                    
                    for packet in self.packets:
                        proto_name = self.get_protocol_name(packet.ip_info[3]) if packet.ip_info and packet.ip_info[3] != 0 else 'ARP'
                        f.write(f"No. {packet.number}\n")
                        f.write(f"Time: {packet.relative_time}\n")
                        f.write(f"Protocol: {proto_name}\n")
                        f.write(f"Length: {len(packet.raw_data)} bytes\n")
                        f.write(f"Info: {packet.info}\n")
                        f.write("-"*100 + "\n")
                
                messagebox.showinfo("成功", f"已导出 {len(self.packets)} 个数据包到:\n{filename}")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")


def main():
    if not is_admin():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("权限错误", "请以管理员身份运行此程序！\n\n右键点击程序 -> 选择'以管理员身份运行'")
        sys.exit(1)
    
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
