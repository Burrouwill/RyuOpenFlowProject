import time
from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.h1_total_packets_out = 0
        self.h2_total_packets_out = 0
        self.h3_total_packets_out = 0
        self.packetCounts = {'10.0.1.1': 0, '10.0.2.1': 0, '10.0.3.1': 0}
        self.MAX_COUNT = 5
        self.UNBLOCK_INTERVAL = 60
        self.blocked_hosts = {}
        self.all_host_packet_counts = { '10.0.1.1' : 'h1_total_packets_out', '10.0.2.1': 'h2_total_packets_out', '10.0.3.1': 'h3_total_packets_out'}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # List of IPv4 addresses to track
        ipv4_addresses = ['10.0.1.1', '10.0.2.1', '10.0.3.1']

        # Create flows to track traffic for each combination of source and destination
        for src_ip in ipv4_addresses:
            for dst_ip in ipv4_addresses:
                if src_ip != dst_ip:
                    # Create a bidirectional flow to track traffic for a specific IP address pair
                    match_bidirectional = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip,
                                                          ipv4_dst=dst_ip)
                    out_port = ofproto.OFPP_CONTROLLER
                    actions = [parser.OFPActionOutput(out_port)]
                    instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    msg = parser.OFPFlowMod(
                        datapath=datapath,
                        priority=1,
                        match=match_bidirectional,
                        instructions=instruction
                    )
                    self.logger.info(f"Tracking Bidirectional Packets between {src_ip} and {dst_ip}")
                    datapath.send_msg(msg)

        # Add a default flow entry to send unmatched packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                self._block_handler(dp)
            hub.sleep(1)

    def _block_handler(self, dp):
        #Iterate through hosts -> Block those with packet count > MAX_COUNT
        self._block_hosts(dp)
        #Unblock valid hosts

    def _block_hosts(self, dp):
        for host_ip in self.all_host_packet_counts:
            max_count = getattr(self, self.all_host_packet_counts[host_ip])
            if max_count >= self.MAX_COUNT and host_ip not in self.blocked_hosts:
                self.block_host(host_ip, dp)

    def block_host(self, host_ip, dp):
        # Block traffic from the host by adding a flow entry with higher priority
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        # Drop outgoing traffic from host
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=host_ip)

        instruction = [
            parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])
        ]
        msg = parser.OFPFlowMod(
            datapath=dp,
            priority=10000,
            match=match,
            instructions=instruction
        )
        self.logger.info("Blocking traffic from host {}".format(host_ip))
        dp.send_msg(msg)


        # Reset the packet count too somewhere - This may cause problems

        # Store the unblock timestamp
        self.blocked_hosts[host_ip] = time.time() + self.UNBLOCK_INTERVAL

    def _unblock_expired_hosts(self):
        # Iterate through blocked hosts and unblock those that have expired
        current_time = time.time()
        expired_hosts = [host for host, unblock_time in self.blocked_hosts.items() if unblock_time <= current_time]
        for host in expired_hosts:
            self.unblock_host(host)

    def unblock_host(self, host_ip):
        # Unblock traffic from the host by removing the flow entry

        # Create a flow entry to match packets from the host

        # Delete the flow entry by sending a FlowMod with command OFPFC_DELETE

        #Reset the packet count too somewhere
        # Remove the host from the blocked list
        if host_ip in self.blocked_hosts:
            del self.blocked_hosts[host_ip]








    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        # Store the initial packet counts
        initial_h1_packets_out = self.h1_total_packets_out
        initial_h2_packets_out = self.h2_total_packets_out
        initial_h3_packets_out = self.h3_total_packets_out

        # Iterate through all the flow stats
        for stat in sorted(body,
                           key=lambda flow: (flow.match.get('ipv4_src', 'N/A'), flow.match.get('ipv4_dst', 'N/A'))):
            ipv4_src = stat.match.get('ipv4_src', 'N/A')
            packet_count = stat.packet_count


            if ipv4_src == '10.0.1.1':
                if ipv4_src in self.blocked_hosts:
                    return

                # Check if there's an increase in the outgoing packet count
                if packet_count > initial_h1_packets_out:
                    increase = packet_count - initial_h1_packets_out
                    self.h1_total_packets_out = packet_count  # Update the outgoing count
                    self.logger.info('Outgoing Packets From h1 increased by %d: %d', increase,
                                     self.h1_total_packets_out)
                if packet_count < initial_h1_packets_out:
                    prev_packet_count = self.packetCounts[ipv4_src]
                    increase = packet_count - prev_packet_count
                    if increase > 0:
                        self.h1_total_packets_out += 1
                        self.logger.info('Outgoing Packets From h1 increased by 1: %d', self.h1_total_packets_out)
                        self.packetCounts[ipv4_src] = packet_count

            if ipv4_src == '10.0.2.1':
                if ipv4_src in self.blocked_hosts:
                    return

                # Check if there's an increase in the outgoing packet count
                if packet_count > initial_h2_packets_out:
                    increase = packet_count - initial_h2_packets_out
                    self.h2_total_packets_out = packet_count  # Update the outgoing count
                    self.logger.info('Outgoing Packets From h2 increased by %d: %d', increase,
                                     self.h2_total_packets_out)
                if packet_count < initial_h2_packets_out:
                    prev_packet_count = self.packetCounts[ipv4_src]
                    increase = packet_count - prev_packet_count
                    if increase > 0:
                        self.h2_total_packets_out += 1
                        self.logger.info('Outgoing Packets From h2 increased by 1: %d', self.h2_total_packets_out)
                        self.packetCounts[ipv4_src] = packet_count

            if ipv4_src == '10.0.3.1':
                if ipv4_src in self.blocked_hosts:
                    return

                # Check if there's an increase in the outgoing packet count
                if packet_count > initial_h3_packets_out:
                    increase = packet_count - initial_h3_packets_out
                    self.h3_total_packets_out = packet_count  # Update the outgoing count
                    self.logger.info('Outgoing Packets From h3 increased by %d: %d', increase,
                                     self.h3_total_packets_out)
                if packet_count < initial_h3_packets_out:
                    prev_packet_count = self.packetCounts[ipv4_src]
                    increase = packet_count - prev_packet_count
                    if increase > 0:
                        self.h3_total_packets_out += 1
                        self.logger.info('Outgoing Packets From h3 increased by 1: %d', self.h3_total_packets_out)
                        self.packetCounts[ipv4_src] = packet_count