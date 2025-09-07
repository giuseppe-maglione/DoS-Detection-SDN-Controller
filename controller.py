# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route, Response

import time, json, queue
import numpy as np
import pandas as pd

import csv, os, joblib

# === PARAMETRI GLOBALI ===
timeInterval = 10           # intervallo polling stats
X = 3                       # numero di cicli consecutivi sopra soglia per bloccare
STATIC_THRESHOLD = 7e5      # soglia statica, circa 80% della capacità critica dei link
K = 1                       # fattore di deviazione standard per la soglia dinamica 
MEAN_RATIO = 1              # fattore di gestione media mobile
N_HISTORY = 20              # numero di campioni per valutare soglia dinamica e raccolta dati
ALPHA = 0.8                 # decremento contatore se rate < 80% della soglia attuale
BAN_RATIO = 10              # fattore di ban-time
MIN_RATE = 250	  	        # rate minimo sotto cui non far lavorare il modello di ML
BAN_TIME = 30               # tempo di ban solo per attacchi stealth e ddos

# MAC noti degli host
HOST_MACS = {"00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03"}
FEATURE_CLASS = "attacco"

# colori per output console
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = '\033[93m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
CYAN = '\033[96m'
RESET = "\033[0m"

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}

        # strutture dati per statistiche
        self.port_stats = {}          # {dpid: {port: {"rx_bytes": ..., "rx_packets": ...}}}
        self.prev_port_stats = {}     # stats al ciclo precedente

        self.detection_state = {}     # {dpid: {mac: {"blocked": False, "counter": 0}}}
        self.rate_history = {}        # {dpid: {mac: [rate1, rate2,...]}}
        self.policies = {}            # {dpid: {mac: policy}}
        
        # setup per raccolta istanze (ML)
        self.mac_timestamps = {}      # {dpid: {mac: [t1, t2, ...]}}
        self.dst_sources = {}         # {dpid: {dst: set([src1, src2, ...])}}      # molte sorgenti e poche destinazioni, tipico di attacchi ddos
        self.mac_pkt_sizes = {}       # {dpid: {mac: [pkt_len1, pkt_len2, ...]}}   # pacchetti piccoli, tipico di attacchi più stralth
        self.csv_file = "traffic.csv"
        self.csv_fields = [
            "timestamp","dpid","mac",
            "mean_rate","var_rate","max_rate","min_rate",
            "mean_interval","std_interval","burst_count",
            "src_diversity","small_pkt_ratio","class"
        ]
        # creazione del file csv
        '''
        if not os.path.exists(self.csv_file) or os.path.getsize(self.csv_file) == 0:
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.csv_fields)
                writer.writeheader()
        '''
        # setup modello (RandomForest)
        self.ml_model = joblib.load("dos_ddos_detector.pkl")
        self.ml_model.n_jobs = 1
        self.ml_features = [
            "mean_rate","var_rate","max_rate","min_rate",
            "mean_interval","std_interval","burst_count",
            "src_diversity","small_pkt_ratio"
        ]

        # setup REST per web-app
        wsgi = kwargs['wsgi']
        wsgi.register(PolicyAPI, {'controller': self})

        # code thread-safe per comunicazione tra thread
        self.stats_queue = queue.Queue()     # monitoring → detection
        self.policy_queue = queue.Queue()    # detection → enforcement
        
        # spawn dei thread
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.detect_thread = hub.spawn(self._detect_loop)
        self.enforce_thread = hub.spawn(self._enforce_loop)
        # self.feature_thread = hub.spawn(self._feature_loop)   # thread di raccolta dati per addestrare il modello

    # === MONITORING ===
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)
        
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _monitor_loop(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(timeInterval)
            self.logger.info(BLUE + '\t[MONITORING] New stats produced' + RESET)
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        self.port_stats.setdefault(dpid, {})
        self.prev_port_stats.setdefault(dpid, {})
        
        # aggiorna le statistiche correnti con i dati del reply
        for stat in ev.msg.body:
            port_no = stat.port_no
            self.port_stats[dpid][port_no] = stat
        
        # calcola il rate di traffico per ogni porta
        for port_no, stat in self.port_stats[dpid].items():
            if port_no in self.prev_port_stats[dpid]:
                prev_stat = self.prev_port_stats[dpid][port_no]
                # calcola la differenza in byte e il tempo trascorso
                delta_bytes = stat.rx_bytes - prev_stat.rx_bytes
                delta_time = timeInterval
                
                # calcola il rate in byte/s
                rate = (delta_bytes / delta_time) if delta_time > 0 else 0
                
                # trova il MAC address associato a questa porta
                # si assume una topologia semplice con 1 host per porta,
                # e si usa la mappa mac_to_port per la ricerca inversa.
                mac_to_check = None
                for mac, port in self.mac_to_port.get(dpid, {}).items():
                    if port == port_no and mac in HOST_MACS:
                        mac_to_check = mac
                        break
                
                if mac_to_check:
                    # usa la storia dei rate per calcolare la soglia dinamica
                    self.rate_history.setdefault(dpid, {}).setdefault(mac_to_check, []).append(rate)
                    hist = self.rate_history[dpid][mac_to_check]
                    if len(hist) > N_HISTORY:
                        hist.pop(0)

                    if hist:
                        mean_val = np.mean(hist)
                        std_val = np.std(hist)
                        dynamic_threshold = mean_val * MEAN_RATIO + K * std_val
                    else:
                        dynamic_threshold = STATIC_THRESHOLD

                    # push delle stats in coda detection 
                    self.stats_queue.put((dpid, mac_to_check, rate, dynamic_threshold))
        
        # aggiorna le statistiche precedenti con le statistiche correnti per il prossimo ciclo
        self.prev_port_stats[dpid] = self.port_stats[dpid].copy()

    # === DETECTION ===
    def _detect_loop(self):
        while True:
            try:
                dpid, mac, rate, dynamic_threshold = self.stats_queue.get(timeout=timeInterval)
            except queue.Empty:
                continue

            now = time.time()
            
            # gestisci eventuali sblocchi
            for dp_id, hosts in self.detection_state.items():
                for mac_addr, state in hosts.items():
                    if state.get("blocked") and now >= state.get("unlock_time", 0):
                        self.policy_queue.put({
                            "action": "remove",
                            "switch": dp_id,
                            "mac": mac_addr
                        })
                        state["blocked"] = False
                        state["counter"] = 0  # reset contatore dopo sblocco

            # init stato se non presente
            self.detection_state.setdefault(dpid, {}).setdefault(mac, {
                "blocked": False,
                "counter": 0,
                "unlock_time": 0
            })
            state = self.detection_state[dpid][mac]

            threshold = max(STATIC_THRESHOLD, dynamic_threshold)
            
            if not state["blocked"]:
                # --- detection classica ---
                classical_detect = False
                classical_detect = rate > threshold
                # --- detection machine learning ---
                ml_detect = False
                if mac in HOST_MACS:    # evita predizioni su dati degli switch (solo host → host)
                    features = self.extract_features(dpid, mac)
                    if features:
                        # evita predizione su dati incompleti
                        if rate > MIN_RATE and any(features[f] > 0 for f in self.ml_features):
                            X_input = pd.DataFrame([[features[f] for f in self.ml_features]],
                                                   columns=self.ml_features)
                            try:
                                pred = self.ml_model.predict(X_input)
                                # supponendo: 0 = attacco, 1 = normale
                                if pred[0] == 0:
                                    ml_detect = True
                            except Exception as e:
                                hub.sleep(1)   
                                
                if classical_detect:
                    state["counter"] = min(X, state["counter"] + 1)
                    self.logger.info(YELLOW + f"\n\t[DETECTION] Warning: A possible DoS attack has been detected. Info:" + RESET)
                    self.logger.info(YELLOW + f"Mac: {mac}, Switch: {dpid}, Exceeded threshold: {threshold:.1f}, Current rate: {rate:.1f}, Counter: {state['counter']}/{X}" + RESET)
                if ml_detect:
                    state["counter"] = min(X, state["counter"] + 1)
                    self.logger.info(PURPLE + f"\n\t[STEALTH/DDOS DETECTION] Warning: A possible Stealth/DDoS attack has been detected by ML model. Info:" + RESET)
                    self.logger.info(PURPLE + f"Mac: {mac}, Switch: {dpid}, Exceeded threshold: {threshold:.1f}, Current rate: {rate:.1f}, Counter: {state['counter']}/{X}" + RESET)
                    
                # decrementa contatore se non riconosciuto da modello ML
                # (altrimenti gli attacchi stealth non vengono bloccati)
                if rate < threshold * ALPHA and not ml_detect:
                    state["counter"] = max(0, state["counter"] - 1)
                
                # blocco se il contatore raggiunge X
                if state["counter"] >= X:
                    if ml_detect:
                        block_time = BAN_TIME       # serve un tempo di blocco fisso per evitare problemi con attacchi stealth
                    else:
                        excess_ratio = rate / threshold
                        block_time = excess_ratio * BAN_RATIO * X
                    state["unlock_time"] = now + block_time
                    policy = {
                        "switch": dpid,
                        "mac": mac,
                        "blocked": True,
                        "reason": "DoS detection",
                        "unlock_time": state["unlock_time"]
                    }
                    self.policy_queue.put(policy)
                    state["blocked"] = True
                    state["counter"] = 0

    # === ENFORCEMENT ===
    def _enforce_loop(self):
        while True:
            try:
                policy = self.policy_queue.get(timeout=1)
            except queue.Empty:
                continue

            dpid = str(policy.get("switch"))
            mac = policy.get("mac")
            reason = str(policy.get("reason", "manual"))

            if policy.get("action") == "remove":
                if dpid in self.policies and mac in self.policies[dpid]:
                    del self.policies[dpid][mac]
                dp = self.datapaths.get(int(dpid))
                if dp:
                    self.unlock_flow(dp, mac)
                continue

            if "blocked" not in policy:
                policy["blocked"] = True
                policy["reason"] = reason

            self.policies.setdefault(dpid, {})[mac] = policy
            dp = self.datapaths.get(int(dpid))
            if dp and policy["blocked"]:
                block_duration = policy["unlock_time"] - time.time()
                self.lock_flow(dp, mac, block_duration)

    def lock_flow(self, dp, mac, block_time):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        match = parser.OFPMatch(eth_src=mac)
        mod = parser.OFPFlowMod(datapath=dp, priority=2, match=match, instructions=[],
                                command=ofproto.OFPFC_ADD, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        dp.send_msg(mod)
        print(RED + f"\t[ENFORCEMENT] Blocked traffic from MAC {mac} on switch {dp.id} for {block_time:.1f} seconds" + RESET)

    def unlock_flow(self, dp, mac):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        match = parser.OFPMatch(eth_src=mac)
        mod = parser.OFPFlowMod(datapath=dp, priority=2, match=match,
                                command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        dp.send_msg(mod)
        print(GREEN + f"\t[ENFORCEMENT] Unblocked traffic from MAC {mac} on switch {dp.id}" + RESET)

    # === MACHINE LEARNING MODEL ===
    def extract_features(self, dpid, mac):
        rates = self.rate_history.get(dpid, {}).get(mac, [])
        times = self.mac_timestamps.get(dpid, {}).get(mac, [])

        if len(rates) < 1 or len(times) < 1:
            return None  # non abbastanza dati

        mean_rate = np.mean(rates)
        var_rate = np.var(rates)
        max_rate = np.max(rates)
        min_rate = np.min(rates)

        intervals = np.diff(times)
        mean_interval = np.mean(intervals) if len(intervals) > 0 else 0
        std_interval = np.std(intervals) if len(intervals) > 0 else 0

        # burst count: quante volte il rate supera 1.5x la media
        burst_count = sum(r > mean_rate * 1.5 for r in rates)
        
        # numero di sorgenti per la stessa destinazione
        # (prende la media dei sorgenti unici visti nelle destinazioni contattate da questo MAC)
        dst_map = self.dst_sources.get(dpid, {})
        src_diversity = 0
        if dst_map:
            counts = [len(srcs) for srcs in dst_map.values()]
            if counts:
                src_diversity = sum(counts) / len(counts)

        # percentuale pacchetti piccoli (<100B)
        pkt_sizes = self.mac_pkt_sizes.get(dpid, {}).get(mac, [])
        small_pkt_ratio = 0
        if pkt_sizes:
            small_pkt_ratio = sum(1 for s in pkt_sizes if s < 100) / len(pkt_sizes)

        features = {
            "timestamp": time.time(),
            "dpid": dpid,
            "mac": mac,
            "mean_rate": mean_rate,
            "var_rate": var_rate,
            "max_rate": max_rate,
            "min_rate": min_rate,
            "mean_interval": mean_interval,
            "std_interval": std_interval,
            "burst_count": burst_count,
            "src_diversity": src_diversity,
            "small_pkt_ratio": small_pkt_ratio,
            "class": str(FEATURE_CLASS)
        }
        return features
    
    def _feature_loop(self):
        while True:
            hub.sleep(timeInterval)  # ogni timeInterval estrai e salva
            for dpid, macs in self.rate_history.items():
                for mac in macs.keys():
                    if mac not in HOST_MACS:  # salta MAC non host
                        continue
                    features = self.extract_features(dpid, mac)
                    if features:
                        features["class"] = str(FEATURE_CLASS)  # aggiungi colonna classe
                        with open(self.csv_file, "a", newline="") as f:
                            writer = csv.DictWriter(
                                f,
                                fieldnames=self.csv_fields,
                                extrasaction="ignore",
                                restval=""        
                            )
                            writer.writerow(features)
            print(CYAN + f"\t[FEATURE EXTRACTOR] New features extracted" + RESET)
            
    # === LEARNING SWITCH ===
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
    def add_flow(self, dp, priority, match, actions, buffer_id=None):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=dp, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                    match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # --- raccolta dati per modello ML --- (unica parte di codice non fornito)
        now = time.time()
        
        # aggiorna mappa dei sorgenti che contattano una stessa destinazione
        self.dst_sources.setdefault(dpid, {}).setdefault(dst, set()).add(src)
        # tieni solo le ultime N_HISTORY destinazioni
        if len(self.dst_sources[dpid][dst]) > N_HISTORY:
            self.dst_sources[dpid][dst].pop()

        # aggiorna lista dimensioni pacchetti per ogni sorgente
        pkt_len = len(msg.data)
        self.mac_pkt_sizes.setdefault(dpid, {}).setdefault(src, []).append(pkt_len)
        # tieni solo gli ultimi N_HISTORY pacchetti
        if len(self.mac_pkt_sizes[dpid][src]) > N_HISTORY:
            self.mac_pkt_sizes[dpid][src].pop(0)
            
        # aggiorna timestamp pacchetti per intervalli
        self.mac_timestamps.setdefault(dpid, {}).setdefault(src, []).append(now)
        # tieni solo gli ultimi N_HISTORY timestamp
        if len(self.mac_timestamps[dpid][src]) > N_HISTORY:
            self.mac_timestamps[dpid][src].pop(0)
        # --- fine raccolta dati ---
        
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
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

# === WEB APP CONTROLLER ===
class PolicyAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(PolicyAPI, self).__init__(req, link, data, **config)
        self.controller = data['controller']

    def _cors_response(self, body, status=200, content_type='application/json'):
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        }
        return Response(content_type=content_type, body=body, status=status, headers=headers)

    @route('policy', '/policy', methods=['GET'])
    def list_policies(self, req, **kwargs):
        # Restituisci policies a livello MAC
        body = json.dumps(self.controller.policies)
        return self._cors_response(body)

    @route('policy', '/policy', methods=['POST'])
    def add_policy(self, req, **kwargs):
        policy_data = json.loads(req.body.decode('utf-8'))
        # Assicurati che policy_data contenga: switch, mac, reason (opzionale)
        policy_data.setdefault('reason', 'manual')
        policy_data['blocked'] = True
        # Calcola unlock_time opzionale (ad esempio 0 se immediata)
        policy_data['unlock_time'] = time.time() + 3600  # default 1h blocco
        self.controller.policy_queue.put(policy_data)
        return self._cors_response("Policy added")

    @route('policy', '/policy', methods=['DELETE'])
    def remove_policy(self, req, **kwargs):
        policy_data = json.loads(req.body.decode('utf-8'))
        # Controlla che siano presenti switch e mac
        self.controller.policy_queue.put({'action': 'remove', **policy_data})
        return self._cors_response("Policy removed")

    @route('policy', '/policy', methods=['OPTIONS'])
    def options(self, req, **kwargs):
        return self._cors_response("", status=200)
