#!/usr/bin/env python3
"""
NetGuard v2.2 — Surveillance réseau Freebox + MODE HACK (DNS Proxy)
Copyright (c) 2026 DOW08 — MIT License
pip install requests flask flask-cors scapy
"""
import os,sys,json,time,hmac,hashlib,socket,threading,logging
import csv,io,subprocess,re,concurrent.futures
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try: import requests
except: print("pip install requests");sys.exit(1)
try:
    from flask import Flask,jsonify,request as frequest,send_from_directory,Response
    from flask_cors import CORS
except: print("pip install flask flask-cors");sys.exit(1)

FREEBOX_HOST="http://mafreebox.freebox.fr"
APP_ID="netguard.dashboard";APP_NAME="NetGuard Dashboard";APP_VERSION="2.2.0"
TOKEN_FILE=Path.home()/".netguard_token.json"
DATA_DIR=Path.home()/".netguard_data"
HISTORY_FILE=DATA_DIR/"device_history.json"
KNOWN_FILE=DATA_DIR/"known_devices.json"
ALERTS_FILE=DATA_DIR/"alerts.json"
DNS_AGG_FILE=DATA_DIR/"dns_aggregated.json"
DASHBOARD_DIR=Path(__file__).parent/"dashboard"
LOG_RETENTION=48*3600
DATA_DIR.mkdir(exist_ok=True)
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(),logging.FileHandler(DATA_DIR/"netguard.log",encoding="utf-8")])
log=logging.getLogger("netguard")

# ─── Stockage mémoire ───
dns_log=[];dns_lock=threading.Lock();MAX_DNS=2000
alerts=[];alerts_lock=threading.Lock()
device_history=defaultdict(list);hist_lock=threading.Lock()
known_devices={};known_lock=threading.Lock()
scan_results={};scan_lock=threading.Lock()
bw_history=[];bw_lock=threading.Lock()
dns_agg=defaultdict(lambda:defaultdict(lambda:{"count":0,"first":0,"last":0}));dns_agg_lock=threading.Lock()
ip_to_mac={};ip_to_name={};ipm_lock=threading.Lock()

# ─── MODE HACK ───
hack_mode_active=False
hack_dns_thread=None
hack_dns_stop=threading.Event()
hack_stats={"total_queries":0,"start_time":0,"devices_seen":set()}
hack_stats_lock=threading.Lock()
UPSTREAM_DNS="8.8.8.8"
UPSTREAM_DNS_2="1.1.1.1"

# ─── Persistance ───
def load_data():
    global alerts
    for f,t,n in[(HISTORY_FILE,device_history,"hist"),(KNOWN_FILE,known_devices,"known"),(ALERTS_FILE,alerts,"alerts")]:
        try:
            if f.exists():
                d=json.loads(f.read_text())
                if isinstance(t,dict):t.update(d)
                elif isinstance(t,list):t.extend(d)
                log.info(f"📂 {n}: {len(d)}")
        except Exception as e:log.warning(f"⚠️ {n}: {e}")
    try:
        if DNS_AGG_FILE.exists():
            for ip,doms in json.loads(DNS_AGG_FILE.read_text()).items():
                for dom,st in doms.items():dns_agg[ip][dom]=st
    except:pass

def save_data():
    try:
        with hist_lock:HISTORY_FILE.write_text(json.dumps(dict(device_history),default=str))
        with known_lock:KNOWN_FILE.write_text(json.dumps(known_devices,default=str))
        with alerts_lock:ALERTS_FILE.write_text(json.dumps(alerts[-500:],default=str))
        with dns_agg_lock:DNS_AGG_FILE.write_text(json.dumps({k:dict(v)for k,v in dns_agg.items()},default=str))
    except Exception as e:log.warning(f"⚠️ save: {e}")

def purge():
    cutoff=time.time()-LOG_RETENTION
    with hist_lock:
        for m in list(device_history):
            device_history[m]=[e for e in device_history[m] if e.get("timestamp",0)>cutoff]
            if not device_history[m]:del device_history[m]
    with alerts_lock:alerts[:]=[a for a in alerts if a.get("timestamp",0)>cutoff]
    with dns_lock:dns_log[:]=[d for d in dns_log if d.get("timestamp",0)>cutoff]
    with dns_agg_lock:
        for ip in list(dns_agg):
            for dom in list(dns_agg[ip]):
                if dns_agg[ip][dom].get("last",0)<cutoff:del dns_agg[ip][dom]
            if not dns_agg[ip]:del dns_agg[ip]
    with bw_lock:bw_history[:]=[b for b in bw_history if b.get("timestamp",0)>cutoff]
    log.info("🧹 Purge 48h OK")

def add_alert(lvl,title,msg,mac=None):
    with alerts_lock:
        alerts.append({"id":int(time.time()*1000),"timestamp":time.time(),"level":lvl,"title":title,"message":msg,"device_mac":mac,"read":False})
        if len(alerts)>500:alerts.pop(0)

def get_local_ip():
    try:s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(("192.168.1.1",53));ip=s.getsockname()[0];s.close();return ip
    except:return None

# ─── DNS Sniffer passif ───
def start_dns_sniffer():
    try:
        from scapy.all import sniff,DNS,DNSQR,IP,conf
        if os.name=="nt":
            try:conf.sniff_promisc=True
            except:pass
        log.info("🔍 Sniffer DNS démarré")
        def cb(pkt):
            if not pkt.haslayer(DNS) or not pkt.haslayer(IP):return
            src=pkt[IP].src;now=time.time()
            if pkt[DNS].qr==0 and pkt.haslayer(DNSQR):
                q=pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                if q.endswith(".local")or q.endswith(".arpa")or"."not in q:return
                if q in("mafreebox.freebox.fr","freebox-server.local"):return
                dip=src if src.startswith("192.168.")else pkt[IP].dst
                with ipm_lock:dm=ip_to_mac.get(dip,dip);dn=ip_to_name.get(dip,dip)
                with dns_lock:
                    dns_log.append({"timestamp":now,"src_ip":dip,"device_name":dn,"query":q,"type":"A"if pkt[DNSQR].qtype==1 else"AAAA"if pkt[DNSQR].qtype==28 else str(pkt[DNSQR].qtype)})
                    if len(dns_log)>MAX_DNS:dns_log.pop(0)
                parts=q.split(".");domain=".".join(parts[-2:])if len(parts)>=2 else q
                with dns_agg_lock:
                    a=dns_agg[dm][domain];a["count"]=a.get("count",0)+1
                    if not a.get("first"):a["first"]=now
                    a["last"]=now;a["device_name"]=dn;a["device_ip"]=dip
        sniff(filter="udp port 53",prn=cb,store=0,promisc=True)
    except ImportError:log.warning("⚠️ scapy manquant")
    except PermissionError:log.warning("⚠️ droits admin requis")
    except Exception as e:log.warning(f"⚠️ DNS sniffer: {e}")

# ─── Port Scanner ───
def scan_port(ip,port,timeout=1):
    try:s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(timeout);r=s.connect_ex((ip,port));s.close();return port if r==0 else None
    except:return None

def scan_device(ip,mac):
    ports=[(21,"FTP"),(22,"SSH"),(23,"Telnet"),(53,"DNS"),(80,"HTTP"),(135,"RPC"),(139,"NetBIOS"),(443,"HTTPS"),(445,"SMB"),(3306,"MySQL"),(3389,"RDP"),(5432,"PostgreSQL"),(5900,"VNC"),(8080,"HTTP-Alt"),(8443,"HTTPS-Alt"),(27017,"MongoDB")]
    op=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        fs={ex.submit(scan_port,ip,p[0]):p for p in ports}
        for f in concurrent.futures.as_completed(fs):
            if f.result()is not None:op.append({"port":fs[f][0],"service":fs[f][1]})
    risky={21,23,135,139,445,3389,5900,6379,27017}
    risk="high" if any(p["port"]in risky for p in op) else("medium" if len(op)>5 else "low")
    r={"ip":ip,"mac":mac,"timestamp":time.time(),"ports":sorted(op,key=lambda x:x["port"]),"risk_level":risk,"total_open":len(op)}
    with scan_lock:scan_results[mac]=r
    if risk=="high":add_alert("danger",f"Ports dangereux {ip}",", ".join(f"{p['port']}/{p['service']}"for p in op if p["port"]in risky),mac)

def run_speedtest():
    r={"download":0,"upload":0,"ping":0,"timestamp":time.time()}
    try:
        cmd=["ping","-n"if os.name=="nt"else"-c","4","8.8.8.8"]
        o=subprocess.run(cmd,capture_output=True,text=True,timeout=10).stdout
        m=(re.search(r"Moyenne\s*=\s*(\d+)",o)or re.search(r"Average\s*=\s*(\d+)",o))if os.name=="nt"else re.search(r"avg.*?=.*?/([\d.]+)/",o)
        if m:r["ping"]=float(m.group(1))
    except:pass
    try:
        t0=time.time();resp=requests.get("https://speed.cloudflare.com/__down?bytes=10000000",timeout=15,stream=True);tot=0
        for c in resp.iter_content(8192):tot+=len(c)
        el=time.time()-t0
        if el>0 and tot>0:r["download"]=round((tot*8)/(el*1e6),2)
    except:pass
    try:
        d=b"0"*2000000;t0=time.time();requests.post("https://speed.cloudflare.com/__up",data=d,timeout=15)
        el=time.time()-t0
        if el>0:r["upload"]=round((len(d)*8)/(el*1e6),2)
    except:pass
    return r

# ─── Monitoring Loop ───
def monitoring_loop(fbx):
    prev=set();pc=0
    while True:
        try:
            hosts=fbx.get_lan_hosts()
            if hosts:
                cur=set()
                for h in hosts:
                    mac=h.get("l2ident",{}).get("id","");active=h.get("active",False);name=h.get("primary_name","Inconnu")
                    if not mac:continue
                    ipv4=""
                    for c in h.get("l3connectivities",[]):
                        if c.get("af")=="ipv4":ipv4=c.get("addr","");break
                    if ipv4:
                        with ipm_lock:ip_to_mac[ipv4]=mac;ip_to_name[ipv4]=name
                    if active:cur.add(mac)
                    with hist_lock:device_history[mac].append({"timestamp":time.time(),"connected":active,"ip":ipv4,"name":name})
                    with known_lock:
                        if mac not in known_devices:
                            known_devices[mac]={"name":name,"first_seen":time.time(),"trusted":False,"vendor":h.get("vendor_name","")}
                            if prev:add_alert("warning",f"Nouvel appareil: {name}",f"MAC: {mac} · {h.get('vendor_name','?')}",mac)
                for mac in prev-cur:
                    n=known_devices.get(mac,{}).get("name",mac);add_alert("info",f"Déconnecté: {n}",f"MAC: {mac}",mac)
                prev=cur
            bw=fbx.get_bandwidth()
            if bw:
                with bw_lock:
                    bw_history.append({"timestamp":time.time(),"rate_down":bw.get("rate_down",0),"rate_up":bw.get("rate_up",0)})
                    if len(bw_history)>720:bw_history.pop(0)
            pc+=1
            if pc>=60:purge();pc=0
            save_data()
        except Exception as e:log.error(f"Monitor: {e}")
        time.sleep(10)

# ═══════════════════════════════════════════════════
# 🔴 MODE HACK — DNS Proxy
# ═══════════════════════════════════════════════════
def _dns_proxy_worker():
    global hack_mode_active
    log.info("🔴 HACK: Proxy DNS démarrage port 53...")
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:sock.bind(("0.0.0.0",53))
        except (PermissionError,OSError) as e:
            log.error(f"🔴 Port 53 indisponible: {e}");hack_mode_active=False;return
        sock.settimeout(1.0)
        log.info("🔴 HACK: Proxy DNS actif ✓")
        with hack_stats_lock:
            hack_stats["start_time"]=time.time();hack_stats["total_queries"]=0;hack_stats["devices_seen"]=set()
        while not hack_dns_stop.is_set():
            try:
                data,addr=sock.recvfrom(4096)
                cip=addr[0];now=time.time()
                domain=_parse_dns(data)
                if domain and not domain.endswith(".local")and not domain.endswith(".arpa")and"."in domain:
                    with ipm_lock:dm=ip_to_mac.get(cip,cip);dn=ip_to_name.get(cip,cip)
                    with dns_lock:
                        dns_log.append({"timestamp":now,"src_ip":cip,"device_name":dn,"query":domain,"type":"A","via":"proxy"})
                        if len(dns_log)>MAX_DNS:dns_log.pop(0)
                    parts=domain.split(".");bd=".".join(parts[-2:])if len(parts)>=2 else domain
                    with dns_agg_lock:
                        a=dns_agg[dm][bd];a["count"]=a.get("count",0)+1
                        if not a.get("first"):a["first"]=now
                        a["last"]=now;a["device_name"]=dn;a["device_ip"]=cip
                    with hack_stats_lock:hack_stats["total_queries"]+=1;hack_stats["devices_seen"].add(cip)
                resp=_forward_dns(data)
                if resp:sock.sendto(resp,addr)
            except socket.timeout:continue
            except Exception as e:
                if not hack_dns_stop.is_set():log.warning(f"🔴 Proxy: {e}")
        sock.close();log.info("🔴 Proxy DNS arrêté")
    except Exception as e:log.error(f"🔴 Fatal: {e}");hack_mode_active=False

def _parse_dns(data):
    try:
        pos=12;labels=[]
        while pos<len(data):
            l=data[pos]
            if l==0 or l>=192:break
            pos+=1;labels.append(data[pos:pos+l].decode(errors="ignore"));pos+=l
        return".".join(labels)if labels else None
    except:return None

def _forward_dns(data):
    for dns in[UPSTREAM_DNS,UPSTREAM_DNS_2]:
        try:s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(data,(dns,53));r,_=s.recvfrom(4096);s.close();return r
        except:
            try:s.close()
            except:pass
    return None

def _kill_dnscache_win():
    """Libère le port 53 sur Windows"""
    if os.name!="nt":return True,"OK"
    # Tester si port déjà libre
    try:
        t=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);t.bind(("0.0.0.0",53));t.close()
        return True,"Port 53 déjà libre"
    except:pass
    # Méthode 1: net stop
    try:
        subprocess.run(["net","stop","dnscache"],capture_output=True,timeout=10)
        time.sleep(1)
        t=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:t.bind(("0.0.0.0",53));t.close();return True,"net stop OK"
        except:t.close()
    except:pass
    # Méthode 2: sc stop
    try:
        subprocess.run(["sc","stop","dnscache"],capture_output=True,timeout=10)
        time.sleep(1)
        t=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:t.bind(("0.0.0.0",53));t.close();return True,"sc stop OK"
        except:t.close()
    except:pass
    # Méthode 3: registre (nécessite reboot)
    try:
        subprocess.run(["reg","add","HKLM\\SYSTEM\\CurrentControlSet\\services\\Dnscache","/v","Start","/t","REG_DWORD","/d","4","/f"],capture_output=True,timeout=10)
        t=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:t.bind(("0.0.0.0",53));t.close();return True,"registre OK"
        except:t.close();return False,"Redémarrage nécessaire (registre modifié)"
    except:return False,"Échec libération port 53"

def _restore_dnscache_win():
    if os.name!="nt":return
    try:
        subprocess.run(["reg","add","HKLM\\SYSTEM\\CurrentControlSet\\services\\Dnscache","/v","Start","/t","REG_DWORD","/d","2","/f"],capture_output=True,timeout=10)
        subprocess.run(["net","start","dnscache"],capture_output=True,timeout=10)
        log.info("🔴 DNS Windows restauré")
    except:pass

def hack_start():
    global hack_mode_active
    if hack_mode_active:return{"ok":False,"error":"Déjà actif","steps":[]}
    results={"steps":[],"ok":False,"error":"","my_ip":"","need_reboot":False}
    my_ip=get_local_ip()
    if not my_ip:results["error"]="IP locale introuvable";return results
    results["my_ip"]=my_ip;results["steps"].append(f"IP: {my_ip}")
    # Libérer port 53
    ok,msg=_kill_dnscache_win()
    results["steps"].append(f"{'✅' if ok else '⚠️'} {msg}")
    if not ok:
        results["need_reboot"]=True;results["error"]=msg;return results
    # Lancer proxy
    hack_dns_stop.clear();hack_mode_active=True
    threading.Thread(target=_dns_proxy_worker,daemon=True).start()
    time.sleep(1.5)
    if not hack_mode_active:
        results["error"]="Proxy n'a pas démarré";return results
    results["steps"].append("✅ Proxy DNS actif sur :53")
    results["steps"].append(f"→ Configurez Freebox DHCP DNS: {my_ip}")
    results["ok"]=True
    add_alert("danger","🔴 MODE HACK activé",f"Proxy DNS sur {my_ip}:53")
    return results

def hack_stop():
    global hack_mode_active
    results={"steps":[],"ok":True}
    hack_dns_stop.set();hack_mode_active=False;time.sleep(1)
    results["steps"].append("✅ Proxy DNS arrêté")
    _restore_dnscache_win()
    results["steps"].append("✅ DNS Windows restauré")
    add_alert("info","🔴 MODE HACK désactivé","Proxy arrêté, DNS Windows restauré.")
    return results

# ═══════════════════════════════════════════════════
# FREEBOX API
# ═══════════════════════════════════════════════════
class FreeboxAPI:
    def __init__(self):
        self.session_token=None;self.app_token=None;self.api_base=None;self._discover()
    def _discover(self):
        try:
            d=requests.get(f"{FREEBOX_HOST}/api_version",timeout=5).json()
            self.api_base=f"{FREEBOX_HOST}{d.get('api_base_url','/api/')}v{d.get('api_version','8.0').split('.')[0]}"
            log.info(f"✅ Freebox API v{d.get('api_version')} — {self.api_base}")
        except Exception as e:log.error(f"❌ {e}");self.api_base=f"{FREEBOX_HOST}/api/v8"
    def _url(self,ep):return f"{self.api_base}/{ep}"
    def authorize(self):
        if TOKEN_FILE.exists():
            try:self.app_token=json.loads(TOKEN_FILE.read_text())["app_token"];log.info("🔑 Token OK");return True
            except:pass
        log.info("🔐 Autorisation... Validez sur la Freebox!")
        try:
            d=requests.post(self._url("login/authorize"),json={"app_id":APP_ID,"app_name":APP_NAME,"app_version":APP_VERSION,"device_name":socket.gethostname()},timeout=10).json()
            if not d.get("success"):return False
            self.app_token=d["result"]["app_token"];tid=d["result"]["track_id"]
            for i in range(90):
                time.sleep(2);st=requests.get(self._url(f"login/authorize/{tid}"),timeout=5).json()["result"]["status"]
                if st=="granted":
                    log.info("✅ Autorisé!");TOKEN_FILE.write_text(json.dumps({"app_token":self.app_token}))
                    try:TOKEN_FILE.chmod(0o600)
                    except:pass
                    return True
                elif st in("denied","timeout"):return False
                elif i%5==0:log.info(f"⏳ {90-i*2}s...")
            return False
        except Exception as e:log.error(f"❌ {e}");return False
    def login(self):
        if not self.app_token and not self.authorize():return False
        try:
            ch=requests.get(self._url("login"),timeout=5).json()["result"]["challenge"]
            pw=hmac.new(self.app_token.encode(),ch.encode(),hashlib.sha1).hexdigest()
            d=requests.post(self._url("login/session"),json={"app_id":APP_ID,"password":pw},timeout=5).json()
            if d.get("success"):
                self.session_token=d["result"]["session_token"]
                log.info(f"✅ Session — {', '.join(k for k,v in d['result'].get('permissions',{}).items() if v)}")
                return True
            if d.get("error_code")=="invalid_token":TOKEN_FILE.unlink(missing_ok=True);self.app_token=None;return self.login()
            return False
        except Exception as e:log.error(f"❌ {e}");return False
    def _h(self):return{"X-Fbx-App-Auth":self.session_token}if self.session_token else{}
    def _get(self,ep):
        try:
            d=requests.get(self._url(ep),headers=self._h(),timeout=10).json()
            if d.get("success"):return d.get("result")
            if d.get("error_code")in("auth_required","invalid_session"):
                if self.login():
                    d=requests.get(self._url(ep),headers=self._h(),timeout=10).json()
                    if d.get("success"):return d.get("result")
            return None
        except:return None
    def get_lan_hosts(self):
        h=self._get("lan/browser/pub")
        if h:return h
        ifaces=self._get("lan/browser/interfaces")
        if not ifaces:return[]
        r=[]
        for i in ifaces:
            x=self._get(f"lan/browser/{i.get('name','')}")
            if x:r.extend(x)
        return r
    def get_connection_status(self):return self._get("connection")or{}
    def get_bandwidth(self):
        s=self.get_connection_status()
        return{"rate_down":s.get("rate_down",0),"rate_up":s.get("rate_up",0),"bandwidth_down":s.get("bandwidth_down",0),"bandwidth_up":s.get("bandwidth_up",0),"bytes_down":s.get("bytes_down",0),"bytes_up":s.get("bytes_up",0),"state":s.get("state",""),"ipv4":s.get("ipv4","")}if s else{}
    def get_system_info(self):return self._get("system")or{}
    def get_wifi_stations(self):return self._get("wifi/stations")or[]
    def get_fw_rules(self):return self._get("fw/redir")or[]
    def get_parental_filter(self):return self._get("parental/config")or{}
    def get_connection_logs(self):return self._get("connection/logs")or[]

# ═══════════════════════════════════════════════════
# FLASK — toutes les routes
# ═══════════════════════════════════════════════════
app=Flask(__name__,static_folder="dashboard");CORS(app);fbx=None

def parse_dev(h):
    l2=h.get("l2ident",{});mac=l2.get("id","");ipv4=""
    for c in h.get("l3connectivities",[]):
        if c.get("af")=="ipv4":ipv4=c.get("addr","");
        if c.get("reachable"):break
    return{"id":h.get("id",mac),"name":h.get("primary_name","Inconnu"),"mac":mac,"ip":ipv4,"type":h.get("host_type","unknown"),"vendor":h.get("vendor_name",""),"connected":h.get("active",False),"last_seen":h.get("last_time_reachable",0),"trusted":known_devices.get(mac,{}).get("trusted",False)}

@app.route("/")
def index():return send_from_directory("dashboard","index.html")
@app.route("/api/status")
def r_status():return jsonify({"connected":fbx.session_token is not None if fbx else False,"timestamp":time.time(),"version":APP_VERSION,"retention_h":LOG_RETENTION//3600})
@app.route("/api/devices")
def r_devices():
    h=fbx.get_lan_hosts()if fbx else[];return jsonify(sorted([parse_dev(x)for x in h],key=lambda d:(not d["connected"],d["name"].lower()))if h else[])
@app.route("/api/bandwidth")
def r_bw():return jsonify(fbx.get_bandwidth()if fbx else{})
@app.route("/api/bandwidth/history")
def r_bwh():
    with bw_lock:return jsonify(list(bw_history))
@app.route("/api/system")
def r_sys():return jsonify(fbx.get_system_info()if fbx else{})
@app.route("/api/dns/log")
def r_dns():
    with dns_lock:return jsonify(list(dns_log))
@app.route("/api/connection/logs")
def r_cl():return jsonify(fbx.get_connection_logs()if fbx else[])
@app.route("/api/wifi/stations")
def r_ws():return jsonify(fbx.get_wifi_stations()if fbx else[])

# Bande passante par appareil
_dbw_prev={};_dbw_lock=threading.Lock()
@app.route("/api/devices/bandwidth")
def r_dbw():
    stations=fbx.get_wifi_stations()if fbx else[];result={};now=time.time()
    for s in stations:
        mac=s.get("mac","")
        if not mac:continue
        rx=s.get("rx_rate",0);tx=s.get("tx_rate",0);rxb=s.get("rx_bytes",0);txb=s.get("tx_bytes",0);sig=s.get("signal",0)
        with _dbw_lock:
            p=_dbw_prev.get(mac,{});dt=now-p.get("ts",now)
            cr=rx;ct=tx
            if dt>0 and dt<30:
                if rx==0:cr=max(0,rxb-p.get("rx",0))/dt
                if tx==0:ct=max(0,txb-p.get("tx",0))/dt
            _dbw_prev[mac]={"rx":rxb,"tx":txb,"ts":now}
        result[mac]={"name":known_devices.get(mac,{}).get("name",s.get("hostname",mac)),"rx_rate":round(cr),"tx_rate":round(ct),"rx_bytes":rxb,"tx_bytes":txb,"signal":sig}
    return jsonify(result)

@app.route("/api/alerts")
def r_alts():
    with alerts_lock:return jsonify(list(reversed(alerts[-100:])))
@app.route("/api/alerts/unread")
def r_alts_u():
    with alerts_lock:return jsonify({"count":sum(1 for a in alerts if not a.get("read"))})
@app.route("/api/alerts/read",methods=["POST"])
def r_alts_r():
    with alerts_lock:
        for a in alerts:a["read"]=True
    return jsonify({"ok":True})
@app.route("/api/history/<mac>")
def r_hist(mac):
    with hist_lock:return jsonify(device_history.get(mac,[]))
@app.route("/api/history")
def r_hist_all():
    with hist_lock:
        return jsonify({m:{"name":known_devices.get(m,{}).get("name",m),"total":len(e),"first":e[0]["timestamp"],"last":e[-1]["timestamp"]}for m,e in device_history.items()if e})
@app.route("/api/known_devices")
def r_kd():
    with known_lock:return jsonify(known_devices)
@app.route("/api/known_devices/<mac>/trust",methods=["POST"])
def r_tr(mac):
    with known_lock:
        if mac in known_devices:known_devices[mac]["trusted"]=True;save_data();return jsonify({"ok":True})
    return jsonify({"error":"not found"}),404
@app.route("/api/known_devices/<mac>/untrust",methods=["POST"])
def r_utr(mac):
    with known_lock:
        if mac in known_devices:known_devices[mac]["trusted"]=False;save_data();return jsonify({"ok":True})
    return jsonify({"error":"not found"}),404
@app.route("/api/intruders")
def r_intr():
    h=fbx.get_lan_hosts()if fbx else[];return jsonify([parse_dev(x)for x in(h or[])if x.get("active")and not known_devices.get(x.get("l2ident",{}).get("id",""),{}).get("trusted")])
@app.route("/api/scan/<mac>",methods=["POST"])
def r_sc(mac):
    for h in(fbx.get_lan_hosts()if fbx else[])or[]:
        if h.get("l2ident",{}).get("id","")==mac:
            d=parse_dev(h)
            if d["ip"]:threading.Thread(target=scan_device,args=(d["ip"],mac),daemon=True).start();return jsonify({"status":"scanning"})
    return jsonify({"error":"not found"}),404
@app.route("/api/scan/<mac>",methods=["GET"])
def r_scr(mac):
    with scan_lock:return jsonify(scan_results.get(mac,{"status":"no_scan"}))
@app.route("/api/scan/all",methods=["POST"])
def r_sca():
    h=fbx.get_lan_hosts()if fbx else[];c=0
    for x in(h or[]):
        if x.get("active"):
            d=parse_dev(x)
            if d["ip"]and"192.168.1.1"not in d["ip"]:threading.Thread(target=scan_device,args=(d["ip"],d["mac"]),daemon=True).start();c+=1;time.sleep(.5)
    return jsonify({"status":"scanning","devices":c})
@app.route("/api/scan/results")
def r_scra():
    with scan_lock:return jsonify(scan_results)
@app.route("/api/speedtest",methods=["POST"])
def r_sp():return jsonify(run_speedtest())

# DNS Aggregation
@app.route("/api/dns/aggregated")
def r_da():
    with dns_agg_lock:
        r={}
        for dk,doms in dns_agg.items():
            dn=known_devices.get(dk,{}).get("name")or ip_to_name.get(dk,dk)
            sd=sorted(doms.items(),key=lambda x:x[1].get("count",0),reverse=True)
            r[dk]={"device_name":dn,"total_queries":sum(d[1].get("count",0)for d in sd),"unique_domains":len(sd),
                "domains":[{"domain":d,"count":s.get("count",0),"first_seen":s.get("first",0),"last_seen":s.get("last",0)}for d,s in sd[:100]]}
        return jsonify(dict(sorted(r.items(),key=lambda x:x[1]["total_queries"],reverse=True)))

@app.route("/api/dns/aggregated/global")
def r_dag():
    with dns_agg_lock:
        gl=defaultdict(lambda:{"count":0,"devices":set(),"last":0})
        for dk,doms in dns_agg.items():
            dn=known_devices.get(dk,{}).get("name")or ip_to_name.get(dk,dk)
            for dom,st in doms.items():gl[dom]["count"]+=st.get("count",0);gl[dom]["devices"].add(dn or dk);gl[dom]["last"]=max(gl[dom]["last"],st.get("last",0))
        return jsonify([{"domain":d,"count":s["count"],"devices":list(s["devices"]),"device_count":len(s["devices"]),"last_seen":s["last"]}for d,s in sorted(gl.items(),key=lambda x:x[1]["count"],reverse=True)[:200]])

# Exports
@app.route("/api/export/devices/csv")
def e_d():
    h=fbx.get_lan_hosts()if fbx else[];devs=[parse_dev(x)for x in h]if h else[]
    o=io.StringIO();w=csv.DictWriter(o,fieldnames=["name","mac","ip","type","vendor","connected","trusted","last_seen"]);w.writeheader()
    for d in devs:w.writerow({k:(datetime.fromtimestamp(d[k]).isoformat()if k=="last_seen"and d[k]else d[k])for k in w.fieldnames})
    o.seek(0);return Response(o.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=netguard_devices_{datetime.now():%Y%m%d_%H%M}.csv"})
@app.route("/api/export/alerts/csv")
def e_a():
    o=io.StringIO();w=csv.DictWriter(o,fieldnames=["timestamp","level","title","message","device_mac"]);w.writeheader()
    with alerts_lock:
        for a in alerts:w.writerow({"timestamp":datetime.fromtimestamp(a["timestamp"]).isoformat(),"level":a["level"],"title":a["title"],"message":a["message"],"device_mac":a.get("device_mac","")})
    o.seek(0);return Response(o.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=netguard_alerts_{datetime.now():%Y%m%d_%H%M}.csv"})
@app.route("/api/export/scan/csv")
def e_s():
    o=io.StringIO();w=csv.writer(o);w.writerow(["MAC","IP","Port","Service","Risk","Time"])
    with scan_lock:
        for m,r in scan_results.items():
            for p in r.get("ports",[]):w.writerow([m,r["ip"],p["port"],p["service"],r["risk_level"],datetime.fromtimestamp(r["timestamp"]).isoformat()])
    o.seek(0);return Response(o.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=netguard_scan_{datetime.now():%Y%m%d_%H%M}.csv"})
@app.route("/api/export/dns/csv")
def e_dns():
    o=io.StringIO();w=csv.writer(o);w.writerow(["Appareil","Domaine","Requêtes","Première","Dernière"])
    with dns_agg_lock:
        for dk,doms in dns_agg.items():
            dn=known_devices.get(dk,{}).get("name",ip_to_name.get(dk,dk))
            for dom,st in sorted(doms.items(),key=lambda x:x[1].get("count",0),reverse=True):
                w.writerow([dn,dom,st.get("count",0),datetime.fromtimestamp(st["first"]).isoformat()if st.get("first")else"",datetime.fromtimestamp(st["last"]).isoformat()if st.get("last")else""])
    o.seek(0);return Response(o.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=netguard_dns_{datetime.now():%Y%m%d_%H%M}.csv"})

# ─── API MODE HACK ───
@app.route("/api/hack/status")
def r_hack_st():
    with hack_stats_lock:
        return jsonify({"active":hack_mode_active,"total_queries":hack_stats.get("total_queries",0),
            "start_time":hack_stats.get("start_time",0),"devices_seen":len(hack_stats.get("devices_seen",set())),
            "upstream_dns":UPSTREAM_DNS,"my_ip":get_local_ip()or""})

@app.route("/api/hack/start",methods=["POST"])
def r_hack_on():return jsonify(hack_start())

@app.route("/api/hack/stop",methods=["POST"])
def r_hack_off():
    if not hack_mode_active:return jsonify({"ok":False,"error":"Pas actif","steps":[]})
    return jsonify(hack_stop())

@app.route("/api/hack/dns_live")
def r_hack_live():
    limit=int(frequest.args.get("limit",50))
    with dns_lock:return jsonify([d for d in dns_log if d.get("via")=="proxy"][-limit:])

# ═══════════════════════════════════════════════════
# MAIN — en dernier
# ═══════════════════════════════════════════════════
def main():
    global fbx
    print("""
    ╔══════════════════════════════════════════════╗
    ║   🔒  NetGuard v2.2 — DOW08                  ║
    ║   Surveillance réseau · MODE HACK            ║
    ╚══════════════════════════════════════════════╝""")
    load_data();purge()
    fbx=FreeboxAPI()
    if not fbx.login():log.error("Connexion impossible.");sys.exit(1)
    threading.Thread(target=start_dns_sniffer,daemon=True).start()
    threading.Thread(target=monitoring_loop,args=(fbx,),daemon=True).start()
    DASHBOARD_DIR.mkdir(exist_ok=True)
    port=8765
    log.info(f"🌐 http://localhost:{port}")
    log.info(f"🧹 Rétention: {LOG_RETENTION//3600}h")
    log.info("Ctrl+C pour arrêter\n")
    try:app.run(host="0.0.0.0",port=port,debug=False,threaded=True)
    except KeyboardInterrupt:
        if hack_mode_active:hack_stop()
        save_data();log.info("👋 Arrêté.")

if __name__=="__main__":main()
