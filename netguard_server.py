#!/usr/bin/env python3
"""
NetGuard v2.1 — Serveur complet Freebox
Logs 48h max · Agrégateur DNS · Démarrage auto
pip install requests flask flask-cors
"""
import os,sys,json,time,hmac,hashlib,socket,threading,logging
import csv,io,subprocess,re,concurrent.futures
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try: import requests
except: print("pip install requests");sys.exit(1)
try:
    from flask import Flask,jsonify,request,send_from_directory,Response
    from flask_cors import CORS
except: print("pip install flask flask-cors");sys.exit(1)

FREEBOX_HOST="http://mafreebox.freebox.fr"
APP_ID="netguard.dashboard";APP_NAME="NetGuard Dashboard";APP_VERSION="2.1.0"
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

dns_log=[];dns_lock=threading.Lock();MAX_DNS=2000
alerts=[];alerts_lock=threading.Lock()
device_history=defaultdict(list);hist_lock=threading.Lock()
known_devices={};known_lock=threading.Lock()
scan_results={};scan_lock=threading.Lock()
bw_history=[];bw_lock=threading.Lock()
dns_agg=defaultdict(lambda:defaultdict(lambda:{"count":0,"first":0,"last":0}));dns_agg_lock=threading.Lock()
ip_to_mac={};ip_to_name={};ipm_lock=threading.Lock()

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
            log.info(f"📂 dns_agg loaded")
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
    lf=DATA_DIR/"netguard.log"
    try:
        if lf.exists() and lf.stat().st_size>10*1024*1024:
            lines=lf.read_text(errors="ignore").splitlines();lf.write_text("\n".join(lines[-5000:])+"\n")
    except:pass
    log.info("🧹 Purge 48h OK")

def add_alert(lvl,title,msg,mac=None):
    a={"id":int(time.time()*1000),"timestamp":time.time(),"level":lvl,"title":title,"message":msg,"device_mac":mac,"read":False}
    with alerts_lock:
        alerts.append(a)
        if len(alerts)>500:alerts.pop(0)

def start_dns_sniffer():
    try:
        from scapy.all import sniff,DNS,DNSQR,IP
        log.info("🔍 Sniffer DNS démarré")
        def cb(pkt):
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                q=pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                src=pkt[IP].src if pkt.haslayer(IP) else"?"
                now=time.time()
                if q.endswith(".local")or q.endswith(".arpa")or"."not in q:return
                with dns_lock:
                    dns_log.append({"timestamp":now,"src_ip":src,"query":q,"type":"A"if pkt[DNSQR].qtype==1 else"AAAA"if pkt[DNSQR].qtype==28 else str(pkt[DNSQR].qtype)})
                    if len(dns_log)>MAX_DNS:dns_log.pop(0)
                parts=q.split(".");domain=".".join(parts[-2:])if len(parts)>=2 else q
                with ipm_lock:dk=ip_to_mac.get(src,src)
                with dns_agg_lock:
                    a=dns_agg[dk][domain];a["count"]=a.get("count",0)+1
                    if not a.get("first"):a["first"]=now
                    a["last"]=now;a["device_name"]=ip_to_name.get(src,src);a["device_ip"]=src
        sniff(filter="udp port 53",prn=cb,store=0)
    except ImportError:log.warning("⚠️ scapy manquant")
    except PermissionError:log.warning("⚠️ sudo requis pour DNS")
    except Exception as e:log.warning(f"⚠️ DNS: {e}")

def scan_port(ip,port,timeout=1):
    try:s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(timeout);r=s.connect_ex((ip,port));s.close();return port if r==0 else None
    except:return None

def scan_device(ip,mac):
    ports=[(21,"FTP"),(22,"SSH"),(23,"Telnet"),(25,"SMTP"),(53,"DNS"),(80,"HTTP"),(110,"POP3"),(135,"RPC"),(139,"NetBIOS"),(143,"IMAP"),(443,"HTTPS"),(445,"SMB"),(993,"IMAPS"),(995,"POP3S"),(1433,"MSSQL"),(3306,"MySQL"),(3389,"RDP"),(5432,"PostgreSQL"),(5900,"VNC"),(5901,"VNC"),(6379,"Redis"),(8080,"HTTP-Alt"),(8443,"HTTPS-Alt"),(9090,"Admin"),(27017,"MongoDB")]
    log.info(f"🔍 Scan {ip}...")
    op=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        fs={ex.submit(scan_port,ip,p[0]):p for p in ports}
        for f in concurrent.futures.as_completed(fs):
            if f.result()is not None:op.append({"port":fs[f][0],"service":fs[f][1]})
    risky={21,23,135,139,445,3389,5900,5901,6379,27017}
    risk="low"
    for p in op:
        if p["port"]in risky:risk="high";break
    if len(op)>5 and risk=="low":risk="medium"
    r={"ip":ip,"mac":mac,"timestamp":time.time(),"ports":sorted(op,key=lambda x:x["port"]),"risk_level":risk,"total_open":len(op)}
    with scan_lock:scan_results[mac]=r
    if risk=="high":add_alert("danger",f"Ports dangereux {ip}",", ".join(f"{p['port']}/{p['service']}"for p in op if p["port"]in risky),mac)
    return r

def run_speedtest():
    r={"download":0,"upload":0,"ping":0,"timestamp":time.time()}
    try:
        cmd=["ping","-n"if os.name=="nt"else"-c","4","8.8.8.8"]
        o=subprocess.run(cmd,capture_output=True,text=True,timeout=10).stdout
        m=re.search(r"Moyenne\s*=\s*(\d+)",o)or re.search(r"Average\s*=\s*(\d+)",o)if os.name=="nt"else re.search(r"avg.*?=.*?/([\d.]+)/",o)
        if m:r["ping"]=float(m.group(1))
    except:pass
    try:
        for u in["https://speed.cloudflare.com/__down?bytes=10000000"]:
            t0=time.time();resp=requests.get(u,timeout=15,stream=True);tot=0
            for c in resp.iter_content(8192):tot+=len(c);
            el=time.time()-t0
            if el>0 and tot>0:r["download"]=round((tot*8)/(el*1e6),2);break
    except:pass
    try:
        d=b"0"*2000000;t0=time.time();requests.post("https://speed.cloudflare.com/__up",data=d,timeout=15)
        el=time.time()-t0
        if el>0:r["upload"]=round((len(d)*8)/(el*1e6),2)
    except:pass
    return r

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
                log.info(f"✅ Session OK — {', '.join(k for k,v in d['result'].get('permissions',{}).items() if v)}")
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
        return{"rate_down":s.get("rate_down",0),"rate_up":s.get("rate_up",0),"bandwidth_down":s.get("bandwidth_down",0),"bandwidth_up":s.get("bandwidth_up",0),"bytes_down":s.get("bytes_down",0),"bytes_up":s.get("bytes_up",0),"state":s.get("state",""),"ipv4":s.get("ipv4",""),"ipv6":s.get("ipv6","")}if s else{}
    def get_system_info(self):return self._get("system")or{}
    def get_fw_rules(self):return self._get("fw/redir")or[]
    def get_parental_filter(self):return self._get("parental/config")or{}
    def get_wifi_stations(self):return self._get("wifi/stations")or[]
    def get_connection_logs(self):return self._get("connection/logs")or[]

# ═══ FLASK ═══
app=Flask(__name__,static_folder="dashboard");CORS(app);fbx=None

def parse_dev(h):
    l2=h.get("l2ident",{});mac=l2.get("id","");ipv4=""
    for c in h.get("l3connectivities",[]):
        if c.get("af")=="ipv4":ipv4=c.get("addr","");
        if c.get("reachable"):break
    return{"id":h.get("id",mac),"name":h.get("primary_name","Inconnu"),"mac":mac,"ip":ipv4,"type":h.get("host_type","unknown"),"vendor":h.get("vendor_name",""),"connected":h.get("active",False),"reachable":h.get("reachable",False),"last_seen":h.get("last_time_reachable",0),"first_seen":h.get("first_activity",0),"access_type":h.get("access_point",{}).get("type",""),"trusted":known_devices.get(mac,{}).get("trusted",False)}

@app.route("/")
def index():return send_from_directory("dashboard","index.html")
@app.route("/api/status")
def api_status():return jsonify({"connected":fbx.session_token is not None,"timestamp":time.time(),"version":APP_VERSION,"retention_h":LOG_RETENTION//3600})
@app.route("/api/devices")
def api_devices():
    h=fbx.get_lan_hosts();return jsonify(sorted([parse_dev(x)for x in h],key=lambda d:(not d["connected"],d["name"].lower()))if h else[])
@app.route("/api/bandwidth")
def api_bw():return jsonify(fbx.get_bandwidth())
@app.route("/api/bandwidth/history")
def api_bwh():
    with bw_lock:return jsonify(list(bw_history))
@app.route("/api/system")
def api_sys():return jsonify(fbx.get_system_info())
@app.route("/api/dns/log")
def api_dnslog():
    with dns_lock:return jsonify(list(dns_log))
@app.route("/api/connection/logs")
def api_cl():return jsonify(fbx.get_connection_logs())
@app.route("/api/fw/rules")
def api_fw():return jsonify(fbx.get_fw_rules())
@app.route("/api/parental")
def api_par():return jsonify(fbx.get_parental_filter())
@app.route("/api/wifi/stations")
def api_ws():return jsonify(fbx.get_wifi_stations())
@app.route("/api/alerts")
def api_alts():
    with alerts_lock:return jsonify(list(reversed(alerts[-100:])))
@app.route("/api/alerts/unread")
def api_alts_u():
    with alerts_lock:return jsonify({"count":sum(1 for a in alerts if not a.get("read"))})
@app.route("/api/alerts/read",methods=["POST"])
def api_alts_r():
    with alerts_lock:
        for a in alerts:a["read"]=True
    return jsonify({"ok":True})
@app.route("/api/history/<mac>")
def api_h(mac):
    with hist_lock:return jsonify(device_history.get(mac,[]))
@app.route("/api/history")
def api_ha():
    with hist_lock:
        return jsonify({m:{"name":known_devices.get(m,{}).get("name",m),"total":len(e),"connected":sum(1 for x in e if x.get("connected")),"first":e[0]["timestamp"],"last":e[-1]["timestamp"]}for m,e in device_history.items()if e})
@app.route("/api/known_devices")
def api_kd():
    with known_lock:return jsonify(known_devices)
@app.route("/api/known_devices/<mac>/trust",methods=["POST"])
def api_tr(mac):
    with known_lock:
        if mac in known_devices:known_devices[mac]["trusted"]=True;save_data();return jsonify({"ok":True})
    return jsonify({"error":"?"}),404
@app.route("/api/known_devices/<mac>/untrust",methods=["POST"])
def api_utr(mac):
    with known_lock:
        if mac in known_devices:known_devices[mac]["trusted"]=False;save_data();return jsonify({"ok":True})
    return jsonify({"error":"?"}),404
@app.route("/api/intruders")
def api_intr():
    h=fbx.get_lan_hosts();return jsonify([parse_dev(x)for x in(h or[])if x.get("active")and not known_devices.get(x.get("l2ident",{}).get("id",""),{}).get("trusted")])
@app.route("/api/scan/<mac>",methods=["POST"])
def api_sc(mac):
    for h in(fbx.get_lan_hosts()or[]):
        if h.get("l2ident",{}).get("id","")==mac:
            d=parse_dev(h)
            if d["ip"]:threading.Thread(target=scan_device,args=(d["ip"],mac),daemon=True).start();return jsonify({"status":"scanning"})
    return jsonify({"error":"?"}),404
@app.route("/api/scan/<mac>",methods=["GET"])
def api_scr(mac):
    with scan_lock:return jsonify(scan_results.get(mac,{"status":"no_scan"}))
@app.route("/api/scan/all",methods=["POST"])
def api_sca():
    h=fbx.get_lan_hosts();c=0
    for x in(h or[]):
        if x.get("active"):
            d=parse_dev(x)
            if d["ip"]and d["ip"]!="192.168.1.1":threading.Thread(target=scan_device,args=(d["ip"],d["mac"]),daemon=True).start();c+=1;time.sleep(.5)
    return jsonify({"status":"scanning","devices":c})
@app.route("/api/scan/results")
def api_scra():
    with scan_lock:return jsonify(scan_results)
@app.route("/api/speedtest",methods=["POST"])
def api_sp():return jsonify(run_speedtest())

# ─── AGRÉGATEUR DNS ───
@app.route("/api/dns/aggregated")
def api_da():
    with dns_agg_lock:
        r={}
        for dk,doms in dns_agg.items():
            with known_lock:dn=known_devices.get(dk,{}).get("name")
            if not dn:
                with ipm_lock:dn=ip_to_name.get(dk,dk)
            sd=sorted(doms.items(),key=lambda x:x[1].get("count",0),reverse=True)
            r[dk]={"device_name":dn,"total_queries":sum(d[1].get("count",0)for d in sd),"unique_domains":len(sd),
                "domains":[{"domain":d,"count":s.get("count",0),"first_seen":s.get("first",0),"last_seen":s.get("last",0)}for d,s in sd[:100]]}
        return jsonify(dict(sorted(r.items(),key=lambda x:x[1]["total_queries"],reverse=True)))

@app.route("/api/dns/aggregated/global")
def api_dag():
    with dns_agg_lock:
        gl=defaultdict(lambda:{"count":0,"devices":set(),"last":0})
        for dk,doms in dns_agg.items():
            with known_lock:dn=known_devices.get(dk,{}).get("name")
            if not dn:
                with ipm_lock:dn=ip_to_name.get(dk,dk)
            for dom,st in doms.items():
                gl[dom]["count"]+=st.get("count",0);gl[dom]["devices"].add(dn or dk);gl[dom]["last"]=max(gl[dom]["last"],st.get("last",0))
        return jsonify([{"domain":d,"count":s["count"],"devices":list(s["devices"]),"device_count":len(s["devices"]),"last_seen":s["last"]}for d,s in sorted(gl.items(),key=lambda x:x[1]["count"],reverse=True)[:200]])

@app.route("/api/dns/aggregated/<dk>")
def api_dad(dk):
    with dns_agg_lock:
        doms=dns_agg.get(dk,{})
        return jsonify([{"domain":d,"count":s.get("count",0),"first_seen":s.get("first",0),"last_seen":s.get("last",0)}for d,s in sorted(doms.items(),key=lambda x:x[1].get("count",0),reverse=True)])

# ─── EXPORTS ───
@app.route("/api/export/devices/csv")
def exp_d():
    h=fbx.get_lan_hosts();devs=[parse_dev(x)for x in h]if h else[]
    o=io.StringIO();w=csv.DictWriter(o,fieldnames=["name","mac","ip","type","vendor","connected","trusted","last_seen"]);w.writeheader()
    for d in devs:w.writerow({k:(datetime.fromtimestamp(d[k]).isoformat()if k=="last_seen"and d[k]else d[k])for k in w.fieldnames})
    o.seek(0);return Response(o.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=netguard_devices_{datetime.now():%Y%m%d_%H%M}.csv"})

@app.route("/api/export/alerts/csv")
def exp_a():
    o=io.StringIO();w=csv.DictWriter(o,fieldnames=["timestamp","level","title","message","device_mac"]);w.writeheader()
    with alerts_lock:
        for a in alerts:w.writerow({"timestamp":datetime.fromtimestamp(a["timestamp"]).isoformat(),"level":a["level"],"title":a["title"],"message":a["message"],"device_mac":a.get("device_mac","")})
    o.seek(0);return Response(o.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=netguard_alerts_{datetime.now():%Y%m%d_%H%M}.csv"})

@app.route("/api/export/scan/csv")
def exp_s():
    o=io.StringIO();w=csv.writer(o);w.writerow(["MAC","IP","Port","Service","Risk","Time"])
    with scan_lock:
        for m,r in scan_results.items():
            for p in r.get("ports",[]):w.writerow([m,r["ip"],p["port"],p["service"],r["risk_level"],datetime.fromtimestamp(r["timestamp"]).isoformat()])
    o.seek(0);return Response(o.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=netguard_scan_{datetime.now():%Y%m%d_%H%M}.csv"})

@app.route("/api/export/dns/csv")
def exp_dns():
    o=io.StringIO();w=csv.writer(o);w.writerow(["Appareil","Domaine","Requêtes","Première visite","Dernière visite"])
    with dns_agg_lock:
        for dk,doms in dns_agg.items():
            dn=known_devices.get(dk,{}).get("name",ip_to_name.get(dk,dk))
            for dom,st in sorted(doms.items(),key=lambda x:x[1].get("count",0),reverse=True):
                w.writerow([dn,dom,st.get("count",0),datetime.fromtimestamp(st["first"]).isoformat()if st.get("first")else"",datetime.fromtimestamp(st["last"]).isoformat()if st.get("last")else""])
    o.seek(0);return Response(o.getvalue(),mimetype="text/csv",headers={"Content-Disposition":f"attachment; filename=netguard_dns_{datetime.now():%Y%m%d_%H%M}.csv"})

def main():
    global fbx
    print("""
    ╔══════════════════════════════════════════════╗
    ║   🔒  NetGuard v2.1                          ║
    ║   Logs 48h · Agrégateur DNS · Auto-start     ║
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
    except KeyboardInterrupt:save_data();log.info("👋 Arrêté.")

if __name__=="__main__":main()
