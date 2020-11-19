import pyshark
import traceback
import pandas as pd
import matplotlib.pyplot as plt
import time
import numpy as np
from io import BytesIO

import sys
sys.setrecursionlimit(5000)

title = "RTCP jitter Checker "
ver = 'v1.3'
#jungil.kwon@sk.com
# v1.1 : criteria 절대값 적용
# v1.2 : SDP Connection Information 의 IP 정보가 영상/음성 다른 경우 처리할 수 있도록 개선
#         RTP filter 의 IP 조건을 64bit mask 처리  (상대 단말 음성/영상 ip 다른 경우 대응)
# v1.3 : Early-media 와 Regular-media 의 ip, port, media_type 정보들이 같을 때 중복해서 RTP를 읽어오는 문제 수정
#          checkDuplicate 함수 추가가
criteria_audio = 5
criteria_video = 20

def getSrcIp(p):
    ip = p[1]
    return ip.src

def getDstIp(p):
    ip = p[1]
    return ip.dst

def getSrcPort(p):
    transport = p[2]
    return int(transport.srcport)

def getDstPort(p):
    transport = p[2]
    return int(transport.dstport)

class Packet:
    def __init__(self, packet):
        self.packet = packet
        self.srcip = getSrcIp(packet)
        self.srcPort = getSrcPort(packet)
        self.dstip = getDstIp(packet)
        self.dstport = getDstPort(packet)
        self.frameNo = int(packet.frame_info.number)

class Sip(Packet):
    def __init__(self, packet):
        super(Sip, self).__init__(packet)

        self.sip = packet.sip
        self.call_id = packet.sip.call_id

        try :
            # invite, 183, 200 등
            self.method = self.sip.Method
        except :
            self.method = self.sip.status_code

        self.cseq = self.sip.cseq
        try :
            self.user_agent = self.sip.user_agent
        except :
            self.user_agent = ''

    def isUeSend(self):
        try :
            if '3GPP' in self.sip.p_access_network_info:
                return True
        except AttributeError as e:
            return False
        return False

    def printSip(self):
        frame = self.packet.frame_info
        print(frame.number, frame.protocols, self.method, "(" + self.cseq + ")")
        print(self.srcip + ' -> ' + self.dstip)
        print("call-id : " + self.call_id)
        print("uer-agent : " + self.user_agent)

class Media:
    def __init__(self, a):
        l = a.split("rtpmap:")[1].split(' ')
        self.payload = int(l[0])
        l = l[1].split('/')
        self.codecName = l[0]
        self.sampleRate = int(l[1])
    def getMediaStr(self):
        return "{}/{}/{}".format(self.payload, self.codecName, self.sampleRate)

class SipSdp(Sip):
    def __init__(self, packet):
        super(SipSdp, self).__init__(packet)

        self.contact_host = self.sip.sdp_connection_info_address
        self.contact_hosts = []
        self.contact_port_audio = 0
        self.contact_port_video = 0
        self.media_attrs = []
        self.rtpmaps = []

        line = str(self.sip).split("\r\n")
        for l in line:
            if l.startswith("\tMedia Description, name and address (m): "):
                self.media_attrs.append(l)
                port = int(l.split(' ')[7])
                if 'audio' in l:
                    self.contact_port_audio = port
                    self.audio_payload = l.split(' ')[9:]
                elif 'video' in l:
                    self.contact_port_video = port
                    self.video_payload = l.split(' ')[9:]
                else:
                    raise UnicodeError

            elif (l.startswith("\tMedia Attribute (a): rtpmap:")):
                self.rtpmaps.append(Media(l))

            elif l.startswith("\tConnection Information (c):"):
                self.contact_hosts.append(l.split(' ')[5])

    def getBitrate(self, ptype):
        for a in self.rtpmaps:
            if a.payload == ptype:
                return a.sampleRate
        return 0

    def ishost(self, addr, port):
        if self.contact_port_audio == port or self.contact_port_video == port:
            for host in self.contact_hosts:
                if host == addr:
                    return True

        return False

    def getRtpMap(self, type):
        list = []

        if(type == "audio"):
            pyload_list = self.audio_payload
        elif (type == "video"):
            pyload_list = self.video_payload

        for r in self.rtpmaps:
            # list.append("{}/{}/{} ".format(r.payload, r.codecName, r.sampleRate))
            if (not ("telephone-event" in r.codecName)) and (str(r.payload) in pyload_list):
                list.append(r.payload)
        return list

    # # payload 값을 받아 음성인지 영상인지 판단 하여 회신
    # def getMediaType(self, ptype):
    #     if str(ptype) in self.getRtpMap("audio"):
    #         return "audio"
    #     elif str(ptype) in self.getRtpMap("audio"):
    #         return "video"
    #     return "unknown"

    def getFirstRtpMap(self):
        return self.rtpmaps[0]

    def isContainPtype(self, ptype):
        for m in self.rtpmaps:
            if m.payload == ptype:
                return True
        return False

    def getRtpMedia(self, ptype):
        for m in self.rtpmaps:
            if m.payload == ptype:
                return m
        return None

    def getDirection(self):
        if self.isUeSend() == True:
            return "Tx"
        else :
            return "Rx"

    def printSdp(self):
        frame = self.packet.frame_info
        print(frame.number, frame.protocols,  self.method , "(" + self.cseq +")")
        print(self.srcip + ' -> ' + self.dstip)
        print("connection : {}({}), {}".format(self.contact_host, self.contact_port_audio, self.getDirection()))
        print("call-id : "  + self.call_id)
        print("uer-agent : "  + self.user_agent)
        for m in self.media_attrs:
            print(m)

class Rtp(Packet):
    def __init__(self, packet):
        super(Rtp, self).__init__(packet)

        self.rtp = packet.rtp
        self.ssrc =  self.rtp.ssrc
        self.p_type = int(self.rtp.p_type)
        self.seq = int(self.rtp.seq)
        self.time_epoch = packet.frame_info.time_epoch
        self.timestamp = self.rtp.timestamp
        try :
            self.setup_frame = self.rtp.setup_frame
        except :
            self.setup_frame = 0


class RtpSession:
    def __init__(self, rtp):
        self.ssrc = rtp.ssrc
        self.p_type = rtp.p_type

        self.ip_a =  rtp.srcip
        self.port_a = rtp.srcPort
        self.ip_b = rtp.dstip
        self.port_b = rtp.dstport

        self.start_time = rtp.packet.sniff_time
        self.end_time = rtp.packet.sniff_time

        try :
            self.setup_frame = int(rtp.setup_frame)
        except :
            self.setup_frame = 0
        # setup_frame : 이전에 나온 RTP frame number, media 변환 시점에 따라차이 발생 가능 하므로 주의 깊게 사용 필요
        # 200OK 이전 RTP 가 먼저 전달 된 경우 해당 RTP 는 기존 SDP frame number 로 인식하게 됨.

        self.rtpdata = pd.DataFrame(columns=["packetNum", "ssrc", "seq", "setupframe", "payload", "time_epoch", "timestamp"])

    def addRtp(self, rtp):
        self.rtpdata = self.rtpdata.append({"packetNum": rtp.frameNo ,"ssrc":rtp.ssrc ,"seq": int(rtp.seq),
                                            "setupframe":int(rtp.setup_frame) ,"payload":int(rtp.p_type) ,
                                            "time_epoch": float(rtp.time_epoch), "timestamp": float(rtp.timestamp)}, ignore_index=True)
        self.end_time = rtp.packet.sniff_time

    def getRtpData(self):
        return self.rtpdata

    # def setRtpData(self, df):
    #     self.rtpdata = df

    def printRtpSession(self, printHead = False):
        print(self.rtpdata.shape)
        print(self.ssrc, self.p_type)
        print("{} ~ {}".format(self.start_time, self.end_time))
        print("setup_frame : " + str(self.setup_frame))
        print(self.getFlow())
        if(printHead):
            print(self.rtpdata.head())

    def getFlow(self):
        return "{}({}) -> {}({})" .format(self.ip_a, self.port_a, self.ip_b, self.port_b)

class RtpList:
    def __init__(self):
        self.list = {}

    def checkAndAdd(self, rtp):
        if not self.list.__contains__(rtp.ssrc):
            new_session = RtpSession(rtp)
            self.list[rtp.ssrc] = new_session

        session = self.list[rtp.ssrc]
        session.addRtp(rtp)

    # def getList(self):
    #     return [self.list[i] for i in self.list]

    def getRtpList(self):
        # list = []
        # for s in self.list:
        #     list.append(s)
        # return list
        return self.list.keys()

    def getRtpSession(self, ssrc):
        return self.list[ssrc]

    def getRtpData(self, ssrc):
        return self.list[ssrc].getRtpData()

    # def setRtpData(self, df):
    #     self.list[ssrc].setRtpData(df)

    def printRtpList(self, printHead = True):
        print("**RtpList**")
        print(self.list)
        for s in self.list:
            print("************")
            print("[ssid] : " + s)
            p = self.list[s]
            p.printRtpSession(printHead)

class MediaConfig:
    def __init__(self, dir, ip, port, mtype, ptype):
        self.direction = dir
        self.ip = ip
        self.port = port
        self.media_type = mtype
        self.payload_ypte = ptype

    def isContainPayload(self, ptype):
        if ptype in self.payload_ypte:
            return True
        return False

    def printMediaConfig(self):
        print("{}, {}({}), {}, {}".format(self.direction, self.ip, self.port, self.media_type, self.payload_ypte))

class CallSession:
    def __init__(self):
        self.invite = None
        self.s183 = None
        self.s200 = None
        self.bye = None
        self.established = False
        self.earlymedia = False
        self.hangup = False
        self.startTime = None
        self.hangupTime = None

    def setInvite(self, sipsdp):
        self.invite = sipsdp
        self.startTime = sipsdp.packet.sniff_time
        self.ip_a = self.invite.contact_host
        self.port_a_audio = self.invite.contact_port_audio
        self.port_a_video = self.invite.contact_port_video

    def set183(self, sipsdp):
        self.s183 = sipsdp
        self.earlymedia = True
        self.ip_early = self.s183.contact_host
        self.port_early = self.s183.contact_port_audio

    def set200(self, sipsdp):
        if(self.established == True):
            return
        self.s200 = sipsdp
        self.established = True
        self.ip_b = self.s200.contact_host
        self.port_b_audio = self.s200.contact_port_audio
        self.port_b_video = self.s200.contact_port_video

    def setBye(self, sip):
        if (self.established == True) and (self.hangup == False ):
            self.bye = sip
            self.hangup = True
            self.hangupTime = sip.packet.sniff_time

    def getMedia(self, rtpSession):
        if self.s200.isContainPtype(rtpSession.p_type):
            if  (self.invite.ishost(rtpSession.ip_a, rtpSession.port_a) and self.s200.ishost(rtpSession.ip_b, rtpSession.port_b)) \
                    or (self.invite.ishost(rtpSession.ip_b, rtpSession.port_b) and self.s200.ishost(rtpSession.ip_a, rtpSession.port_a)):
                return  self.s200.getRtpMedia(rtpSession.p_type)

        elif self.earlymedia and self.s183.isContainPtype(rtpSession.p_type):
            if (self.invite.ishost(rtpSession.ip_a, rtpSession.port_a) and self.s183.ishost(rtpSession.ip_b, rtpSession.port_b)) \
                    or (self.invite.ishost(rtpSession.ip_b, rtpSession.port_b) and self.s183.ishost(rtpSession.ip_a, rtpSession.port_a)):
                return  self.s183.getRtpMedia(rtpSession.p_type)
        return None

    def getMediaConfig(self):
        list = []
        for cs in [self.invite , self.s183, self.s200]:
            if cs == None :
                continue
            list.append(MediaConfig(cs.getDirection() , cs.contact_host, cs.contact_port_audio, "audio", cs.getRtpMap("audio")))
            if(cs.contact_port_video != 0):
                list.append(MediaConfig(cs.getDirection(), cs.contact_host, cs.contact_port_video, "video", cs.getRtpMap("video")))
        return list

    def getMediaType(self, payload):
        list = self.getMediaConfig()
        for mc in list:
            if (mc.isContainPayload(payload) == True) :
                return mc.media_type
        return None

    def getByeTimeEpoch(self):
        return float(self.bye.packet.frame_info.time_epoch)

    def printSession(self):
        print("established : " + str(self.established) + ", hangpu : " + str(self.hangup))
        print(self.ip_a + "(" + str(self.port_a_audio) + ") -> " + self.ip_b + "(" + str(self.port_b_audio) + ") ")
        if self.port_b_video > 0 :
            print(self.ip_a + "(" + str(self.port_a_video) + ") -> " + self.ip_b + "(" + str(self.port_b_video)+ ") ")
        print(str(self.startTime) + " ~ " + str(self.hangupTime) + " (" + str(self.hangupTime - self.startTime) + ")")

        print("INVITE")
        self.invite.printSdp()
        if(self.earlymedia):
            print("183")
            self.s183.printSdp()
        print("200")
        self.s200.printSdp()
        print("BYE")
        self.bye.printSip()

        for l in self.getMediaConfig():
            # print("{}, {}({}), {}, {}".format(l.direction, l.ip, l.port, l.media_type, l.payload_ypte))
            l.printMediaConfig()


class CallList:
    def __init__(self):
        self.list = {}

    def checkAndAdd(self, packet):
        if(type(packet) ==SipSdp) :
            if packet.method == "INVITE":
                if not self.list.__contains__(packet.call_id):
                    new_session = CallSession()
                    new_session.setInvite(packet)
                    self.list[packet.call_id] = new_session
            elif packet.method == "183":
                if self.list.__contains__(packet.call_id):
                    session = self.list[packet.call_id]
                    session.set183(packet)
            elif packet.method == "200":
                if self.list.__contains__(packet.call_id):
                    session = self.list[packet.call_id]
                    session.set200(packet)
        elif(type(packet) == Sip) :
            if packet.method == "BYE":
                if self.list.__contains__(packet.call_id):
                    session = self.list[packet.call_id]
                    session.setBye(packet)

    # def getPeerIpAddr(self, ue_addr):
    #     for cs in self.list:
    #         self.list[cs]

    def getCallListValue(self):
        return self.list.values()

    # bitrate 반환
    # RTP session 에 해당하는 SIP session 찾아서 반환
    def getCallSession(self, rtpsession):
        for cs in self.list:
            media = self.list[cs].getMedia(rtpsession)
            if(media != None):
                return self.list[cs]
        return None

    def getCallSessionMedia(self, rtpsession):
        cs = self.getCallSession(rtpsession)
        if(cs == None):
            return None
        return cs.getMedia(rtpsession)

    def getMediaType(self, rtpsession):
        cs = self.getCallSession(rtpsession)
        if (cs == None):
            return None
        return cs.getMediaType(rtpsession.p_type)

    def printCallList(self):
        print("**CallList**")
        print(self.list)
        for s in self.list:
            print("************")
            print("[call-id] : " + s)
            p = self.list[s]
            p.printSession()

class Rtcp(Packet):
    def __init__(self, packet):
        super(Rtcp, self).__init__(packet)

        self.rtcp_type = int(packet.rtcp.pt)
        if(self.rtcp_type == 203): #Goodbye
            return
        self.ssrc = packet.rtcp.ssrc_identifier
        self.high_seq = int(packet.rtcp.ssrc_high_seq)
        self.lost = int(packet.rtcp.ssrc_cum_nr)
        self.jitter = int(packet.rtcp.ssrc_jitter)

class RtcpSession:
    def __init__(self, rtcp):
        self.ssrc = rtcp.ssrc
        self.rtcp_type = rtcp.rtcp_type

        self.ip_a = rtcp.srcip
        self.port_a = rtcp.srcPort
        self.ip_b = rtcp.dstip
        self.port_b = rtcp.dstport

        self.start_time = rtcp.packet.sniff_time
        self.end_time = rtcp.packet.sniff_time

        self.setup_frame = rtcp.packet.rtcp.setup_frame
        # # setup_frame : 이전에 나온 RTP frame number, media 변환 시점에따라 차이 발생 가능 하므로 주의 깊게 사용 필요
        # # 200OK 이전 RTP 가 먼저 전달 된 경우 해당 RTP 는 기존 SDP frame number 로 인식하게 됨.

        self.rtcpdata = pd.DataFrame(columns=["packetNum", "ssrc", "rtcp_type", "seq", "rtcp_lost", "rtcp_jitter(ts)"])

    def addRtcp(self, rtcp):
        self.rtcpdata = self.rtcpdata.append({"packetNum": rtcp.frameNo, "ssrc":rtcp.ssrc,
                                            "rtcp_type":rtcp.rtcp_type, "seq": int(rtcp.high_seq),
                                            "rtcp_lost": int(rtcp.lost), "rtcp_jitter(ts)": int(rtcp.jitter)},
                                           ignore_index=True)
        self.end_time = rtcp.packet.sniff_time

    def getRtcpData(self):
        return self.rtcpdata

    def printRtcpSession(self, printHead=False):
        print(self.rtcpdata.shape)
        print(self.ssrc, self.rtcp_type)
        print("{} ~ {}".format(self.start_time, self.end_time))
        print("setup_frame : " + self.setup_frame)
        print("{}({}) -> {}({})".format(self.ip_a, self.port_a, self.ip_b, self.port_b))
        if (printHead):
            print(self.rtcpdata.head())

class RtcpList:
    def __init__(self):
        self.list = {}

    def checkAndAdd(self, rtcp):
        if(rtcp.rtcp_type == 203): #goodbye
            return
        if not self.list.__contains__(rtcp.ssrc):
            new_session = RtcpSession(rtcp)
            self.list[rtcp.ssrc] = new_session

        session = self.list[rtcp.ssrc]
        session.addRtcp(rtcp)

    def getRtcpList(self):
        return self.list.keys()

    def getRtcpData(self, ssrc):
        return self.list[ssrc].getRtcpData()

    # def getList(self):
    #     return [self.list[i] for i in self.list]


    def printRtcpList(self, printHead = True):
        print("**RTCP List**")
        print(self.list)
        for s in self.list:
            print("************")
            print("[ssid] : " + s)
            p = self.list[s]
            p.printRtcpSession(printHead)


def StartRtpAnalysis(packet_file_name, label):
    # packet_file_name = self.packet_file_name[0]

    lb_status = label  # shared memory

    def printToStatus(str):
        lb_status.value = str.encode()

    ## SIP Load
    printToStatus("loading SIP session....")
    cap = pyshark.FileCapture(packet_file_name, display_filter='sip')

    sipList = []

    for p in cap:
        frame = p.frame_info

        try:
            if 'sdp' in frame.protocols:
                # print(frame.number, frame.protocols)
                sipList.append(SipSdp(p))

            elif 'sip' in frame.protocols:
                # print(frame.number, frame.protocols)
                sipList.append(Sip(p))

        except:
            traceback.print_exc()
            print("Except", frame.number, frame.protocols)
            pass

        cap.clear()

    callList = CallList()

    for s in sipList:
        # print("=====%===")
        # if type(s) == SipSdp:
        #     s.printSdp()
        callList.checkAndAdd(s)

    callList.printCallList()

    # UE 목록 생성
    ue_list = []
    peer_list = []

    def checkDuplicate(list, m):
        for l in list:
            if l.direction == m.direction:
                if l.ip == m.ip:
                    if l.media_type == m.media_type:
                        if l.payload_ypte == m.payload_ypte:
                            if l.port == m.port:
                                return True
        return False


    for cs in callList.getCallListValue():
        for m in cs.getMediaConfig():
            if m.direction == "Tx":
                # if not ue_list.__contains__(m):
                if not checkDuplicate(ue_list, m):
                    ue_list.append(m)
            elif m.direction == "Rx":
                # if not peer_list.__contains__(m):
                if not checkDuplicate(peer_list, m):
                    peer_list.append(m)

    print("[UE send addr]")
    for ue in ue_list:
        ue.printMediaConfig()

    print("[UE receive addr]")
    for peer in peer_list:
        peer.printMediaConfig()

    ## RTP Load
    print("Load RTP packet")
    printToStatus("loading RTP packets....")
    rtplist = RtpList()
    filter_list = []

    start_time = time.time()

    for idx, peer in enumerate(peer_list):
        if ':' in peer.ip:
            ip_filter = "ipv6"
        else:
            ip_filter = "ip"

        pt = " and "
        i = 0
        for rm in peer.payload_ypte:
            if i == 0:
                pt += "("
            if i > 0:
                pt += " or "
            i = i + 1
            pt += "rtp.p_type ==" + str(rm)
        pt += ")"

        filter = "rtp and " + ip_filter + ".src==" + peer.ip + "/64" + " and udp.srcport==" + str(peer.port) + pt
        print("Load RTP filter : ", filter)
        decodeas = {'udp.port==' + str(peer.port): 'rtp'}
        print("Load decode_as filter : ", decodeas)
        # filter_list.append(filter)

        rtp = pyshark.FileCapture(packet_file_name, decode_as=decodeas, display_filter=filter)

        for p in rtp:
            frame = p.frame_info

            try:
                if 'rtcp' in frame.protocols:
                    continue

                if 'rtp' in frame.protocols:
                    # print(frame.number, frame.protocols)

                    sys.stdout.write("\rframe.number : %i" % int(frame.number))
                    sys.stdout.flush()
                    printToStatus("loading RTP packets....({}/{}) frame.number : {}".format(idx+1, len(peer_list) , str(frame.number)))

                    rtplist.checkAndAdd(Rtp(p))
                    # if(int(frame.number) > 1000):
                    #     break

            except Exception as e:
                if not any(s in frame.protocols for s in ("icmp,", "icmpv6")):
                    traceback.print_exc()
                print(" Except:", frame.number, frame.protocols)
                pass
        print("\n")
        rtp.close()

    print("--- %s seconds ---" % (time.time() - start_time))
    rtplist.printRtpList()

    ## RTP jitter 분석
    # How jitter is calculated
    # Wireshark calculates jitter according to RFC3550 (RTP):
    #
    # If Si is the RTP timestamp from packet i, and Ri is the time of arrival in RTP timestamp units for packet i, then for two packets i and j, D may be expressed as
    #
    # D(i,j) = (Rj - Ri) - (Sj - Si) = (Rj - Sj) - (Ri - Si)
    # The interarrival jitter SHOULD be calculated continuously as each data packet i is received from source SSRC_n, using this difference D for that packet and the previous packet i-1 in order of arrival (not necessarily in sequence), according to the formula
    #
    # J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
    # RTP timestamp: RTP timestamp is based on the sampling frequency of the codec, 8000 in most audio codecs and 90000 in most video codecs. As the sampling frequency must be known to correctly calculate jitter it is problematic to do jitter calculations for dynamic payload types as the codec and it's sampling frequency must be known which implies that the setup information for the session must be in the trace and the codec used must be known to the program(with the current implementation).
    #
    # Developers with time to spend could change the current implementation to also record the sampling frequency in the SDP data and add that to the RTP conversation data and use that in the RTP analysis.
    # https://wiki.wireshark.org/RTP_statistics

    print("##########jitter 계산##########")
    printToStatus("analyzing jitter....")

    def getMedia(rtpsession):
        return callList.getCallSessionMedia(rtpsession)

    def getSamplingClock(rtpsession):
        media = getMedia(rtpsession)
        if media != None:
            return media.sampleRate
        print("Error : can not find media session!!")
        return 0

    def getMediaType(rtpsession):
        return callList.getMediaType(rtpsession)

    def getByeTime(rtpsession):
        return callList.getCallSession(rtpsession).getByeTimeEpoch()

    try:
        for rs in rtplist.list.values():
            df = rs.getRtpData()
            rs.printRtpSession()
            sample_rate = getSamplingClock(rs)
            print("Sample Rate : ", sample_rate)

            df["R_diff"] = df["time_epoch"] - df["time_epoch"].shift(1)
            df["S_diff"] = (df["timestamp"] * 1 / sample_rate) - (df["timestamp"].shift(1) * 1 / sample_rate)
            df["D"] = df["R_diff"] - df["S_diff"]
            jitter = [0]
            lost = [0]

            for j in range(1, df.shape[0]):
                jitter.append(jitter[j - 1] + (abs(df.loc[j, "D"]) - jitter[j - 1]) / 16)
                lost.append(lost[j - 1] + (df.loc[j, "seq"] - df.loc[j - 1, "seq"]) - 1)

            df["Jitter(ms)"] = jitter
            df["Jitter(ms)"] = df["Jitter(ms)"] * 1000
            df["Jitter(ts)"] = df["Jitter(ms)"] * sample_rate / 1000

            df["lost"] = lost

            pd.set_option('display.expand_frame_repr', False)  # 컬럼 전체 출력
            print(df.head(20))
            print("Max Jitter {} ms".format(df["Jitter(ms)"].max()))
            print("Mean Jitter {} ms".format(df["Jitter(ms)"].mean()))

            # rs.setRtpData(df)

            print("###############")

    except Exception as e:
        traceback.print_exc()
        pass

    print("#########RTCP 로드##########")
    printToStatus("loading RTCP packets....")
    rtcplist = RtcpList()

    for idx, ssrc in enumerate(rtplist.getRtpList()):

        # filter = "rtcp and "+ ip_filter +".src==" + ue.ip + " and udp.srcport==" + str(peer.port+1)
        filter = "rtcp.ssrc.identifier ==" + ssrc
        print("Load RCTP filter : ", filter)

        rtcp = pyshark.FileCapture(packet_file_name, display_filter=filter)

        for p in rtcp:
            frame = p.frame_info

            try:
                if 'rtcp' in frame.protocols:
                    # print(frame.number, frame.protocols)

                    sys.stdout.write("\rframe.number : %i" % int(frame.number))
                    sys.stdout.flush()
                    printToStatus("loading RTCP packets....({}/{}) frame.number : {}".format(idx + 1, len(rtplist.getRtpList()),
                                                                                            str(frame.number)))

                    rtcplist.checkAndAdd(Rtcp(p))

            except Exception as e:
                traceback.print_exc()
                pass

        rtcp.clear()
        print("\n")

    def getSamplingClock_by_ssrc(ssrc):
        try:
            rtpsession = rtplist.getRtpSession(ssrc)
            return getSamplingClock(rtpsession)
        except Exception as e:
            return 1

    def getMedia_by_ssrc(ssrc):
        try:
            rtpsession = rtplist.getRtpSession(ssrc)
            return getMedia(rtpsession)
        except Exception as e:
            return 1

    def getIQRStr(df, column):
        q1 = round(df[column].quantile(0.25), 2)
        q3 = round(df[column].quantile(0.75), 2)
        iqr = round(q3 - q1, 2)
        return "Q1={}, Q3={}, IQR={}".format(q1, q3, iqr)

    # IQR 기반 이상치 제거
    def removeOutliersByIQR(df, column):
        q1 = round(df[column].quantile(0.25), 2)
        q3 = round(df[column].quantile(0.75), 2)
        iqr = round(q3 - q1, 2)

        lb = q1 - (iqr * 1.5)
        ub = q3 + (iqr * 1.5)

        outlier = (df[column] > lb) & (df[column] < ub)
        return df[outlier]

    # RTCP jitter 값 변환
    for ssrc in rtcplist.getRtcpList():
        df = rtcplist.getRtcpData(ssrc)
        df["rtcp_jitter(ms)"] = df["rtcp_jitter(ts)"] / getSamplingClock_by_ssrc(ssrc) * 1000

    rtcplist.printRtcpList()

    # 파일 저장
    writer = pd.ExcelWriter(packet_file_name + '_RTCP jitter 분석.xlsx', engine='xlsxwriter')

    # 테이블 합치기`
    result_list = {}

    for idx, ssrc in enumerate(rtplist.getRtpList()):
        rs = rtplist.getRtpSession(ssrc)

        df1 = rtplist.getRtpData(ssrc)
        try:
            df2 = rtcplist.getRtcpData(ssrc)
            print("ssrc : {}, RTCP does not exist".format(ssrc))
        except KeyError:
            continue

        dm = pd.merge(df1, df2, how='left', on=["ssrc", "seq"])

        # Bye 이후 제거
        dm = dm[dm["time_epoch"] < getByeTime(rs)]

        result_list[ssrc] = dm
        dm["jitter_diff"] = dm["rtcp_jitter(ms)"] - dm["Jitter(ms)"]

        dm_ro = removeOutliersByIQR(dm, "jitter_diff")

        print("-----------")
        print(ssrc, df1.shape, df2.shape, dm.shape)
        rs.printRtpSession()
        print(dm[dm["rtcp_jitter(ms)"].notnull()])
        print("Max Jitter diff {} ms".format(dm["jitter_diff"].max()))
        print("Min Jitter diff {} ms".format(dm["jitter_diff"].min()))
        print("Mean Jitter diff {} ms".format(dm["jitter_diff"].mean()))
        print(getIQRStr(dm, "jitter_diff"))
        print("===========")

        dm.to_excel(writer, sheet_name=ssrc)

        # 시각화
        printToStatus("Check the result.. ({}/{}), ssrc={}".format(idx+1, len(rtplist.getRtpList()), ssrc))
        # Get the xlsxwriter objects from the dataframe writer object.
        workbook = writer.book
        worksheet = writer.sheets[ssrc]
        imgdata = BytesIO()

        fig = plt.figure(1, figsize=(7, 7), dpi=80, facecolor='w', edgecolor='k')
        plt.subplot(211)
        plt.plot(dm["seq"], dm["Jitter(ms)"], "k-", dm["seq"], dm["rtcp_jitter(ms)"], "rs", dm["seq"],
                 dm["jitter_diff"], "go", dm["seq"], dm["rtcp_lost"], 'rx')
        plt.legend(['RTP jitter(ms)', 'RTCP jitter(ms)', "jitter diff(ms)", "RTCP lost"])
        plt.title("ssrc : {}, <{}> {}\n{}".format(ssrc, getMediaType(rs), getMedia_by_ssrc(ssrc).getMediaStr(),
                                                  rs.getFlow()))
        plt.subplot(212)

        criteria = 0
        if(getMediaType(rs) == 'audio'):
            criteria = criteria_audio
        elif(getMediaType(rs) == 'video'):
            criteria = criteria_video

        result = 'Fail'
        if(dm_ro.shape[0] == 0):
            diff_mean_value = dm["jitter_diff"].mean()
        else:
            diff_mean_value = dm_ro["jitter_diff"].mean()

        if(abs(diff_mean_value) <= criteria):
            result = "Pass"


        if (dm.loc[dm["jitter_diff"].notnull(), "jitter_diff"].shape[0] > 0):
            plt.boxplot(dm.loc[dm["jitter_diff"].notnull(), "jitter_diff"].tolist())
            plt.title("jitter diff")
            plt.xlabel(
                "Jitter diff Max {0:.2f} ms, Min {1:.2f} ms, Mean {2:.2f} ms\n".format(dm["jitter_diff"].max(),
                                                                                       dm["jitter_diff"].min(),
                                                                                       dm["jitter_diff"].mean())
                + getIQRStr(dm, "jitter_diff")
                + "\nJitter diff(w/o outlier) Max {0:.2f} ms, Min {1:.2f} ms, Mean {2:.2f} ms\nResult:".format(
                    dm_ro["jitter_diff"].max(), dm_ro["jitter_diff"].min(), dm_ro["jitter_diff"].mean())
                + result + " (criteria : audio:±{}ms, video:±{}ms)\n".format(criteria_audio, criteria_video)
                + "\n<" + title + ver + ">"
            )

        dm_ro
        # plt.gcf().subplots_adjust(bottom=0.20)
        plt.tight_layout()
        plt.show()

        fig.savefig(imgdata, format="png", bbox_inches='tight')
        imgdata.seek(0)
        worksheet.insert_image('U2', "", {'image_data': imgdata})

    writer.save()
    print("===== End =====")
    printToStatus("Complete!!")


from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QFileDialog
from PyQt5.QtWidgets import QPushButton
from PyQt5.QtWidgets import QLabel
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QBoxLayout
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QThread
from PyQt5.QtCore import QMutex
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtCore import QWaitCondition

from multiprocessing import Process, sharedctypes

from ctypes import *

import traceback
import sys
import time

class Thread(QThread):

    # 사용자 정의 시그널 선언
    change_value = pyqtSignal(int)


    def __init__(self):
        QThread.__init__(self)
        self.cond = QWaitCondition()
        self.mutex = QMutex()
        self.cnt = 0
        self._status = True

    def __del__(self):
        self.wait()

    def run(self):
        while True:
            self.mutex.lock()

            if not self._status:
                self.cond.wait(self.mutex)

            if 100 == self.cnt:
                self.cnt = 0
            self.cnt += 1
            self.change_value.emit(self.cnt)
            # print("thread :" , self.cnt)
            self.msleep(100)  # ※주의 QThread에서 제공하는 sleep을 사용

            self.mutex.unlock()

    def toggle_status(self):
        self._status = not self._status
        if self._status:
            self.cond.wakeAll()

    @property
    def status(self):
        return self._status


class Form(QWidget):
    def __init__(self):
        QWidget.__init__(self, flags=Qt.Widget)
        self.setWindowTitle("[SD QI] " + title + ver)
        box = QBoxLayout(QBoxLayout.TopToBottom)
        self.lb = QLabel()
        self.status = QLabel()
        self. num =sharedctypes.Array('c', b'                                                      ')
        # self.sh_status =  sharedctypes.RawValue(py_object, self.status)

        print(type( self.status))
        self.pb = QPushButton("Select Packet File")
        self.pg = QPushButton("Analyze")
        box.addWidget(self.pb)
        box.addWidget(self.lb)
        box.addWidget(self.pg)
        box.addWidget(self.status)

        self.th = Thread()
        self.th.start()

        self.setLayout(box)
        self.pb.clicked.connect(self.get_file_name)
        self.pg.clicked.connect(self.selfexecute_analysis)
        self.th.change_value.connect(self.printToStatus)


    def get_file_name(self):
        filter = 'Packet (*.pcap;*.pcapng)'
        self.packet_file_name = QFileDialog.getOpenFileName(caption="Packet", filter=filter)
        self.lb.setText(self.packet_file_name[0])
        # print("#### Filename :", self.packet_file_name[0])
        # self.status.setText("")
        self.num.value = b''

    def selfexecute_analysis(self):
        self.num.value = b''
        self.pg.setDisabled(True)

        try:
            print("#### Filename :", self.packet_file_name)

            print(type(self.status))

            proc = Process(target=StartRtpAnalysis, args=(self.packet_file_name[0], self.num,))
            proc.start()

        except Exception as e:
            traceback.print_exc()

    def printToStatus(self):
        value = (self.num.value).decode("utf-8")
        # print("statusUpdate " + )
        self.status.setText(value)
        # print("printToStatus")
        if("Complete" in value):
            self.pg.setDisabled(False)


def StartRtpAnalysis_GUI():
    app = QApplication(sys.argv)
    form = Form()
    form.show()
    sys.exit(app.exec_())

## Start
if __name__ == "__main__":
    StartRtpAnalysis_GUI()
