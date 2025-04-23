# from PacketCapture import PacketCapture
# from Building_the_Alert_System import AlertSystem
# from Building_the_Detection_Engine import DetectionEngine
# from Traffic_Analysis_Module import TrafficAnalyzer
# import queue
# from scapy.all import TCP,IP
# class IntrusionDetectionSystem:
#     def __init__(self, interface="eth0"):
#         self.packet_capture = PacketCapture()
#         self.traffic_analyzer = TrafficAnalyzer()
#         self.detection_engine = DetectionEngine()
#         self.alert_system = AlertSystem()

#         self.interface = interface

#     def start(self):
#         print(f"Starting IDS on interface {self.interface}")
#         self.packet_capture.start_capture(self.interface)

#         while True:
#             try:
#                 packet = self.packet_capture.packet_queue.get(timeout=1)
#                 features = self.traffic_analyzer.analyze_packet(packet)

#                 if features:
#                     threats = self.detection_engine.detect_threats(features)

#                     for threat in threats:
#                         packet_info = {
#                             'source_ip': packet[IP].src,
#                             'destination_ip': packet[IP].dst,
#                             'source_port': packet[TCP].sport,
#                             'destination_port': packet[TCP].dport
#                         }
#                         self.alert_system.generate_alert(threat, packet_info)

#             except queue.Empty:
#                 continue
#             except KeyboardInterrupt:
#                 print("Stopping IDS...")
#                 self.packet_capture.stop()
#                 break

# if __name__ == "__main__":
#     ids = IntrusionDetectionSystem()
#     ids.start()

# from PacketCapture import PacketCapture
# from Building_the_Alert_System import AlertSystem
# from Building_the_Detection_Engine import DetectionEngine
# from Traffic_Analysis_Module import TrafficAnalyzer
# import queue
# from scapy.all import TCP, IP
# import numpy as np

# class IntrusionDetectionSystem:
#     def __init__(self, interface="en0"):
#         self.packet_capture = PacketCapture()
#         self.traffic_analyzer = TrafficAnalyzer()
#         self.detection_engine = DetectionEngine()
#         self.alert_system = AlertSystem()
#         self.interface = interface

#         # ✅ Train the Anomaly Detector with realistic normal traffic data
#         normal_traffic = np.array([
#             [600, 10, 100],  # Normal web request
#             [650, 15, 120],  
#             [550, 12, 110],  
#             [580, 9, 95]
#         ] * 25)  # Multiplying to create a larger dataset

#         self.detection_engine.train_anomaly_detector(normal_traffic)
#         print("✅ Anomaly detector trained with normal traffic data.")

#     def start(self):
#         print(f"🚀 Starting IDS on interface {self.interface}")
#         self.packet_capture.start_capture(self.interface)

#         while True:
#             try:
#                 packet = self.packet_capture.packet_queue.get(timeout=1)
#                 features = self.traffic_analyzer.analyze_packet(packet)

#                 if features:
#                     threats = self.detection_engine.detect_threats(features)

#                     if threats:  # ✅ Only alert if a threat is detected
#                         packet_info = {
#                             'source_ip': packet[IP].src,
#                             'destination_ip': packet[IP].dst,
#                             'source_port': packet[TCP].sport,
#                             'destination_port': packet[TCP].dport
#                         }
#                         for threat in threats:
#                             self.alert_system.generate_alert(threat, packet_info)
#                         print(f"🔥 Threat detected: {threats}")
#                     else:
#                         print("✅ No threats detected for this packet.")

#             except queue.Empty:
#                 continue
#             except KeyboardInterrupt:
#                 print("🛑 Stopping IDS...")
#                 self.packet_capture.stop()
#                 break

# if __name__ == "__main__":
#     ids = IntrusionDetectionSystem()
#     ids.start()

from flask import Flask, jsonify, render_template
from PacketCapture import PacketCapture
from Building_the_Alert_System import AlertSystem
from Building_the_Detection_Engine import DetectionEngine
from Traffic_Analysis_Module import TrafficAnalyzer
import threading
import queue
from scapy.all import TCP, IP
import numpy as np

app = Flask(__name__)

threats = []  # ✅ Global threat list (Thread-safe handling required)
lock = threading.Lock()  # ✅ Thread lock to prevent race conditions

class IntrusionDetectionSystem:
    def __init__(self, interface="en0"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.interface = interface

        # ✅ Train Anomaly Detector
        normal_traffic = np.array([
            [600, 10, 100], [650, 15, 120], [550, 12, 110], [580, 9, 95]
        ] * 25)

        self.detection_engine.train_anomaly_detector(normal_traffic)
        print("✅ Anomaly detector trained with normal traffic data.")

    def start(self):
        print(f"🚀 Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    detected_threats = self.detection_engine.detect_threats(features)

                    if detected_threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }

                        for threat in detected_threats:
                            alert = self.alert_system.generate_alert(threat, packet_info)
                            print(f"🔥 Threat detected: {threat}")

                            with lock:  # ✅ Prevent multiple threads modifying `threats` at once
                                threats.append({
                                    "threat": threat,
                                    **packet_info
                                })
                    else:
                        print("✅ No threats detected.")

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("🛑 Stopping IDS...")
                self.packet_capture.stop()
                break

@app.route('/')
def index():
    return render_template("index.html")  # ✅ Serves the frontend UI

@app.route('/get-threats')
def get_threats():
    with lock:  # ✅ Ensures thread safety
        return jsonify(threats)

def run_ids():
    ids = IntrusionDetectionSystem()
    ids.start()

if __name__ == "__main__":
    threading.Thread(target=run_ids, daemon=True).start()  # ✅ Runs IDS in a separate thread
    app.run(debug=True)
