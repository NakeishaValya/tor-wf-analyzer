import os
import sys
import re
import logging
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import pyshark
    import pandas as pd
except ImportError as e:
    print(f"Error: Required library not installed. {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

LOCAL_IP = "192.168.40.117" 
LOCAL_SUBNET = "192.168.40.0/24"

class PcapngFeatureExtractor:
    
    def __init__(self, pcapng_directory: str, output_csv: str = "features.csv", local_ip: str = None, local_subnet: str = None):
        self.pcapng_dir = Path(pcapng_directory)
        self.output_csv = Path(output_csv)
        self.features_data = []
        self.local_ip = local_ip or LOCAL_IP
        self.local_subnet = local_subnet or LOCAL_SUBNET
        
        if self.local_ip: logger.info(f"Using LOCAL_IP: {self.local_ip}")
        if self.local_subnet: logger.info(f"Using LOCAL_SUBNET: {self.local_subnet}")
        if not self.pcapng_dir.exists() or not self.pcapng_dir.is_dir():
            raise ValueError(f"Invalid directory path: {pcapng_directory}")
    
    def get_class_label(self, filename: str) -> str:
        name = filename.replace('.pcapng', '').replace('.pcap', '')
        label = re.sub(r'\d+$', '', name)
        return re.sub(r'^\d+_', '', label)
    
    def extract_features_from_file(self, pcapng_path: str) -> Tuple[int, int, int]:
        incoming_bytes, outgoing_bytes, packet_count = 0, 0, 0
        try:
            logger.info(f"Reading: {pcapng_path}")
            cap = pyshark.FileCapture(
                pcapng_path,
                keep_packets=False,
                use_json=True,
                tshark_path=r"C:\Program Files\Wireshark\tshark.exe"
            )
            
            for packet in cap:
                try:
                    if not (hasattr(packet, 'ip') or hasattr(packet, 'ipv6')):
                        continue
                    
                    packet_count += 1
                    packet_size = int(packet.length)
                    
                    if self._is_incoming_packet(packet):
                        incoming_bytes += packet_size
                    else:
                        outgoing_bytes += packet_size
                except AttributeError:
                    continue
                except Exception:
                    continue
            
            cap.close()
            logger.info(f"Extracted: incoming={incoming_bytes}B, outgoing={outgoing_bytes}B, packets={packet_count}")
        except Exception as e:
            logger.error(f"Error reading file {pcapng_path}: {e}")
            raise
        return incoming_bytes, outgoing_bytes, packet_count
    
    def _is_incoming_packet(self, packet) -> bool:
        try:
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                current_file = ""
                if hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'file_name'):
                    current_file = packet.frame_info.file_name.lower()
                
                # penyesuaian ip lokal untuk membedakan sesi capture data lama dan data baru pada folder /pcapng_data
                if "itb" in current_file or "cnn" in current_file:
                    target_local_ip = "172.18.255.49" # IP Wi-Fi Baru
                else:
                    target_local_ip = "192.168.40.117" # IP Wi-Fi Lama
                
                if dst_ip == target_local_ip: return True
                if src_ip == target_local_ip: return False
            
            layer = packet.tcp if hasattr(packet, 'tcp') else (packet.udp if hasattr(packet, 'udp') else None)
            if layer:
                return int(layer.dstport) > 10000 or int(layer.srcport) < 1024
            return False
        except:
            return False
    
    def process_all_files(self) -> pd.DataFrame:
        pcapng_files = sorted(self.pcapng_dir.glob('*.pcapng')) + sorted(self.pcapng_dir.glob('*.pcap'))
        if not pcapng_files:
            logger.warning(f"No .pcapng/.pcap files found in {self.pcapng_dir}")
            return pd.DataFrame()
        
        logger.info(f"Found {len(pcapng_files)} files to process")
        for idx, file_path in enumerate(pcapng_files, 1):
            try:
                logger.info(f"[{idx}/{len(pcapng_files)}] Processing: {file_path.name}")
                incoming, outgoing, count = self.extract_features_from_file(str(file_path))
                
                # ─── PERHITUNGAN FITUR KONTRIBUSI RANCANGAN MAKALAH ───
                total_bytes = incoming + outgoing
                incoming_ratio = incoming / total_bytes if total_bytes > 0 else 0.0
                avg_packet_size = total_bytes / count if count > 0 else 0.0
                
                self.features_data.append({
                    'filename': file_path.name,
                    'class_label': self.get_class_label(file_path.name),
                    'total_incoming_bytes': incoming,
                    'total_outgoing_bytes': outgoing,
                    'total_packets': count,
                    'incoming_ratio': incoming_ratio,  # Fitur Baru Kontribusi 1
                    'avg_packet_size': avg_packet_size  # Fitur Baru Kontribusi 2
                })
                logger.info(f"✓ Completed: {file_path.name}")
            except Exception as e:
                logger.error(f"✗ Failed to process {file_path.name}: {e}")
                continue
        return pd.DataFrame(self.features_data)
    
    def save_to_csv(self, df: pd.DataFrame) -> None:
        if df.empty: return
        try:
            df.to_csv(self.output_csv, index=False)
            logger.info(f"✓ Features saved to: {self.output_csv} ({len(df)} rows)")
        except Exception as e:
            logger.error(f"Error saving CSV: {e}")
            raise
    
    def print_summary(self, df: pd.DataFrame) -> None:
        if df.empty: return
        print("\n" + "="*80 + "\nFEATURE EXTRACTION SUMMARY\n" + "="*80)
        print(f"Total files: {len(df)} | Classes: {df['class_label'].nunique()}")
        print("\nClass distribution:\n", df['class_label'].value_counts())
        print(f"\n{'Feature':<25} {'Min':<12} {'Max':<12} {'Mean':<12}")
        print("-"*65)
        for col in ['total_incoming_bytes', 'total_outgoing_bytes', 'total_packets', 'incoming_ratio', 'avg_packet_size']:
            print(f"{col:<25} {df[col].min():<12.4f} {df[col].max():<12.4f} {df[col].mean():<12.4f}")
        print("\n" + "="*80)


def main():
    PCAPNG_DIRECTORY = "./pcapng_data"
    OUTPUT_CSV = "./features.csv"
    LOCAL_IP_ENV = "192.168.40.117"
    
    if len(sys.argv) > 1: PCAPNG_DIRECTORY = sys.argv[1]
    if len(sys.argv) > 2: OUTPUT_CSV = sys.argv[2]
    if len(sys.argv) > 3: LOCAL_IP_ENV = sys.argv[3]
    
    try:
        extractor = PcapngFeatureExtractor(PCAPNG_DIRECTORY, OUTPUT_CSV, local_ip=LOCAL_IP_ENV)
        df = extractor.process_all_files()
        if not df.empty:
            extractor.save_to_csv(df)
            extractor.print_summary(df)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()