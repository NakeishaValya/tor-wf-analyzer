"""
Website Fingerprinting Feature Extraction Script

This script extracts network traffic features from .pcapng files for machine learning-based
website fingerprinting tasks. Features include total incoming bytes, outgoing bytes, and packet counts.

Requirements:
    - pyshark: pip install pyshark
    - pandas: pip install pandas
    - tshark: Install Wireshark (includes tshark)
"""

import os
import sys
import csv
from pathlib import Path
from typing import Dict, List, Tuple
import logging

try:
    import pyshark
    import pandas as pd
except ImportError as e:
    print(f"Error: Required library not installed. {e}")
    print("Please install required packages: pip install pyshark pandas")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =====================================================================
# KONFIGURASI IP LOKAL - SESUAIKAN DENGAN LAPTOP ANDA
# =====================================================================
# Contoh: LOCAL_IP = "192.168.1.100"
# Untuk menemukan IP lokal laptop Anda:
#   Windows: ipconfig (cari IPv4 Address)
#   Linux/Mac: ifconfig atau hostname -I
# Set ke None untuk menggunakan heuristik berbasis port (default)
LOCAL_IP = "192.168.40.117"  # "192.168.1.100"  # GANTI DENGAN IP LAPTOP ANDA

# Subnet lokal untuk deteksi paket (opsional)
# Format: "192.168.1.0/24" atau None untuk auto-detect
LOCAL_SUBNET = "192.168.40.0/24"  # "192.168.1.0/24"


class PcapngFeatureExtractor:
    """Extract network features from pcapng files for website fingerprinting."""
    
    def __init__(self, pcapng_directory: str, output_csv: str = "features.csv", 
                 local_ip: str = None, local_subnet: str = None):
        """
        Initialize the feature extractor.
        
        Args:
            pcapng_directory: Path to directory containing .pcapng files
            output_csv: Path to output CSV file
            local_ip: Local machine IP address (e.g., "192.168.1.100")
                     If None, uses port-based heuristic for direction detection
            local_subnet: Local subnet in CIDR format (e.g., "192.168.1.0/24")
        """
        self.pcapng_dir = Path(pcapng_directory)
        self.output_csv = Path(output_csv)
        self.features_data = []
        self.local_ip = local_ip or LOCAL_IP
        self.local_subnet = local_subnet or LOCAL_SUBNET
        
        if self.local_ip:
            logger.info(f"Using LOCAL_IP: {self.local_ip}")
        if self.local_subnet:
            logger.info(f"Using LOCAL_SUBNET: {self.local_subnet}")
        
        # Validate directory
        if not self.pcapng_dir.exists():
            raise ValueError(f"Directory does not exist: {pcapng_directory}")
        if not self.pcapng_dir.is_dir():
            raise ValueError(f"Path is not a directory: {pcapng_directory}")
    
    def get_class_label(self, filename: str) -> str:
        """
        Map filename to website class label.
        
        This function can be customized based on your naming convention.
        Default: removes extension and uses the filename as class label.
        
        Examples:
            "wikipedia1.pcapng" -> "wikipedia"
            "amazone10.pcapng" -> "amazone"
            "github5.pcapng" -> "github"
        
        Args:
            filename: Name of the pcapng file
            
        Returns:
            Class label string
        """
        # Remove .pcapng extension
        name = filename.replace('.pcapng', '').replace('.pcap', '')
        
        # Extract base domain/website name (remove trailing numbers)
        # Adjust regex pattern based on your naming convention
        import re
        # Remove trailing numbers (format: websiteName123)
        label = re.sub(r'\d+$', '', name)
        # Remove numeric prefixes if present
        label = re.sub(r'^\d+_', '', label)
        
        return label
    
    def extract_features_from_file(self, pcapng_path: str) -> Tuple[int, int, int]:
        """
        Extract features from a single pcapng file.
        
        Args:
            pcapng_path: Path to pcapng file
            
        Returns:
            Tuple of (total_incoming_bytes, total_outgoing_bytes, total_packet_count)
        """
        incoming_bytes = 0
        outgoing_bytes = 0
        packet_count = 0
        
        try:
            logger.info(f"Reading: {pcapng_path}")
            
            # Read the pcap file
            cap = pyshark.FileCapture(
                pcapng_path,
                keep_packets=False,
                use_json=True,
                tshark_path=r"C:\Program Files\Wireshark\tshark.exe"
            )
            
            # Iterate through packets
            for packet in cap:
                try:
                    # Filter for IP packets only
                    if not self._is_ip_packet(packet):
                        continue
                    
                    packet_count += 1
                    
                    # Get packet size (length of the packet in bytes)
                    packet_size = int(packet.length)
                    
                    # Determine packet direction (incoming vs outgoing)
                    # This is based on standard conventions:
                    # - Assume local network is lower IP addresses or first source
                    # - Packets from lower to higher = outgoing
                    # - Packets from higher to lower = incoming
                    
                    if self._is_incoming_packet(packet):
                        incoming_bytes += packet_size
                    else:
                        outgoing_bytes += packet_size
                
                except AttributeError as e:
                    logger.debug(f"Skipping packet with missing attributes: {e}")
                    continue
                except Exception as e:
                    logger.debug(f"Error processing packet: {e}")
                    continue
            
            cap.close()
            logger.info(
                f"Extracted: incoming={incoming_bytes}B, "
                f"outgoing={outgoing_bytes}B, packets={packet_count}"
            )
            
        except Exception as e:
            logger.error(f"Error reading file {pcapng_path}: {e}")
            raise
        
        return incoming_bytes, outgoing_bytes, packet_count
    
    def _is_ip_packet(self, packet) -> bool:
        """
        Check if packet contains IP layer.
        
        Args:
            packet: PyShark packet object
            
        Returns:
            True if packet has IP layer, False otherwise
        """
        try:
            # Check for IPv4 or IPv6
            return hasattr(packet, 'ip') or hasattr(packet, 'ipv6')
        except:
            return False
    
    def _is_incoming_packet(self, packet) -> bool:
        """
        Determine if packet is incoming or outgoing based on IP addresses.
        
        METODE 1 (IP-Based - AKURAT):
        Jika LOCAL_IP dikonfigurasi:
        - Incoming: packet dengan dst_ip = LOCAL_IP (paket masuk ke laptop)
        - Outgoing: packet dengan src_ip = LOCAL_IP (paket keluar dari laptop)
        
        METODE 2 (Port-Based - FALLBACK):
        Jika LOCAL_IP tidak dikonfigurasi:
        - Menggunakan heuristik berbasis port number
        - Server port (<1024) = traffic masuk
        - Client port (>1024) = traffic keluar
        
        Args:
            packet: PyShark packet object
            
        Returns:
            True if packet appears to be incoming, False otherwise
        """
        try:
            # METHOD 1: IP-Based Detection (Recommended)
            if self.local_ip and hasattr(packet, 'ip'):
                try:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    logger.debug(f"Packet: {src_ip} -> {dst_ip}")
                    
                    # Logika penentuan arah paket berdasarkan IP lokal
                    # Incoming: paket dikirim FROM remote TO local
                    if dst_ip == self.local_ip:
                        logger.debug(f"Incoming: {src_ip} -> {dst_ip} (dst=local)")
                        return True
                    # Outgoing: paket dikirim FROM local TO remote
                    elif src_ip == self.local_ip:
                        logger.debug(f"Outgoing: {src_ip} -> {dst_ip} (src=local)")
                        return False
                    # If neither matches, use port-based fallback
                except:
                    pass
            
            # METHOD 2: Port-Based Heuristic (Fallback)
            # Gunakan ketika IP lokal tidak tersedia
            if hasattr(packet, 'tcp'):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
                # Well-known server ports (< 1024) = incoming traffic
                # High ports (> 1024) = outgoing traffic
                return dst_port > 10000 or src_port < 1024
            elif hasattr(packet, 'udp'):
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
                return dst_port > 10000 or src_port < 1024
            else:
                # If no transport layer, assume bidirectional
                return False
        except:
            return False
    
    def process_all_files(self) -> pd.DataFrame:
        """
        Process all .pcapng files in the directory.
        
        Returns:
            DataFrame with extracted features
        """
        pcapng_files = sorted(self.pcapng_dir.glob('*.pcapng')) + \
                      sorted(self.pcapng_dir.glob('*.pcap'))
        
        if not pcapng_files:
            logger.warning(f"No .pcapng or .pcap files found in {self.pcapng_dir}")
            return pd.DataFrame()
        
        logger.info(f"Found {len(pcapng_files)} files to process")
        
        for idx, file_path in enumerate(pcapng_files, 1):
            try:
                logger.info(f"[{idx}/{len(pcapng_files)}] Processing: {file_path.name}")
                
                # Extract features
                incoming, outgoing, count = self.extract_features_from_file(str(file_path))
                
                # Get class label
                class_label = self.get_class_label(file_path.name)
                
                # Store in results
                self.features_data.append({
                    'filename': file_path.name,
                    'class_label': class_label,
                    'total_incoming_bytes': incoming,
                    'total_outgoing_bytes': outgoing,
                    'total_packets': count,
                    'total_bytes': incoming + outgoing
                })
                
                logger.info(f"✓ Completed: {file_path.name}")
                
            except Exception as e:
                logger.error(f"✗ Failed to process {file_path.name}: {e}")
                continue
        
        # Create DataFrame
        df = pd.DataFrame(self.features_data)
        
        if df.empty:
            logger.warning("No features extracted from any files")
            return df
        
        logger.info(f"Total files processed: {len(df)}")
        return df
    
    def save_to_csv(self, df: pd.DataFrame) -> None:
        """
        Save features DataFrame to CSV file.
        
        Args:
            df: DataFrame with extracted features
        """
        if df.empty:
            logger.warning("DataFrame is empty. No CSV file created.")
            return
        
        try:
            df.to_csv(self.output_csv, index=False)
            logger.info(f"✓ Features saved to: {self.output_csv}")
            logger.info(f"  - Rows: {len(df)}")
            logger.info(f"  - Columns: {', '.join(df.columns)}")
            
            # Print summary statistics
            logger.info("\nSummary Statistics:")
            logger.info(df[['total_incoming_bytes', 'total_outgoing_bytes', 'total_packets']].describe())
            
        except Exception as e:
            logger.error(f"Error saving CSV: {e}")
            raise
    
    def print_summary(self, df: pd.DataFrame) -> None:
        """
        Print summary of extracted features.
        
        Args:
            df: DataFrame with extracted features
        """
        if df.empty:
            print("\nNo data to display.")
            return
        
        print("\n" + "="*80)
        print("FEATURE EXTRACTION SUMMARY")
        print("="*80)
        print(f"\nTotal files processed: {len(df)}")
        print(f"\nUnique website classes: {df['class_label'].nunique()}")
        print(f"\nClass label distribution:")
        print(df['class_label'].value_counts())
        
        print(f"\n{'Feature':<30} {'Min':<15} {'Max':<15} {'Mean':<15}")
        print("-"*75)
        for col in ['total_incoming_bytes', 'total_outgoing_bytes', 'total_packets']:
            print(f"{col:<30} {df[col].min():<15} {df[col].max():<15} {df[col].mean():<15.2f}")
        
        print("\nFirst 10 rows:")
        print(df.head(10).to_string(index=False))
        print("="*80 + "\n")


def main():
    """Main execution function."""
    
    # Configuration
    PCAPNG_DIRECTORY = "./pcapng_data"  # Change this to your directory
    OUTPUT_CSV = "./features.csv"
    
    # =====================================================================
    # KONFIGURASI IP LOKAL - SESUAIKAN DENGAN LAPTOP ANDA
    # =====================================================================
    # Uncomment dan set dengan IP lokal laptop Anda untuk deteksi arah paket 
    # yang lebih akurat. Contoh:
    #   LOCAL_IP = "192.168.1.100"
    # 
    # Untuk menemukan IP lokal laptop Anda:
    #   Windows: jalankan "ipconfig" di cmd, cari IPv4 Address
    #   Linux/Mac: jalankan "ifconfig" atau "hostname -I"
    LOCAL_IP = "192.168.40.117"  # Ganti ke IP lokal Anda, contoh: "192.168.1.100"
    
    # Validate command-line arguments if provided
    if len(sys.argv) > 1:
        PCAPNG_DIRECTORY = sys.argv[1]
    if len(sys.argv) > 2:
        OUTPUT_CSV = sys.argv[2]
    if len(sys.argv) > 3:
        LOCAL_IP = sys.argv[3]  # Optional: pass LOCAL_IP dari command line
    
    logger.info(f"PCAPNG Directory: {PCAPNG_DIRECTORY}")
    logger.info(f"Output CSV: {OUTPUT_CSV}")
    if LOCAL_IP:
        logger.info(f"Local IP (untuk deteksi arah): {LOCAL_IP}")
    else:
        logger.info("Local IP: Not set (menggunakan heuristik berbasis port)")
    
    try:
        # Initialize extractor dengan LOCAL_IP
        extractor = PcapngFeatureExtractor(
            PCAPNG_DIRECTORY, 
            OUTPUT_CSV,
            local_ip=LOCAL_IP
        )
        
        # Process all files
        df = extractor.process_all_files()
        
        # Save to CSV
        if not df.empty:
            extractor.save_to_csv(df)
            extractor.print_summary(df)
        else:
            logger.warning("No features extracted. CSV file not created.")
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
