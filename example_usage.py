"""
Example usage of the PcapngFeatureExtractor class

This script demonstrates various ways to use the feature extractor.
"""

from extract_features import PcapngFeatureExtractor
import pandas as pd
import logging

# Configure logging level (set to DEBUG for more verbose output)
logging.basicConfig(level=logging.INFO)

# Example 1: Basic usage with default settings
print("\n" + "="*80)
print("EXAMPLE 1: Basic Usage")
print("="*80)

try:
    extractor = PcapngFeatureExtractor(
        pcapng_directory="./pcapng_data",
        output_csv="./features.csv"
    )
    df = extractor.process_all_files()
    extractor.save_to_csv(df)
    extractor.print_summary(df)
except Exception as e:
    print(f"Error: {e}")


# Example 1b: DENGAN IP LOKAL (RECOMMENDED untuk akurasi tinggi)
print("\n" + "="*80)
print("EXAMPLE 1b: Basic Usage WITH LOCAL IP (AKURAT)")
print("="*80)
print("\n[PENTING] Ubah IP di bawah dengan IP lokal laptop Anda!")
print("  Windows: jalankan 'ipconfig' dan cari IPv4 Address")
print("  Linux/Mac: jalankan 'ifconfig' atau 'hostname -I'\n")

try:
    # ⚠️ GANTI DENGAN IP LOKAL LAPTOP ANDA ⚠️
    LOCAL_IP = "192.168.40.117"  # Contoh: ganti dengan IP Anda
    
    extractor = PcapngFeatureExtractor(
        pcapng_directory="./pcapng_data",
        output_csv="./features_with_local_ip.csv",
        local_ip=LOCAL_IP  # Set IP lokal untuk deteksi arah yang akurat
    )
    df = extractor.process_all_files()
    
    if not df.empty:
        extractor.save_to_csv(df)
        print("\n✓ File saved: features_with_local_ip.csv")
        print(f"\nLogic yang digunakan:")
        print(f"  - Incoming: Paket ke {LOCAL_IP}")
        print(f"  - Outgoing: Paket dari {LOCAL_IP}")
        print(f"\nFirst 5 rows:")
        print(df[['filename', 'class_label', 'total_incoming_bytes', 'total_outgoing_bytes']].head())
except Exception as e:
    print(f"Error: {e}")


# Example 2: Custom output filename
print("\n" + "="*80)
print("EXAMPLE 2: Custom Output Filename")
print("="*80)

try:
    extractor = PcapngFeatureExtractor(
        pcapng_directory="./pcapng_data",
        output_csv="./my_custom_features.csv"
    )
    df = extractor.process_all_files()
    extractor.save_to_csv(df)
    print(f"\nFiles saved to my_custom_features.csv")
except Exception as e:
    print(f"Error: {e}")


# Example 3: Post-processing features with pandas
print("\n" + "="*80)
print("EXAMPLE 3: Post-processing with Pandas")
print("="*80)

try:
    extractor = PcapngFeatureExtractor(
        pcapng_directory="./pcapng_data",
        output_csv="./features_processed.csv"
    )
    df = extractor.process_all_files()
    
    if not df.empty:
        # Calculate additional features
        df['incoming_ratio'] = df['total_incoming_bytes'] / (df['total_bytes'] + 1)
        df['outgoing_ratio'] = df['total_outgoing_bytes'] / (df['total_bytes'] + 1)
        df['avg_packet_size'] = df['total_bytes'] / (df['total_packets'] + 1)
        
        # Save enhanced features
        df.to_csv("./features_processed.csv", index=False)
        print("\nEnhanced features saved with additional calculated fields:")
        print(f"  - incoming_ratio: Incoming bytes / Total bytes")
        print(f"  - outgoing_ratio: Outgoing bytes / Total bytes")
        print(f"  - avg_packet_size: Average packet size in bytes")
        print(f"\nFirst 5 rows with new features:")
        print(df[['filename', 'class_label', 'incoming_ratio', 'avg_packet_size']].head())
except Exception as e:
    print(f"Error: {e}")


# Example 4: Filtering and analysis by class label
print("\n" + "="*80)
print("EXAMPLE 4: Analysis by Class Label")
print("="*80)

try:
    extractor = PcapngFeatureExtractor(
        pcapng_directory="./pcapng_data",
        output_csv="./features.csv"
    )
    df = extractor.process_all_files()
    
    if not df.empty:
        print("\nStatistics by Class Label:")
        print("-" * 80)
        
        # Group by class label and calculate statistics
        grouped = df.groupby('class_label').agg({
            'total_incoming_bytes': ['mean', 'std', 'min', 'max'],
            'total_outgoing_bytes': ['mean', 'std', 'min', 'max'],
            'total_packets': ['mean', 'std', 'min', 'max']
        })
        
        print(grouped)
        
        # Save statistics to CSV
        grouped.to_csv("./class_statistics.csv")
        print("\nStatistics saved to class_statistics.csv")
except Exception as e:
    print(f"Error: {e}")


# Example 5: Creating train/test split
print("\n" + "="*80)
print("EXAMPLE 5: Creating Train/Test Split")
print("="*80)

try:
    from sklearn.model_selection import train_test_split
    
    extractor = PcapngFeatureExtractor(
        pcapng_directory="./pcapng_data",
        output_csv="./features.csv"
    )
    df = extractor.process_all_files()
    
    if not df.empty:
        # Select features and target
        X = df[['total_incoming_bytes', 'total_outgoing_bytes', 'total_packets']]
        y = df['class_label']
        
        # Split into train/test (80/20)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Save splits
        train_df = pd.DataFrame(X_train)
        train_df['class_label'] = y_train
        test_df = pd.DataFrame(X_test)
        test_df['class_label'] = y_test
        
        train_df.to_csv("./train_features.csv", index=False)
        test_df.to_csv("./test_features.csv", index=False)
        
        print(f"\nTrain set: {len(train_df)} samples")
        print(f"Test set: {len(test_df)} samples")
        print(f"Class distribution in train set:")
        print(y_train.value_counts())
        print("\nFiles saved:")
        print("  - train_features.csv")
        print("  - test_features.csv")
except ImportError:
    print("sklearn not installed. Install with: pip install scikit-learn")
except Exception as e:
    print(f"Error: {e}")


print("\n" + "="*80)
print("Examples completed!")
print("="*80)
