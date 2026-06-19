#!/usr/bin/env python3
"""
APK Inspector and Recovery Tool

A tool for inspecting, analyzing, and recovering malformed APK files.
This tool extracts APK contents, fixes malformed assets and manifests, and reconstructs
a clean APK file suitable for analysis.

Author: Cleafy Labs
Version: 1.0.0
License: MIT
"""

import sys
import os
import shutil
import zipfile
import argparse
import logging
from pathlib import Path
from typing import Optional
import tempfile
import traceback

# Custom modules for APK fixing
try:
    from zipfixer import ZipFixer
    from manfixer import AndroidManifestParser
    from astfixer import APKAssetExtractor
    from apksigner import APKSigner
    from arscfixer import ArscFixer
except ImportError as e:
    logging.error(f"Required module not found: {e}")
    sys.exit(1)

class MalfixerError(Exception):
    """Custom exception for APK Inspector errors."""
    pass


class Malfixer:
    """
    An APK inspection and recovery tool.
    
    This class provides methods to inspect, analyze, and repair malformed APK files
    by extracting contents, fixing assets and manifests, and reconstructing clean APK files.
    """
    
    def __init__(self, apk_path: str, logger: logging, output_dir: Optional[str] = None):
        """
        Initialize the APK Inspector.
        
        Args:
            apk_path (str): Path to the input APK file
            logger: Logger
            output_dir (str, optional): Directory for output files. Defaults to current directory.
        """
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir) if output_dir else self.apk_path.parent
        self.temp_dir = None
        
        # Validate input file
        if not self.apk_path.exists():
            raise MalfixerError(f"APK file not found: {self.apk_path}")

        self.logger = logger
            
    def _create_temp_directory(self) -> Path:
        """Create a temporary directory for APK extraction."""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="malfixer_"))
        self.logger.debug(f"Created temporary directory: {self.temp_dir}")
        return self.temp_dir

    def _cleanup_temp_directory(self) -> None:
        """Clean up the temporary directory."""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            self.logger.debug("Cleaned up temporary directory")

    def inspect_and_recover(self) -> Path:
        """
        Main method to inspect and recover the APK file.
        
        Returns:
            Path: Path to the recovered APK file, "None" if no malformation is detected.
        """

        try:
            self.logger.debug(f"Starting APK inspection: {self.apk_path}")
            
            # Create temporary workspace and a working copy of the apk
            self._create_temp_directory()    
            output_apk = str(self.output_dir / self.apk_path.stem) + "-fixed.apk"
            shutil.copy(self.apk_path, output_apk)

            # Check if the APK is a malformed ZIP file
            zipfixer = ZipFixer(output_apk, self.logger)
            zipresult = zipfixer.recover(output_apk)
            
            # Check for malformed assets
            astfixer = APKAssetExtractor(output_apk, self.logger)
            mal_assets = astfixer.find_malformed_assets()

            if mal_assets:
                astfixer.decompress_and_save_files(mal_assets, str(self.temp_dir) + "/recovered_assets/")

            # Unzip APK contents to the temporary directory.
            # Also record each entry's original compress_type so the re-zip can
            # preserve it instead of blindly re-deflating everything.
            _MAX_PATH = 512  # guard against deeply-nested paths causing RecursionError in os.makedirs
            original_compress: dict = {}
            with zipfile.ZipFile(output_apk, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    original_compress[file_info.filename] = file_info.compress_type
                    if len(file_info.filename) > _MAX_PATH:
                        self.logger.warning(f"Skipping {file_info.filename[:80]}... (path too long)")
                        continue
                    try:
                        zip_ref.extract(file_info, path=str(self.temp_dir))
                    except zipfile.BadZipFile as e:
                        self.logger.warning(f"Skipping file {file_info.filename} due to a bad CRC: {e}")
                    except Exception as e:
                        self.logger.warning(f"Skipping file {file_info.filename} due to error: {e}")
            self.logger.debug("APK content extracted.")


            # Replace the AndroidManifest.xml file
            manifest_path = self.temp_dir / "AndroidManifest.xml"


            manfixer = AndroidManifestParser(str(self.temp_dir), self.logger)
            manresult = manfixer.parse_manifest(manifest_path)

            if manresult:
                shutil.move(self.temp_dir / "fixed.xml", manifest_path)
                self.logger.debug("AndroidManifest.xml replaced.")

            # Check and fix resources.arsc
            arscresult = False
            arsc_path = self.temp_dir / "resources.arsc"
            if arsc_path.exists():
                arsc_data = arsc_path.read_bytes()
                arsc_parser = ArscFixer(arsc_data, self.logger)
                parse_result = arsc_parser.parse()
                if not parse_result.valid:
                    fixed_data, fixes = arsc_parser.fix()
                    if fixes:
                        arsc_path.write_bytes(fixed_data)
                        arscresult = True
                        self.logger.debug(
                            f"resources.arsc: {len(fixes)} fix(es) applied "
                            f"({parse_result.error_count} errors resolved)."
                        )
                    else:
                        self.logger.warning(
                            "resources.arsc: malformed but no automatic fix available."
                        )
                else:
                    self.logger.debug("resources.arsc: no malformation detected.")

            if zipresult != "None" or mal_assets or manresult or arscresult:
                # Re-zip the contents into a new APK file.
                #
                # Compression rules:
                #   MUST_STORE  — Android memory-maps these at runtime; they must be
                #                 uncompressed inside the ZIP.
                #   *.so        — native libs are mmap-executed directly from the APK on
                #                 Android 6+ (extractNativeLibs=false); must be STORED.
                #   everything else — preserve the compression the entry had in the
                #                 original APK (recorded above).  This avoids re-deflating
                #                 already-compressed media (png/jpg/mp3/…) which would
                #                 waste CPU and could increase file size.
                _MUST_STORE = {"resources.arsc", "AndroidManifest.xml"}
                with zipfile.ZipFile(output_apk, 'w', zipfile.ZIP_DEFLATED) as new_apk:
                    for file_path in self.temp_dir.rglob('*'):
                        if file_path.is_file():
                            arcname = str(file_path.relative_to(self.temp_dir))
                            if arcname in _MUST_STORE or arcname.endswith(".so"):
                                compress = zipfile.ZIP_STORED
                            else:
                                compress = original_compress.get(arcname, zipfile.ZIP_DEFLATED)
                            new_apk.write(str(file_path), arcname, compress_type=compress)
                self.logger.debug(f"New APK created: {output_apk}")
            
            
                self.logger.debug("APK inspection and recovery completed successfully")

                return output_apk
            else:
                self.logger.debug("No malformation detected. Recovery not needed.")    
                os.remove(output_apk)
                return "None"
            
        except Exception as e:
            self.logger.error(f"APK inspection failed: {e}")
            raise
        finally:
            # Clean up temporary directory
            self._cleanup_temp_directory()

    def resign_apk(self, apk_path):
        print("Resigned")
        pass
        return apk_path


def main():
    """Main entry point for the APK Inspector tool."""
    parser = argparse.ArgumentParser(
        description="MalFixer: APK Inspector and Recovery Tool",
        epilog="""
        This tool inspects APK files for malformed structures, recovers assets,
        fixes Android manifests, and creates clean APK files suitable for analysis.
        
        Example usage:
            python malfixer.py /path/to/app.apk
            python malfixer.py /path/to/app.apk --output-dir /path/to/output
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "apk_path",
        help="Path to the input APK file"
    )
    
    parser.add_argument(
        "--output-dir",
        help="Directory for output files (default: same as input APK)",
        default=None
    )
    
    parser.add_argument(
        "--resign",
        help="Resign and re-align the APK. WARNING: This operation replaces the APK's original certificate with a new one.",
        action="store_true"
    )

    parser.add_argument(
        "--log-level", "-l",
        default="ERROR",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: ERROR)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Malfixer 1.0.0"
    )
    
    args = parser.parse_args()

    # Setup logging
    numeric_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        force=True  # Override any previous logging setup
    )
    logger = logging.getLogger(__name__)

    # Create and run Malfixer
    try:
        malfixer = Malfixer(args.apk_path, logger, args.output_dir)
        output_apk = malfixer.inspect_and_recover()

        if args.resign:
            logger = logging.getLogger(__name__)
            signer = APKSigner(logger)
            output_apk = signer.sign(output_apk)
        
        if output_apk != "None":
            print(f"\nSuccess! Fixed APK created: {output_apk}")
        else:
            print(f"\nNo malfrmation detected. Recovery is not needed.")

    except MalfixerError as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}", file=sys.stderr)
        traceback.print_exc() 
        sys.exit(1)


if __name__ == "__main__":
    main()
