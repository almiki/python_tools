
def main():
    import argparse
    import hashlib
    import os
    import shutil

    p = argparse.ArgumentParser(description='Maybe file copier')
    p.add_argument('--sources', '-s', dest="sources", required=True, nargs="+", help="Source files")
    p.add_argument('--source-dir', '-sd', dest="source_dir", required=False, help="Directory of source files")
    p.add_argument('--destinations', '-d', dest="destinations", required=True, nargs="+", help="Destination files")
    p.add_argument('--destination-dir', '-dd', dest="destination_dir", required=False, help="Directory of destination files")
    args = p.parse_args()

    def fix_path(directory, file_path):
        if directory:
            file_path = os.path.join(directory, file_path)
        return os.path.abspath(file_path)

    sources = [fix_path(args.source_dir, s) for s in args.sources]
    dests = [fix_path(args.destination_dir, s) for s in args.destinations]
    if len(sources) != len(dests):
        raise Exception("Mismatching sources/destinations")

    # If anything was copied, return 0 to indicated "success"
    result = 1

    for source, dest in zip(sources, dests):
        try:
            hashes = []
            for path in [source, dest]:
                with open(path, 'rb') as f:
                    hashes.append(hashlib.file_digest(f, 'sha256').hexdigest())
            source_hash, dest_hash = hashes
        except:
            source_hash = dest_hash = None
            
        if source_hash is None or dest_hash is None or source_hash != dest_hash:
            shutil.copyfile(source, dest)
            print("Copied {} to {}".format(source, dest))
            result = 0

        else:
            print("Skipping copy of {}".format(source))

    return result

if __name__ == "__main__":
    import sys
    sys.exit(main())
