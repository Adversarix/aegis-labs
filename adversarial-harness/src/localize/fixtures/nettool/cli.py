import argparse
from checks import ping_host
from config import DEFAULT_COUNT

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    print(ping_host(ap.parse_args().host, DEFAULT_COUNT))

if __name__ == "__main__":
    main()
