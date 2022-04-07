import os
from sniffer import Sniffer

practica = 'dns_1'

def main():
    directory = 'tests'
    for filename in os.listdir(directory):
        if practica in filename:
            f = os.path.join(directory, filename)
            if os.path.isfile(f):
                try:
                    Sniffer(filename=f).handle()
                except Exception as e:
                    print(e)

if __name__ == '__main__':
    main()