import os
from sniffer import Sniffer

practica = 'tcp'

def main():
    directory = 'tests'
    for filename in os.listdir(directory):
        if practica in filename:
            f = os.path.join(directory, filename)
            if os.path.isfile(f):
                Sniffer(f).handle()

if __name__ == '__main__':
    main()