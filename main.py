import os
import csv
import threading
import re
# from dotenv import load_dotenv
import hashlib

def load_dotenv():
    with open('.env') as env:
        data = env.read()
        target_dir = data.split('=')[1]
        return target_dir.strip()

class Node:
    def __init__(self, parent, children, path, uuid, name, filetype, hash):
        self.parent = '' if parent is None else parent
        self.children = children
        self.path = path
        self.uuid = uuid
        self.name = name
        self.filetype = filetype
        self.hash = hash

    @classmethod
    def from_filetree(cls, parent, children, path):
        uuid = hashlib.sha256(path.encode('utf-8')).hexdigest()
        name = os.path.basename(path)
        filetype = cls.get_filetype(name)
        hash = cls.calculate_hash_from_filepath(path)

        return cls(parent=parent, children=children, path=path,
                   uuid=uuid, name=name, filetype=filetype, hash=hash)

    @classmethod
    def from_csv(cls, row):
        uuid, name, filetype, parent, path, hash, children = row
        children = re.sub(r'[\[\]]', '', children).split(',')

        return cls(parent=parent, children=children, path=path,
                   uuid=uuid, name=name, filetype=filetype, hash=hash)

    def __str__(self):
        return self.uuid

    def __repr__(self):
        return self.uuid

    def __eq__(self, node):
        return self.uuid == node.uuid

    @classmethod
    def get_filetype(cls, filename):
        if (len(filename.split('.')) > 1):
            return filename.split('.')[1]
        return 'Folder'

    @classmethod
    def calculate_hash_from_filepath(cls, filepath):
        if os.path.isdir(filepath):
            return hashlib.sha256(filepath.encode('utf-8')).hexdigest()

        hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash.update(chunk)
        return hash.hexdigest()

    @classmethod
    def print_csv_header(cls):
        return "uuid;name;filetype;parent;path;hash;children\n"

    def print_csv_line(self):
        csvl = ';'.join([
            self.uuid, self.name, self.filetype, str(self.parent),
            self.path, self.hash, "{}".format(self.children)
        ])

        return '{}\n'.format(csvl)


def generate_graph_csv_from_path(path):
    main_file = os.path.basename(path)
    generate_graph(path)

    with open("{}.csv".format(main_file), 'w') as file:
        for node in graph:
            print(node.uuid, node.parent)
            file.write(node.print_csv_line())


def write_graph_to_csv(filename):
    with open("{}.csv".format(filename), 'w') as file:
        file.write(Node.print_csv_header())
        for node in graph.values():
            print(node.uuid, node.parent)
            file.write(node.print_csv_line())


def load_graph_from_csv(csvfile):
    with open(csvfile) as f:
        csvreader = csv.reader(f, delimiter=';')
        for row in csvreader:
            node = Node.from_csv(row)
            graph[node.uuid] = node


def generate_graph(path, parent=None, recursive=True):
    node = Node.from_filetree(parent=parent, children=[], path=path)
    graph[node.uuid] = node

    if os.path.isfile(path):
        return node

    if not recursive:
        return node

    entries = os.scandir(path)
    children = []
    for entry in entries:
        children.append(generate_graph(entry.path, parent=node))

    graph[node.uuid].children = children

    joint_hashes = ",".join(map(lambda x: x.hash, children)).encode('utf-8')
    graph[node.uuid].hash = hashlib.sha256(joint_hashes).hexdigest()

    return node


def check_for_duplicates():
    hashycheky = {}
    for node in graph.values():
        if node.hash in hashycheky:
            hashycheky[node.hash].append(node)
        else:
            hashycheky[node.hash] = [node]

    for nodes in hashycheky.values():
        if (len(nodes) > 1):
            log_duplicate(nodes[0], nodes)


def log_duplicate(curr, dups):
    print("Arquivo {} é uma duplicata!".format(curr.path))
    print("Duplicatas:")
    for dup in dups:
        print("\tDuplicata: {}".format(dup.path))


def build_graph(main_dir):
    root_node = generate_graph(main_dir, recursive=False)

    entries = os.scandir(main_dir)
    threads = []
    for entry in entries:
        t = threading.Thread(
            target=generate_graph,
            args=(entry.path,),
            kwargs={"parent": root_node}
        )
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()


def print_graph():
    print("NORMAL")
    for node in graph.values():
        print("{}\t{}".format(node.name, node.hash))
    print("\nDEBUG")
    for node in graph.values():
        print("\t".join([node.name, str(node.parent), node.hash]))


graph = {}


if __name__ == '__main__':

    # load_graph_from_csv('./testing.csv')

    main_dir = load_dotenv()
    build_graph(main_dir)
    write_graph_to_csv(os.path.basename(main_dir))

    # print_graph()
    check_for_duplicates()
