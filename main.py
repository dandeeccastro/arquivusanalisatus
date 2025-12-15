import csv

# from dotenv import load_dotenv
import hashlib
import os
import re
import sys
import threading


def load_dotenv():
    with open(".env") as env:
        data = env.read()
        target_dir = data.split("=")[1]
        return target_dir.strip()


class Node:
    def __init__(self, parent, children, path, uuid, name, filetype, hash):
        self.parent = "" if parent is None else parent
        self.children = children
        self.path = path
        self.uuid = uuid
        self.name = name
        self.filetype = filetype
        self.hash = hash

    @classmethod
    def from_filetree(cls, parent, children, path, should_calculate_hash=True):
        uuid = hashlib.sha256(path.encode("utf-8")).hexdigest()
        name = os.path.basename(path)
        filetype = cls.get_filetype(name)
        if should_calculate_hash:
            hash = cls.calculate_hash_from_filepath(path)
        else:
            hash = ""

        return cls(
            parent=parent,
            children=children,
            path=path,
            uuid=uuid,
            name=name,
            filetype=filetype,
            hash=hash,
        )

    @classmethod
    def from_csv(cls, row):
        uuid, name, filetype, parent, path, hash, children = row
        children = re.sub(r"[\[\]]", "", children).split(",")

        return cls(
            parent=parent,
            children=children,
            path=path,
            uuid=uuid,
            name=name,
            filetype=filetype,
            hash=hash,
        )

    def __str__(self):
        return self.uuid

    def __repr__(self):
        return self.uuid

    def __eq__(self, node):
        return self.uuid == node.uuid

    @classmethod
    def get_filetype(cls, filename):
        if len(filename.split(".")) > 1:
            return filename.split(".")[1]
        return "Folder"

    @classmethod
    def calculate_hash_from_filepath(cls, filepath):
        if os.path.isdir(filepath):
            return hashlib.sha256(filepath.encode("utf-8")).hexdigest()

        hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash.update(chunk)
        return hash.hexdigest()

    @classmethod
    def print_csv_header(cls):
        return "uuid;name;filetype;parent;path;hash;children\n"

    def print_csv_line(self):
        csvl = ";".join(
            [
                self.uuid,
                self.name,
                self.filetype,
                str(self.parent),
                self.path,
                self.hash,
                "{}".format(self.children),
            ]
        )

        return "{}\n".format(csvl)


def generate_graph_csv_from_path(path):
    main_file = os.path.basename(path)
    generate_graph(path)

    with open("{}.csv".format(main_file), "w") as file:
        for node in graph:
            print(node.uuid, node.parent)
            file.write(node.print_csv_line())


def write_graph_to_csv(filename):
    print(filename)
    with open("{}.csv".format(filename), "w") as file:
        file.write(Node.print_csv_header())
        for node in graph.values():
            print(node.uuid, node.parent)
            file.write(node.print_csv_line())


def build_graph_from_csv(csvfile):
    root = None
    graph = {}
    with open(csvfile) as f:
        csvreader = csv.reader(f, delimiter=";")
        idx = 0
        for row in csvreader:
            if idx == 0:
                idx += 1
                continue

            node = Node.from_csv(row)
            graph[node.uuid] = node

            if idx == 1:
                root = node
            idx += 1

    # populate children
    for node in graph.values():
        if len(node.children) > 0:
            c = []
            for child in node.children:
                if child != "":
                    p = re.sub(" ", "", child)
                    c.append(graph[p])
            node.children = c

    return root


def generate_graph(path, parent=None, recursive=True, should_calculate=True):
    node = Node.from_filetree(
        parent=parent, children=[], path=path, should_calculate_hash=should_calculate
    )
    graph[node.uuid] = node

    if parent:
        parent.children.append(node)

    if os.path.isfile(path):
        return node

    if not recursive:
        return node

    entries = os.scandir(path)
    children = []
    for entry in entries:
        children.append(
            generate_graph(entry.path, parent=node, should_calculate=should_calculate)
        )

    graph[node.uuid].children = children

    joint_hashes = ",".join(map(lambda x: x.hash, children)).encode("utf-8")
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
        if len(nodes) > 1:
            log_duplicate(nodes[0], nodes)


def log_duplicate(curr, dups):
    print("Arquivo {} é uma duplicata!".format(curr.path))
    print("Duplicatas:")
    for dup in dups:
        print("\tDuplicata: {}".format(dup.path))


def build_graph_from_filesystem(main_dir, should_calculate=True):
    root_node = generate_graph(
        main_dir, recursive=True, should_calculate=should_calculate
    )

    # threads = []
    # for entry in os.scandir(main_dir):
    #     t = threading.Thread(
    #         target=generate_graph,
    #         args=(entry.path,),
    #         kwargs={"parent": root_node, "should_calculate": should_calculate},
    #     )
    #     threads.append(t)

    # for t in threads:
    #     t.start()
    # for t in threads:
    #     t.join()

    return root_node


def print_graph():
    print("NORMAL")
    for node in graph.values():
        print("{}\t{}".format(node.name, node.hash))
    print("\nDEBUG")
    for node in graph.values():
        print("\t".join([node.name, str(node.parent), node.hash]))


def check_correctedness(main_dir):
    curr_dir = os.path.basename(main_dir)
    root_node_csv = build_graph_from_csv("{}.csv".format(curr_dir))
    root_node_graph = build_graph_from_filesystem(main_dir, should_calculate=False)
    return are_trees_equal(root_node_csv, root_node_graph)


def are_trees_equal(node_a, node_b):
    if not node_a and not node_b:
        return True

    if not node_a:
        return False

    if not node_b:
        return False

    if node_a.path != node_b.path:
        return False

    if len(node_a.children) != len(node_b.children):
        return False

    result = node_a.path == node_b.path
    for i in range(len(node_a.children)):
        result = result and are_trees_equal(node_a.children[i], node_b.children[i])
        if not result:
            break

    return result


graph = {}


if __name__ == "__main__":
    main_dir = load_dotenv()
    if len(sys.argv) > 1 and sys.argv[1] == "-c":
        are_equal = check_correctedness(main_dir)
        print("Are files equal? {}".format(are_equal))
    elif len(sys.argv) > 1 and sys.argv[1] == "-d":
        build_graph_from_filesystem(main_dir, should_calculate=False)
        write_graph_to_csv(os.path.basename(main_dir))
    else:
        build_graph_from_filesystem(main_dir)
        print(main_dir)
        write_graph_to_csv(os.path.basename(main_dir))
        check_for_duplicates()
