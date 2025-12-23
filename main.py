import csv
import hashlib
import os
import re
import sys
import threading


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
        filetype = cls.filetype(name)
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
    def filetype(cls, filename):
        if len(filename.split(".")) > 1:
            return filename.split(".")[-1]
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

    def to_csv(self):
        data = [
            self.uuid,
            self.name,
            self.filetype,
            str(self.parent),
            self.path,
            self.hash,
            "{}".format(self.children),
        ]
        csvl = ";".join(data)

        return "{}\n".format(csvl)

    def to_yaml(self):
        return f"""- uuid: {self.uuid}
  name: {self.name}
  filetype: {self.filetype}
  parent: {self.parent}
  path: {self.path}
  hash: "{self.hash}"
  children: {self.children}
"""


class Graph:
    def __init__(self, root: Node):
        self.root = root

    def print_duplicates(self):
        """Prints duplicate files inside graph"""
        hashycheky = {}
        nodes = [self.root]
        while len(nodes) > 0:
            node = nodes.pop(0)
            if node.hash in hashycheky:
                hashycheky[node.hash].append(node)
            else:
                hashycheky[node.hash] = [node]
            nodes += node.children

        for nodes in hashycheky.values():
            if len(nodes) > 1:
                print("Arquivo {} é uma duplicata!".format(nodes[0].path))
                print("Duplicatas:")
                for node in nodes:
                    print("\tDuplicata: {}".format(node.path))

    def to_yaml(self):
        nodes = [self.root]
        result = ""
        while len(nodes) > 0:
            node = nodes.pop(0)
            result += f"{node.to_yaml()}\n"
            nodes += node.children

        return result

    @classmethod
    def check_correctedness(cls, main_dir):
        """Checks wether graph built from csv and through code are the same

        Keywords Arguments:
        main_dir -- Directory that should be analyzed
        """
        curr_dir = os.path.basename(main_dir)
        csv_graph = Graph.from_csv("{}.csv".format(curr_dir))
        filesystem_graph = Graph.from_filetree(main_dir, should_calculate=False)
        return Graph.are_trees_equal(csv_graph.root, filesystem_graph.root)

    @classmethod
    def are_trees_equal(cls, node_a, node_b):
        """Evaluates if node_a and node_b are equal and returns the result."""
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
            result = result and Graph.are_trees_equal(
                node_a.children[i], node_b.children[i]
            )
            if not result:
                break

        return result

    # TODO: change this to yaml formatting
    def write_to_csv(self, filename):
        """Writes graph to csv file

        Keyword arguments:
        filename -- the name of the file to be created
        """
        with open("{}.csv".format(filename), "w") as file:
            file.write(Node.print_csv_header())
            nodes = [self.root]
            while len(nodes) > 0:
                node = nodes.pop(0)
                file.write(node.to_csv())
                nodes += node.children

    @classmethod
    def from_filetree(cls, main_dir, should_calculate=True):
        """Builds a graph starting from given directory
        Returns a new Graph instance

        Keyword arguments:
        main_dir -- Starting directory for graph generation
        should_calculate -- Defines wether we should calculate file hashes during traversal
        """
        root_node = Graph.generate_node(
            main_dir, recursive=False, should_calculate=should_calculate
        )

        threads = []
        for entry in os.scandir(main_dir):
            t = threading.Thread(
                target=Graph.generate_node,
                args=(entry.path,),
                kwargs={"parent": root_node, "should_calculate": should_calculate},
            )
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        return cls(root=root_node)

    @classmethod
    def from_csv(cls, csvfile):
        """Builds a node graph from CSV graph data.
        Returns root node of said graph

        Keyword Arguments:
        csvfile -- csv file that contains graph data
        """
        root = None
        graph = {}
        with open(csvfile) as f:
            csv.field_size_limit(sys.maxsize)
            csvreader = csv.reader(
                f,
                delimiter=";",
            )
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

    @classmethod
    def generate_node(cls, path, parent=None, recursive=True, should_calculate=True):
        """Recursively generates a graph based on a filepath.
        Returns root node for said graph.

        Keyword Arguments:
        path -- path of folder that should be analyzed
        parent -- parent of current node
        recursive -- defines wether we should recurse into filesystem or not
        should_calculate -- defines wether we should calculate file hash or not
        """
        node = Node.from_filetree(
            parent=parent,
            children=[],
            path=path,
            should_calculate_hash=should_calculate,
        )

        if parent:
            parent.children.append(node)

        if os.path.isfile(path):
            return node

        if not recursive:
            return node

        entries = os.scandir(path)
        for entry in entries:
            Graph.generate_node(
                entry.path, parent=node, should_calculate=should_calculate
            )

        joint_hashes = ",".join(map(lambda x: x.hash, node.children)).encode("utf-8")
        node.hash = hashlib.sha256(joint_hashes).hexdigest()

        return node

    def print_graph(self):
        """Prints graph for debugging"""

        print("NORMAL")
        nodes = [self.root]
        while len(nodes) > 0:
            node = nodes.pop(0)
            print("{}\t{}".format(node.name, node.hash))
            nodes += node.children

        print("\nDEBUG")
        nodes = [self.root]
        while len(nodes) > 0:
            node = nodes.pop(0)
            print("\t".join([node.name, str(node.parent), node.hash]))
            nodes += node.children


def help():
    """Prints help message"""
    return """Usage:
        -t, --target <DIR>: filesystem to be checked (OBRIGATORY)
        -c, --check: validates if csv and filesystem trees are equal
        -d, --debug: generate a csv without calculating hashes
        -h, --help: Prints this message!"""


def parse_arguments():
    target_dir = None
    should_print_help = False
    should_check_correctedness = False
    should_check_filesystem_full = False
    should_check_filesystem_simple = False
    should_print_yaml = False

    if len(sys.argv) > 1:
        flags = sys.argv[1:]
        for idx in range(len(flags)):
            if flags[idx] == "-t" or flags[idx] == "--target":
                if idx + 1 >= len(flags):
                    raise ValueError(f"Target not set!\n{help()}")
                else:
                    idx += 1
                    if flags[idx] in ["-c", "-d", "-h", "--check", "--debug", "--help"]:
                        raise ValueError(f"Target not set!\n{help()}")
                    else:
                        target_dir = flags[idx]
                        should_check_filesystem_full = True
            elif flags[idx] == "-c" or flags[idx] == "--check":
                should_check_correctedness = True
            elif flags[idx] == "-d" or flags[idx] == "--debug":
                should_check_filesystem_simple = True
            elif flags[idx] == "-h" or flags[idx] == "--help":
                should_print_help = True
            elif flags[idx] == "-y" or flags[idx] == "--yaml":
                should_print_yaml = True
    else:
        raise ValueError(f"Missing arguments!\n{help()}")

    return (
        target_dir,
        should_print_help,
        should_check_correctedness,
        should_check_filesystem_simple,
        should_check_filesystem_full,
        should_print_yaml,
    )


if __name__ == "__main__":
    (
        target_dir,
        should_print_help,
        should_check_correctedness,
        should_check_filesystem_simple,
        should_check_filesystem_full,
        should_print_yaml,
    ) = parse_arguments()

    curr_dir = os.path.basename(str(target_dir))
    if target_dir is None:
        raise ValueError(f"Target not set!\n{help()}")
    elif should_print_help:
        help()
    elif should_check_correctedness:
        are_equal = Graph.check_correctedness(target_dir)
        print("Are files equal? {}".format(are_equal))
    elif should_print_yaml:
        graph = Graph.from_filetree(target_dir)
        print(graph.to_yaml())
    elif should_check_filesystem_simple:
        graph = Graph.from_filetree(target_dir, should_calculate=False)
        graph.write_to_csv(curr_dir)
    elif should_check_filesystem_full:
        graph = Graph.from_filetree(target_dir)
        graph.write_to_csv(curr_dir)
        graph.print_duplicates()
    else:
        raise ValueError(f"Incorrect arguments\n{help()}")
