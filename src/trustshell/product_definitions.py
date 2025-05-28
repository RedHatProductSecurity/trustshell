from collections import defaultdict
import copy
import json
import logging
import os
import re
from typing import Optional
import httpx

from anytree import Node, NodeMixin, LevelOrderGroupIter
from trustshell import CONFIG_DIR, console

logger = logging.getLogger(__name__)

class ProductBase(object):
    def __init__(self, name):
        self.name = name

    def __hash__(self):
        return hash(self.label)

    def __eq__(self, other):
        if isinstance(other, ProductBase) and type(self) == type(other):
            return self.label == other.label()
        return False

class ProductModule(ProductBase, NodeMixin):
    def __init__(self, name, cpe_patterns):
        super().__init__(name)
        self.cpe_patterns = [pattern.replace(".", "\\.").replace("*", ".*") for pattern in cpe_patterns]

    def match(self, cpe) -> bool:
        # First try to match exactly, then substring
        for suffix in ("$", ""):
            # We must try in descending-length order so that X:10 matches before X:1.
            for regex in sorted(self.cpe_patterns, key=len, reverse=True):
                if re.match(regex + suffix, cpe):
                    return True
        return False

class ProductStream(ProductBase, NodeMixin):
    def __init__(self, name: str, cpes: list[str]=[], active=False):
        super().__init__(name)
        self.cpes = self._filter_rhel_mainline_cpes(cpes)
        self.active = active

    def set_active(self, active: bool):
        self.active = active

    @staticmethod
    def _filter_rhel_mainline_cpes(cpes) -> list[str]:
        """Special logic for RHEL streams is required because during the lifetime of a RHEL
        release it will have the main line CPE (redhat:enterprise_linux:),
        and also EUS/AUS/TUS CPEs depending on it's lifecycle phase. The rule here is that
        if a stream has both main line and EUS/AUS/TUS ignore the main line one
        (which is less specific)"""
        cpe_set = set(cpes)
        if len(cpe_set) <= 1:
            return cpes
        has_eatus = False
        for cpe in cpes:
            for us in "eus", "aus", "tus", "e4s":
                if f":rhel_{us}:" in cpe:
                    has_eatus = True
                    break
            if has_eatus:
                break
        if not has_eatus:
            return cpes
        return [cpe for cpe in cpes if ":redhat:enterprise_linux:" not in cpe]

class ProdDefs:
    ETAG_FILE = os.path.join(CONFIG_DIR, "etag.txt")
    PRODUCT_FILE = os.path.join(CONFIG_DIR, "products.json")

    @classmethod
    def get_etag(cls, url: str):
        response = httpx.head(url)
        return response.headers.get("etag")

    # Assisted by watsonx Code Assistant
    @classmethod
    def persist_etag(cls, etag: str, file_path: str):
        with open(file_path, "w") as f:
            f.write(etag)

    # Assisted by watsonx Code Assistant
    @classmethod
    def load_etag(cls, file_path: str):
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return f.read().strip()
        return None

    # Assisted by watsonx Code Assistant
    @classmethod
    def load_product_definitions(cls, url: str, file_path: str):
        response = httpx.get(url)
        with open(file_path, "w") as f:
            f.write(response.text)

    @classmethod
    def get_product_definitions_service(cls) -> dict:
        proddefs_url = None
        if "PRODDEFS_URL" not in os.environ:
            console.print("PRODDEFS_URL not set, not product mappings will be available", style="warning")
            return {}
        else:
            proddefs_url = os.getenv("PRODDEFS_URL")

        etag = cls.load_etag(cls.ETAG_FILE)
        url_etag = cls.get_etag(proddefs_url)

        if etag == url_etag:
            with open(cls.PRODUCT_FILE, "r") as f:
                product_definitions = json.load(f)
        else:
            cls.load_product_definitions(proddefs_url, cls.PRODUCT_FILE)
            cls.persist_etag(url_etag, cls.ETAG_FILE)
            with open(cls.PRODUCT_FILE, "r") as f:
                product_definitions = json.load(f)
        return product_definitions

    def __init__(self, active_only: bool = True):
        self.stream_nodes_by_cpe = defaultdict(list)
        product_streams_by_name = defaultdict(list)
        self.module_trees: list[ProductModule] = []

        data = self.get_product_definitions_service()

        if not data:
            return
        
        for ps_update_stream, stream_data in data["ps_update_streams"].items():
            cpes = stream_data.get("cpe", [])
            stream_node = ProductStream(ps_update_stream, cpes)
            product_streams_by_name[ps_update_stream].append(stream_node)
            for cpe in cpes:
                # We need this check because RHEL mainline CPEs are filtered out
                if cpe in stream_node.cpes:
                    self.stream_nodes_by_cpe[cpe].append(stream_node)

        seen_stream_names: set[str] = set()
        for ps_module, module_data in data["ps_modules"].items():
            cpes = module_data.get("cpe", [])
            module_node = ProductModule(ps_module, cpes)
            
            active_streams: set[str] = set()
            active_streams.update(module_data.get("active_ps_update_streams", []))
            for stream in module_data.get("ps_update_streams"):
                for stream_node in product_streams_by_name[stream]:
                    if stream in active_streams:
                        stream_node.set_active(True)
                        self._check_stream_name(seen_stream_names, stream)
                        stream_node.parent = module_node
                    elif active_only and stream in self.stream_nodes_by_cpe:
                        # The stream is not active in the module, and we only want active streams
                        # Therefore lets remove this stream from the product_streams_by_cpe map
                        del self.stream_nodes_by_cpe[stream]
                    else:
                        # At this point we know the stream is inactive, but we want all streams
                        stream_node.parent = module_node
                        self._check_stream_name(seen_stream_names, stream)
            if active_only and len(active_streams) == 0:
                # Skip adding the module if it doesn't have any active streams
                continue
            self.module_trees.append(module_node)

    @staticmethod
    def _check_stream_name(seen_stream_names, stream):
        if stream in seen_stream_names:
            console.print(f"Warning: duplicate stream: {stream} detected.", style="warning")
        seen_stream_names.add(stream)

        

    def get_module_trees(self) -> list[ProductModule]:
        return self.module_trees
    
    def match_module_pattern(self, cpe: str) -> list[ProductModule]:
        module_matches = []
        for module_tree in self.module_trees:
            for modules in LevelOrderGroupIter(module_tree, maxlevel=1):
                for module in modules:
                    if module.match(cpe):
                        module_matches.append(module)
        return module_matches


    @staticmethod
    def _clean_cpe(cpe: str) -> str:
        # CPEs from SBOMs have extra characters added to them, clean them up here
        # see https://github.com/trustification/trustify/issues/1621
        # Remove all '*' characters
        cleaned_cpe = cpe.replace("*", "")
        # Remove trailing ':' characters
        return cleaned_cpe.rstrip(":")

    def extend_with_product_mappings(self, ancestor_trees: list[Node]) -> list[Node]:
        if not self.module_trees:
            # ProdDefs service is unavailable, don't attempt any product mapping
            return ancestor_trees
        ancestors_with_products: list[Node] = []
        for tree in ancestor_trees:
            # We don't want changes to the module_tree affecting other trees
            # local_module_trees = copy.deepcopy(self.module_trees)
            for roots in list(LevelOrderGroupIter(tree, maxlevel=1)):
                for root in roots:
                    cleaned_root_name = self._clean_cpe(root.name)
                    module = self._check_streams(root, cleaned_root_name)
                    if module:
                        ancestors_with_products.append(module)
                    else:
                        module = self._check_modules(root, cleaned_root_name)
                    if not root.parent: # Didn't find any matching Product
                        console.print(f"Warning, didn't find any products matching {cleaned_root_name}", style="warning")
        return ancestors_with_products


    def _check_streams(self, root: Node, cleaned_root_name: str) -> Optional[ProductModule]:
        """ Check if cpe matches exactly to any ProductStreams """
        if cleaned_root_name in self.stream_nodes_by_cpe:
            stream_nodes = self.stream_nodes_by_cpe[cleaned_root_name]
            no_of_stream_nodes = len(stream_nodes)
            if no_of_stream_nodes == 1:
                root.parent = stream_nodes[0]
                # stream could be inactive, in which case return nothing
                if root.parent:
                    stream_nodes[0].parent.children = [stream_nodes[0]]
                    return stream_nodes[0].parent
            elif no_of_stream_nodes > 1:
                console.print(f"Warning, more than one stream found matching {cleaned_root_name}", syle="warning")
        return None

    def _check_modules(self, root: Node, cleaned_root_name: str) -> Optional[ProductModule]:
        # Check if the cpe matches any ProductModule
        module_nodes = self.match_module_pattern(cleaned_root_name)
        no_of_modules = len(module_nodes)
        if no_of_modules == 1:
            # Replace the stream children of this module with the current root
            module_nodes[0].children = [root]
            return module_nodes[0]
        elif no_of_modules > 1:
            console.print(f"Warning, more than one module found matching {cleaned_root_name}", syle="warning")
        return None