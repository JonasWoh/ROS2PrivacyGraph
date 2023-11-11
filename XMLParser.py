from lxml import etree as ET
import os
import copy
import ROSGraph


# Builds a graph from the policy files in the given directory and subdirectories
# TODO: Add option to read from a single file instead of a directory
def build_graph_from_directory(existing_graph_path=None, path: str = None, include_standard_elements=False) -> (
        ROSGraph.ROSGraph):
    if path is None:
        path = os.getcwd()
    graph = ROSGraph.ROSGraph(graph_path=existing_graph_path, include_standard_elements=include_standard_elements)
    keystore = crawl_keystore(path)
    contents = {}
    for index, xml_file in enumerate(keystore):
        contents[index] = read_sros2_file(xml_file)
    for index, content in contents.items():
        add_policy_to_graph(content, graph)
    return graph


# Lists all xml files in the given directory and subdirectories with their respective paths including their names as
# keys and names as values
def crawl_keystore(path: str):
    keystore = {}
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".xml"):
                keystore[os.path.join(root, file)] = file.split('.')[0]
    return keystore


# Reads a policy file and returns a dictionary containing the xml file's structure
def read_sros2_file(path: str) -> dict:
    tree = ET.parse(path)
    tree.xinclude()
    root = tree.getroot()
    if root.tag == 'policy':
        content = parse_policy(tree.getroot())
    else:
        print(f'Root tag {root.tag} not recognised.')
        content = {}
    return content


def parse_policy(root) -> dict:
    policy_dict = {}
    for enclaves in root:
        for enclave_index, enclave in enumerate(enclaves):
            policy_dict[f'Enclave_{enclave_index}'] = copy.deepcopy(enclave.attrib)
            policy_dict[f'Enclave_{enclave_index}']['profiles'] = parse_enclave(enclave)
    return policy_dict


def parse_enclave(enclave) -> dict:
    enclave_dict = {}
    for profiles_index, profiles in enumerate(enclave):
        enclave_dict[f'Profiles_{profiles_index}'] = copy.deepcopy(profiles.attrib)
        for profile_index, profile in enumerate(profiles):
            enclave_dict[f'Profiles_{profiles_index}'][f'Profile_{profile_index}'] = copy.deepcopy(profile.attrib)
            enclave_dict[f'Profiles_{profiles_index}'][f'Profile_{profile_index}']['expressions'] \
                = parse_profile(profile)

    return enclave_dict


def parse_profile(profile) -> dict:
    profile_dict = {}
    for expression_index, expression in enumerate(profile):
        profile_dict[f'Expression_{expression_index}'] = copy.deepcopy(expression.attrib)
        profile_dict[f'Expression_{expression_index}']['type'] = expression.tag
        profile_dict[f'Expression_{expression_index}']['expression_elements'] \
            = parse_expression(expression)
    return profile_dict


def parse_expression(expression) -> dict:
    expression_dict = {}
    for expression_element_index, expression_element in enumerate(expression):
        expression_dict[f'Element_{expression_element_index}'] = {'type': expression_element.tag,
                                                                  'name': expression_element.text}
    return expression_dict


def add_policy_to_graph(policy: dict, graph: ROSGraph.ROSGraph) -> None:
    for enclave_key, enclave in policy.items():
        enclave_name = enclave['path']
        for key, item in enclave.items():
            if key == 'profiles':
                for profiles_key, profiles in item.items():
                    for profile_key, profile in profiles.items():
                        if profile_key.startswith('Profile'):
                            add_profile_to_graph(profile, graph, enclave_name)


def add_profile_to_graph(profile: dict, graph: ROSGraph.ROSGraph, enclave_name: str) -> None:
    node_name = profile['node']
    namespace = profile['ns']
    for key, item in profile.items():
        if key == 'expressions':
            for expression_key, expression in profile[key].items():
                for attribute_key, attribute_value in expression.items():
                    if attribute_key in ['publish', 'subscribe', 'reply', 'request', 'execute', 'call']:
                        for element_key, element in expression['expression_elements'].items():
                            allowed = None
                            if attribute_value == 'ALLOW':
                                allowed = True
                            elif attribute_value == 'DENY':
                                allowed = False
                            else:
                                print(f'Attribute value {attribute_value} not recognised.')
                            graph.add_connection(namespace, enclave_name, node_name, element['name'],
                                                 element['type'], attribute_key, allowed)
