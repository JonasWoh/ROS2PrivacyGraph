import networkx as nx
import matplotlib.pyplot as plt


# A class representing the data flow graph of a ROS system with nodes representing ROS nodes, topics, services and
# actions and edges representing the communication between them
# Contains additional information about the nodes and edges, such as the enclave they belong to, the privacy type of
# the node or the type of communication represented by the edge
class ROSGraph:
    # Initializes the ROSGraph
    # @param nx_graph: An existing networkx graph to be used as the base for the ROSGraph
    def __init__(self, graph_path=None, include_standard_elements=False):
        print('>>>>>>>>>>Initializing ROSGraph<<<<<<<<<<')
        self.include_standard_elements = include_standard_elements
        self.remove_non_descendants = True
        self.vulnerable_path_elements = []
        self.vulnerable_edges = []
        self.nx_graph = nx.DiGraph()
        # TODO: Implement reading of graph from file
        #if graph_path is not None:
            #self.read_graph(graph_path)
        self.privacy_graph = None  # Only access through get_privacy_graph()
        self.update_privacy_graph()
        print('>>>>>>>>>>Finished Initializing ROSGraph<<<<<<<<<<')

    # Adds a graph node representing a ROS node to the graph
    # @param node_name: Combination <namespace><name> of the node to add
    # @param enclave: The enclave the node belongs to
    # @param privacy_type: The privacy type of the node (default, source, leak, conduit, sanitizer)
    def add_node_node(self, node_name: str, enclave: str, privacy_type='default'):
        self.nx_graph.add_node(node_name, node_type='node', enclave=enclave, privacy_type=privacy_type)

    # Adds a graph node representing a ROS topic to the graph
    # @param topic_name: The name of the topic to add
    # @param enclave: The enclave the topic belongs to
    # @param data_type: The type of the topic to add
    # @param privacy_type: The privacy type of the topic (default, sensitive, mundane)
    def add_topic_node(self, topic_name, enclave, data_type=None, privacy_type='default'):
        self.nx_graph.add_node(topic_name, node_type='topic', data_type=data_type, enclave=enclave,
                               privacy_type=privacy_type)

    # Adds a graph node representing a ROS service to the graph
    # @param service_name: The name of the service to add
    # @param enclave: The enclave the service belongs to
    # @param data_type: The type of the service to add
    # @param privacy_type: The privacy type of the service (default, sensitive, mundane)
    def add_service_node(self, service_name, enclave, data_type=None, privacy_type='default'):
        self.nx_graph.add_node(service_name, node_type='service', data_type=data_type, enclave=enclave,
                               privacy_type=privacy_type)

    # Adds a graph node representing a ROS action to the graph
    # @param action_name: The name of the action to add
    # @param enclave: The enclave the action belongs to
    # @param data_type: The type of the action to add
    # @param privacy_type: The privacy type of the action (default, sensitive, mundane)
    def add_action_node(self, action_name, enclave, data_type=None, privacy_type='default'):
        self.nx_graph.add_node(action_name, node_type='action', data_type=data_type, enclave=enclave,
                               privacy_type=privacy_type)

    # Add a graph edge representing the subscription of a node to a topic to the graph
    # @param node_name: The name of the node subscribing to the topic in the form <namespace><name>
    # @param topic_name: The name of the topic the node subscribes to
    # @param allowed: Whether the connection is allowed by the MAC or not
    def add_subscriber(self, node_name, topic_name, allowed=None):
        if not self.nx_graph.has_edge(topic_name, node_name):
            self.nx_graph.add_edge(topic_name, node_name, role='subscriber', allowed=None)
        self.add_allow_or_deny(topic_name, node_name, allowed=allowed)

    # Add a graph edge representing the publication of a node to a topic to the graph
    # @param node_name: The name of the node publishing to the topic in the form <namespace><name>
    # @param topic_name: The name of the topic the node publishes to
    # @param allowed: Whether the connection is allowed by the MAC or not
    def add_publisher(self, node_name, topic_name, allowed=None):
        if not self.nx_graph.has_edge(node_name, topic_name):
            self.nx_graph.add_edge(node_name, topic_name, role='publisher', allowed=None)
        self.add_allow_or_deny(node_name, topic_name, allowed=allowed)

    # Add a graph edge representing the relation of a client node to the service to the graph
    # @param node_name: The name of the node calling the service in the form <namespace><name>
    # @param service_name: The name of the service the node calls
    # @param allowed: Whether the connection is allowed by the MAC or not
    def add_client(self, node_name, service_name, allowed=None):
        if not self.nx_graph.has_edge(service_name, node_name):
            self.nx_graph.add_edge(service_name, node_name, role='client', allowed=None)
        self.add_allow_or_deny(service_name, node_name, allowed=allowed)
        if not self.nx_graph.has_edge(node_name, service_name):
            self.nx_graph.add_edge(node_name, service_name, role='client', allowed=None)
        self.add_allow_or_deny(node_name, service_name, allowed=allowed)

    # Add a graph edge representing the relation of a server node to the service to the graph
    # @param node_name: The name of the node providing the service in the form <namespace><name>
    # @param service_name: The name of the service the node provides
    # @param allowed: Whether the connection is allowed by the MAC or not
    def add_server(self, node_name, service_name, allowed=None):
        if not self.nx_graph.has_edge(node_name, service_name):
            self.nx_graph.add_edge(node_name, service_name, role='server', allowed=None)
        self.add_allow_or_deny(node_name, service_name, allowed=allowed)
        if not self.nx_graph.has_edge(service_name, node_name):
            self.nx_graph.add_edge(service_name, node_name, role='server', allowed=None)
        self.add_allow_or_deny(service_name, node_name, allowed=allowed)

    # Add a graph edge representing the relation of a client node to the action to the graph
    # @param node_name: The name of the node calling the action in the form <namespace><name>
    # @param action_name: The name of the action the node calls
    # @param allowed: Whether the connection is allowed by the MAC or not
    def add_caller(self, node_name, action_name, allowed=None):
        if not self.nx_graph.has_edge(action_name, node_name):
            self.nx_graph.add_edge(action_name, node_name, role='caller', allowed=None)
        self.add_allow_or_deny(action_name, node_name, allowed=allowed)
        if not self.nx_graph.has_edge(node_name, action_name):
            self.nx_graph.add_edge(node_name, action_name, role='caller', allowed=None)
        self.add_allow_or_deny(node_name, action_name, allowed=allowed)

    # Add a graph edge representing the relation of a server node to the action to the graph
    # @param node_name: The name of the node providing the action in the form <namespace><name>
    # @param action_name: The name of the action the node provides
    # @param allowed: Whether the connection is allowed by the MAC or not
    def add_executor(self, node_name, action_name, allowed=None):
        if not self.nx_graph.has_edge(node_name, action_name):
            self.nx_graph.add_edge(node_name, action_name, role='executor', allowed=None)
        self.add_allow_or_deny(node_name, action_name, allowed=allowed)
        if not self.nx_graph.has_edge(action_name, node_name):
            self.nx_graph.add_edge(action_name, node_name, role='executor', allowed=None)
        self.add_allow_or_deny(action_name, node_name, allowed=allowed)

    # Add a graph edge representing an allowed connection between a node and a mode of communication or, if the edge
    # already exists, set the allowed attribute to True
    # @param source: The source node of the edge (u)
    # @param target: The target node of the edge (v)
    def add_allowed(self, source, target):
        if self.nx_graph.has_edge(source, target):
            try:
                if self.nx_graph.edges[source, target]['allowed'] is False:
                    pass  # ALLOW rule can't overwrite DENY rule
                elif self.nx_graph.edges[source, target]['allowed'] is None:
                    self.nx_graph.edges[source, target]['allowed'] = True
            except KeyError:
                self.nx_graph.edges[source, target]['allowed'] = True
        else:
            self.nx_graph.add_edge(source, target, role=None, allowed=True)

    # Add a graph edge representing a denied connection between a node and a mode of communication or, if the edge
    # already exists, set the allowed attribute to False
    # @param source: The source node of the edge (u)
    # @param target: The target node of the edge (v)
    def add_denied(self, source, target):
        if self.nx_graph.has_edge(source, target):
            self.nx_graph.edges[source, target]['allowed'] = False
        else:
            self.nx_graph.add_edge(source, target, role=None, allowed=False)

    # Change the allowed attribute of an existing edge to True. This is only possible if a DENY rule was changed to
    # ALLOW by the user. Generally ALLOW rules do not overwrite DENY rules.
    # @param source: The source node of the edge (u)
    # @param target: The target node of the edge (v)
    def change_deny_to_allow(self, source, target):
        if self.nx_graph.has_edge(source, target):
            self.nx_graph.edges[source, target]['allowed'] = True
        else:
            print(f'>>>>>>>>>>Edge {source} -> {target} does not exist<<<<<<<<<<')

    # Add a graph edge representing a connection between a node and a mode of communication with the given allowed or,
    # if the edge already exists, set the allowed attribute to the given value
    # @param source: The source node of the edge (u)
    # @param target: The target node of the edge (v)
    def add_allow_or_deny(self, source, target, allowed):
        if allowed is True:
            self.add_allowed(source, target)
        elif allowed is False:
            self.add_denied(source, target)
        elif allowed is None:
            pass
        else:
            print(f'>>>>>>>>>>Allowed value {allowed} not recognised<<<<<<<<<<')

    # Set the privacy type for a ros node
    # @param node_name: The name of the node to set the privacy type for
    # @param privacy_type: The privacy type to set for the node
    def set_privacy_type_for_node(self, node_name, privacy_type) -> None:
        node_privacy_types = ['default', 'source', 'leak', 'conduit', 'sanitizer']
        if self.nx_graph.has_node(node_name):
            if self.nx_graph.nodes[node_name]['node_type'] == 'node':
                if privacy_type in node_privacy_types:
                    self.nx_graph.nodes[node_name]['privacy_type'] = privacy_type
                else:
                    print(f'>>>>>>>>>>Privacy type {privacy_type} not recognised<<<<<<<<<<')
            else:
                print(f">>>>>>>>>>Graph node {node_name} is not a ros node, but a(n) "
                      f"{self.nx_graph.nodes[node_name]['node_type']}<<<<<<<<<<")
        else:
            print(f'>>>>>>>>>>Graph node {node_name} does not exist<<<<<<<<<<')

    # Set the privacy type for a transmitter
    # @param transmitter_name: The name of the transmitter to set the privacy type for
    # @param privacy_type: The privacy type to set for the transmitter
    def set_privacy_type_for_transmitter(self, transmitter_name, privacy_type) -> None:
        transmitter_privacy_types = ['default', 'sensitive', 'mundane']
        if self.nx_graph.has_node(transmitter_name):
            if self.nx_graph.nodes[transmitter_name]['node_type'] in ['topic', 'service', 'action']:
                if privacy_type in transmitter_privacy_types:
                    self.nx_graph.nodes[transmitter_name]['privacy_type'] = privacy_type
                else:
                    print(f'>>>>>>>>>>Privacy type {privacy_type} not recognised<<<<<<<<<<')
            else:
                print(f">>>>>>>>>>Graph node {transmitter_name} is not a ros transmitter, but a(n) "
                      f"{self.nx_graph.nodes[transmitter_name]['node_type']}<<<<<<<<<<")
        else:
            print(f'>>>>>>>>>>Graph node {transmitter_name} does not exist<<<<<<<<<<')

    # Applies multiple categorizations according to lists
    def apply_categorization(self, source_nodes=[], leak_nodes=[], conduit_nodes=[], sanitizer_nodes=[],
                             sensitive_transmitters=[], mundane_transmitters=[]) -> None:
        for source in source_nodes:
            self.set_privacy_type_for_node(source, 'source')
        for leak in leak_nodes:
            self.set_privacy_type_for_node(leak, 'leak')
        for conduit in conduit_nodes:
            self.set_privacy_type_for_node(conduit, 'conduit')
        for sanitizer in sanitizer_nodes:
            self.set_privacy_type_for_node(sanitizer, 'sanitizer')
        for sensitive_transmission in sensitive_transmitters:
            self.set_privacy_type_for_transmitter(sensitive_transmission, 'sensitive')
        for mundane_transmission in mundane_transmitters:
            self.set_privacy_type_for_transmitter(mundane_transmission, 'mundane')

    # Add a connection between a node and a transmitter with the given transmission type and node competence
    # @param enclave: The enclave the node belongs to
    # @param node_name: The name of the node to add
    # @param transmitter_name: The name of the transmitter to add
    # @param transmission_type: The type of transmission to add
    # @param node_competence: The role of the node in the transmission
    # @param allowed: Whether the node is allowed to perform its role in the transmission
    def add_connection(self, namespace, enclave, node_name, transmitter_name, transmission_type, node_competence,
                       allowed=None):
        full_node_name = namespace + '/' + node_name
        full_node_name = full_node_name.replace('//', '/')
        self.add_node_node(full_node_name, enclave)
        if not transmitter_name.startswith('/'):
            transmitter_name = namespace + '/' + transmitter_name
            transmitter_name = transmitter_name.replace('//', '/')
        if transmission_type == 'topic':
            self.add_topic_node(transmitter_name, enclave)
            if node_competence == 'publish':
                self.add_publisher(full_node_name, transmitter_name, allowed)
            elif node_competence == 'subscribe':
                self.add_subscriber(full_node_name, transmitter_name, allowed)
            else:
                print(f'>>>>>>>>>>Node competence {node_competence} not recognised<<<<<<<<<<')
        elif transmission_type == 'service':
            self.add_service_node(transmitter_name, enclave)
            if node_competence == 'reply':
                self.add_server(full_node_name, transmitter_name, allowed)
            elif node_competence == 'request':
                self.add_client(full_node_name, transmitter_name, allowed)
            else:
                print(f'>>>>>>>>>>Node competence {node_competence} not recognised<<<<<<<<<<')
        elif transmission_type == 'action':
            self.add_action_node(transmitter_name, enclave)
            if node_competence == 'execute':
                self.add_executor(full_node_name, transmitter_name, allowed)
            elif node_competence == 'call':
                self.add_caller(full_node_name, transmitter_name, allowed)
            else:
                print(f'>>>>>>>>>>Node competence {node_competence} not recognised<<<<<<<<<<')
        else:
            print(f'>>>>>>>>>>Transmission type {transmission_type} not recognised<<<<<<<<<<')

    # Updates the privacy graph to reflect the current state of the ROS graph
    def update_privacy_graph(self) -> None:
        # Removes all nodes and edges that belong to the standard set of connections a node has.
        if not self.include_standard_elements:
            self.remove_standard_elements()
        self.privacy_graph = nx.DiGraph(self.nx_graph)

        nodes_to_delete = []
        edges_to_delete = []

        # Remove all nodes and edges that are not descendants of a source node or source nodes themselves
        sources = self.get_nodes_of_privacy_type('node', 'source', graph_type='privacy')
        source_descendants = []
        if sources and self.remove_non_descendants:
            for node in sources:
                source_descendants += nx.descendants(self.nx_graph, node)
            non_descendants = [element for element in self.nx_graph.nodes() if element not in source_descendants and
                               element not in sources]
        else:
            non_descendants = []

        # Remove sanitizer nodes and mundane topics, services, and actions
        for node in self.privacy_graph.nodes():
            if self.privacy_graph.nodes[node]['privacy_type'] in ['sanitizer', 'mundane'] or node in non_descendants:
                nodes_to_delete.append(node)
        for edge in self.privacy_graph.edges():
            if (self.privacy_graph.edges[edge]['allowed'] in [False, None] or edge[0] in nodes_to_delete or edge[1] in
                    nodes_to_delete):  # TODO: delete edges with allowed=None? -> deletion by default?
                edges_to_delete.append(edge)
        self.privacy_graph.remove_edges_from(edges_to_delete)
        self.privacy_graph.remove_nodes_from(nodes_to_delete)

        # Remove topics, services, and actions with only one adjacent node (no communication to other nodes)
        nodes_to_delete = []
        edges_to_delete = []
        for node in self.privacy_graph.nodes():
            if self.privacy_graph.degree(node) == 0:
                nodes_to_delete.append(node)
        for node in self.privacy_graph.nodes():
            if self.privacy_graph.nodes[node]['node_type'] in ['topic', 'service', 'action']:
                predecessor_nodes = [n for n in self.privacy_graph.predecessors(node)]
                successor_nodes = [n for n in self.privacy_graph.successors(node)]
                if (len(predecessor_nodes) == 1 and len(successor_nodes) == 1 and predecessor_nodes[0] ==
                        successor_nodes[0]):
                    nodes_to_delete.append(node)

        # Remove all nodes and edges that are no longer descendants of a source node or source nodes themselves after
        # removing transmitters with only one adjacent node  # TODO: implement loop handling this
        source_descendants = []
        if sources and self.remove_non_descendants:
            for node in sources:
                source_descendants += nx.descendants(self.privacy_graph, node)
            non_descendants = [element for element in self.privacy_graph.nodes() if element not in source_descendants and
                               element not in sources]
        else:
            non_descendants = []
        for node in self.privacy_graph.nodes():
            if node in non_descendants:
                nodes_to_delete.append(node)
        for edge in self.privacy_graph.edges():
            if edge[0] in nodes_to_delete or edge[1] in nodes_to_delete:  # TODO: delete edges with allowed=None? -> deletion by default?
                edges_to_delete.append(edge)
        self.privacy_graph.remove_edges_from(edges_to_delete)
        self.privacy_graph.remove_nodes_from(nodes_to_delete)

        # Remove topics, services, and actions with only one adjacent node (no communication to other nodes)
        nodes_to_delete = []
        edges_to_delete = []
        for node in self.privacy_graph.nodes():
            if self.privacy_graph.degree(node) == 0:
                nodes_to_delete.append(node)
        for node in self.privacy_graph.nodes():
            if self.privacy_graph.nodes[node]['node_type'] in ['topic', 'service', 'action']:
                predecessor_nodes = [n for n in self.privacy_graph.predecessors(node)]
                successor_nodes = [n for n in self.privacy_graph.successors(node)]
                if (len(predecessor_nodes) == 1 and len(successor_nodes) == 1 and predecessor_nodes[0] ==
                        successor_nodes[0]) or len(predecessor_nodes) == 0 or len(successor_nodes) == 0:
                    nodes_to_delete.append(node)
        for edge in self.privacy_graph.edges():
            if edge[0] in nodes_to_delete or edge[1] in nodes_to_delete:  # TODO: delete edges with allowed=None? -> deletion by default?
                edges_to_delete.append(edge)
        self.privacy_graph.remove_edges_from(edges_to_delete)
        self.privacy_graph.remove_nodes_from(nodes_to_delete)

    # Removes all nodes and edges that belong to the standard set of connections a node has.
    # This includes the /rosout topic for logging,
    # topic /parameter_events, and services /describe_parameters, /get_parameters, /get_parameter_types,
    # /list_parameters, /set_parameters, /set_parameters_atomically for parameter management,
    # topic /clock for time management,
    def remove_standard_elements(self) -> None:
        rosout = [element for element in self.nx_graph.nodes() if element.endswith('/rosout')]
        parameter_events = [element for element in self.nx_graph.nodes() if element.endswith('/parameter_events')]
        describe_parameters = [element for element in self.nx_graph.nodes() if element.endswith('/describe_parameters')]
        get_parameters = [element for element in self.nx_graph.nodes() if element.endswith('/get_parameters')]
        get_parameter_types = [element for element in self.nx_graph.nodes() if element.endswith('/get_parameter_types')]
        list_parameters = [element for element in self.nx_graph.nodes() if element.endswith('/list_parameters')]
        set_parameters = [element for element in self.nx_graph.nodes() if element.endswith('/set_parameters')]
        set_parameters_atomically = [element for element in self.nx_graph.nodes() if element.endswith(
            '/set_parameters_atomically')]
        clock = [element for element in self.nx_graph.nodes() if element.endswith('/clock')]
        nodes_to_delete = (rosout + parameter_events + describe_parameters + get_parameters + get_parameter_types +
                           list_parameters + set_parameters + set_parameters_atomically + clock)
        # TODO: decide if included in standard elements
        # change_state = [element for element in self.nx_graph.nodes() if element.endswith('/change_state')]
        # get_available_states = [element for element in self.nx_graph.nodes() if element.endswith('/get_available_states')]
        # get_available_transitions = [element for element in self.nx_graph.nodes() if
        #                             element.endswith('/get_available_transitions')]
        # get_state = [element for element in self.nx_graph.nodes() if element.endswith('/get_state')]
        # get_transition_graph = [element for element in self.nx_graph.nodes() if
        #                        element.endswith('/get_transition_graph')]
        # nodes_to_delete += (change_state + get_available_states + get_available_transitions + get_state +
        #                   get_transition_graph)
        edges_to_delete = []
        for edge in self.nx_graph.edges():
            if edge[0] in nodes_to_delete or edge[1] in nodes_to_delete:
                edges_to_delete.append(edge)
        self.nx_graph.remove_edges_from(edges_to_delete)
        self.nx_graph.remove_nodes_from(nodes_to_delete)

    # Determines whether the graph is privacy vulnerable or not based on possible connections between source and leak
    # nodes in the current privacy graph
    # TODO: visualize vulnerable paths in own graphic?
    def is_privacy_vulnerable(self) -> bool:
        self.vulnerable_path_elements = []
        self.vulnerable_edges = []
        self.update_privacy_graph()
        privacy_vulnerable = False
        vulnerable_paths = []
        sources = self.get_nodes_of_privacy_type('node', 'source', graph_type='privacy')
        leaks = (self.get_nodes_of_privacy_type('node', 'leak', graph_type='privacy') +
                 self.get_nodes_of_privacy_type('node', 'default', graph_type='privacy'))
        for source in sources:
            for leak in leaks:
                if nx.has_path(self.privacy_graph, source, leak):
                    privacy_vulnerable = True
                    disjoint_paths = nx.edge_disjoint_paths(self.privacy_graph, source, leak)
                    for path in disjoint_paths:
                        leak_counter = 0
                        for node in path:
                            if node in leaks:
                                leak_counter += 1
                        if leak_counter == 1:
                            vulnerable_paths.append(path)
                            print(f'>>>>>>>>>>Privacy Endangered: {source} can reach {leak}<<<<<<<<<<')
                        elif leak_counter > 1:
                            # Path contains multiple leaks, so the subpath from the source to the first leak is already
                            # included in the list
                            pass
                        else:
                            print(f'>>>>>>>>>>Path {path} contains no leaks<<<<<<<<<<')  # Should never happen

        for path in vulnerable_paths:
            for index, element in enumerate(path):
                previous_element = path[index - 1]
                if element not in self.vulnerable_path_elements:
                    self.vulnerable_path_elements.append(element)
                if index != 0:
                    if (self.nx_graph.has_edge(previous_element, element) and
                            self.nx_graph.edges[previous_element, element] not in self.vulnerable_edges):
                        self.vulnerable_edges.append((previous_element, element))
                    if (self.nx_graph.has_edge(element, previous_element) and
                            self.nx_graph.edges[element, previous_element] not in self.vulnerable_edges):
                        self.vulnerable_edges.append((element, previous_element))

        print(f'>>>>>>>>>>Vulnerable Paths: {vulnerable_paths}<<<<<<<<<<') if privacy_vulnerable else print(
            '>>>>>>>>>>No Vulnerable Paths<<<<<<<<<<')
        return privacy_vulnerable

    # Sets the layout for the graph visualization using networkx
    # @param layout: The layout to use for the visualization (spiral, spring, planar, multipartite, kamada_kawai)
    def set_layout(self, layout, graph_type='ros') -> dict:
        graph = self.nx_graph
        if graph_type == 'privacy':
            graph = self.get_privacy_graph()
        if layout == 'spiral':
            return nx.spiral_layout(graph)
        elif layout == 'spring':
            return nx.spring_layout(graph)
        elif layout == 'planar':
            return nx.planar_layout(graph)
        elif layout == 'multipartite':
            # Shows enclaves, can be used for node_type
            return nx.multipartite_layout(graph, subset_key='enclave')
        elif layout == 'kamada_kawai':  # Needs package 'scipy' to run
            return nx.kamada_kawai_layout(graph)
        else:
            print(f'>>>>>>>>>>Layout {layout} not recognised, defaulted to spiral layout<<<<<<<<<<')
            return nx.spiral_layout(graph)

    # Gets all nodes of a given type from the graph
    # @param node_type: The type of node to get (node, topic, service, action)
    def get_nodes_of_type(self, node_type) -> list:
        nodes = []
        for node in self.nx_graph.nodes():
            if self.nx_graph.nodes[node]['node_type'] == node_type:
                nodes.append(node)
        return nodes

    # Gets all nodes of a given privacy type from the graph
    # @param node_type: The type of node to get (node, topic, service, action)
    # @param privacy_type: The privacy type of node to get (source, leak, conduit, sanitizer, default)
    # @param graph_type: The type of graph to get the nodes from (ros, privacy)
    def get_nodes_of_privacy_type(self, node_type, privacy_type, graph_type='ros') -> list:
        if graph_type == 'ros':
            graph = self.nx_graph
        elif graph_type == 'privacy':
            graph = self.privacy_graph
        else:
            print(f'>>>>>>>>>>Graph {graph_type} not recognised, defaulted to ros graph<<<<<<<<<<')
            graph = self.nx_graph
        nodes = []
        for node in graph.nodes():
            if (graph.nodes[node]['node_type'] == node_type and
                    graph.nodes[node]['privacy_type'] == privacy_type):
                nodes.append(node)
        return nodes

    # Gets the ROS graph
    def get_ros_graph(self) -> nx.DiGraph:
        return self.nx_graph

    # Gets the privacy graph
    def get_privacy_graph(self) -> nx.DiGraph:
        self.update_privacy_graph()
        return self.privacy_graph

    # Visualizes the graph
    # @param layout: The layout to use for the visualization (spiral, spring, planar, multipartite, kamada_kawai)
    # TODO: improve visualization of big graphs
    def show_ros_view(self, layout='spiral'):
        if not self.include_standard_elements:
            self.remove_standard_elements()
        pos = self.set_layout(layout)

        node_list = self.get_nodes_of_type('node')
        topic_list = self.get_nodes_of_type('topic')
        service_list = self.get_nodes_of_type('service')
        action_list = self.get_nodes_of_type('action')
        print(f'Topics: {topic_list}')
        print(f'Services: {service_list}')
        print(f'Actions: {action_list}')

        node_size = 300  # 200/300
        nx.draw_networkx_nodes(self.nx_graph, pos, nodelist=node_list, node_color='lightgrey', node_shape='o',
                               node_size=node_size)
        nx.draw_networkx_nodes(self.nx_graph, pos, nodelist=topic_list, node_color='lightblue', node_shape='s',
                               node_size=node_size)
        nx.draw_networkx_nodes(self.nx_graph, pos, nodelist=service_list, node_color='orange', node_shape='s',
                               node_size=node_size)
        nx.draw_networkx_nodes(self.nx_graph, pos, nodelist=action_list, node_color='lightgreen', node_shape='s',
                               node_size=node_size)
        allowed_edges = []
        denied_edges = []
        for edge in self.nx_graph.edges():
            try:
                if self.nx_graph.edges[edge]['allowed'] is True:
                    allowed_edges.append(edge)
                elif self.nx_graph.edges[edge]['allowed'] is False or self.nx_graph.edges[edge]['allowed'] is None:
                    denied_edges.append(edge)
            except KeyError:
                print(f'>>>>>>>>>>No Allowed or Denied Attribute for Edge {edge}<<<<<<<<<<')

        edge_width = 1  # 0.7/1
        nx.draw_networkx_edges(self.nx_graph, pos, allowed_edges, arrows=True, edge_color='black', width=edge_width)
        nx.draw_networkx_edges(self.nx_graph, pos, denied_edges, arrows=True, edge_color='lightgrey', width=edge_width)
        labels = {}
        for node in self.nx_graph.nodes():
            labels[node] = node
        label_font_size = 10  # 7/10
        nx.draw_networkx_labels(self.nx_graph, pos, labels, font_size=label_font_size)
        plt.subplots_adjust(left=0.01, bottom=0.01, right=0.99, top=0.99, wspace=None, hspace=None)
        plt.show()

    # Visualizes the privacy view of either the ROS graph or the privacy graph
    # @param layout: The layout to use for the visualization (spiral, spring, planar, multipartite, kamada_kawai)
    # @param ros_or_privacy_graph: The graph to visualize (ros, privacy)
    def show_privacy_view(self, layout='spiral', ros_or_privacy_graph='privacy'):
        if not self.include_standard_elements:
            self.remove_standard_elements()
        if ros_or_privacy_graph == 'ros':
            graph = self.nx_graph
        elif ros_or_privacy_graph == 'privacy':
            graph = self.get_privacy_graph()
        else:
            print(f'>>>>>>>>>>Graph {ros_or_privacy_graph} not recognised, defaulted to ros graph<<<<<<<<<<')
            graph = self.nx_graph
        pos = self.set_layout(layout, graph_type=ros_or_privacy_graph)

        privacy_typing_nodes = {'source': [], 'leak': [], 'conduit': [], 'sanitizer': [], 'default': []}
        privacy_typing_transmitters = {'sensitive': [], 'mundane': [], 'default': []}
        for node in graph.nodes():
            if graph.nodes[node]['node_type'] == 'node':
                privacy_typing_nodes[graph.nodes[node]['privacy_type']].append(node)
            else:
                privacy_typing_transmitters[graph.nodes[node]['privacy_type']].append(node)

        nx.draw_networkx_nodes(graph, pos, nodelist=privacy_typing_nodes['source'], node_color='yellow',
                               node_shape='o', node_size=300)
        nx.draw_networkx_nodes(graph, pos, nodelist=privacy_typing_nodes['leak'], node_color='red',
                               node_shape='o', node_size=300)
        nx.draw_networkx_nodes(graph, pos, nodelist=privacy_typing_nodes['conduit'], node_color='orange',
                               node_shape='o', node_size=300)
        nx.draw_networkx_nodes(graph, pos, nodelist=privacy_typing_nodes['sanitizer'], node_color='green',
                               node_shape='o', node_size=300)
        nx.draw_networkx_nodes(graph, pos, nodelist=privacy_typing_nodes['default'], node_color='lightgrey',
                               node_shape='o', node_size=300)

        nx.draw_networkx_nodes(graph, pos, nodelist=privacy_typing_transmitters['sensitive'],
                               node_color='violet', node_shape='s', node_size=300)
        nx.draw_networkx_nodes(graph, pos, nodelist=privacy_typing_transmitters['mundane'],
                               node_color='lightgreen', node_shape='s', node_size=300)
        nx.draw_networkx_nodes(graph, pos, nodelist=privacy_typing_transmitters['default'],
                               node_color='lightblue', node_shape='s', node_size=300)

        allowed_edges = []
        denied_edges = []
        for edge in graph.edges():
            try:
                if graph.edges[edge]['allowed'] is True:
                    allowed_edges.append(edge)
                elif graph.edges[edge]['allowed'] is False or graph.edges[edge]['allowed'] is None:
                    denied_edges.append(edge)  # TODO: Should edges with allowed=None be considered denied?
            except KeyError:
                # TODO: Add allowed=None?
                print(f'>>>>>>>>>>No Allowed or Denied Attribute for Edge {edge}<<<<<<<<<<')

        nx.draw_networkx_edges(graph, pos, allowed_edges, arrows=True, edge_color='black', width=1)
        nx.draw_networkx_edges(graph, pos, denied_edges, arrows=True, edge_color='lightgrey', width=1)
        nx.draw_networkx_edges(graph, pos, self.vulnerable_edges, arrows=True, edge_color='red', width=1)

        labels = {}
        for node in graph.nodes():
            labels[node] = node
        nx.draw_networkx_labels(graph, pos, labels, font_size=10)
        plt.subplots_adjust(left=0.01, bottom=0.01, right=0.99, top=0.99, wspace=None, hspace=None)
        plt.show()
