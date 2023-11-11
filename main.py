import os
import json
import networkx as nx
import XMLParser
import sys
import getopt
import ROSGraph


# This is the main function that is called when the program is run. It handles command line arguments and calls the
# necessary functions to build the graph and display it.
def main(argv) -> None:
    print(f'Starting directory: {os.getcwd()}')
    print(f'Output directory: {os.path.join(os.getcwd(), "output")}')
    show_ros_view = False
    show_privacy_view = False
    use_existing_graph = False
    existing_graph_path = os.path.join(os.getcwd(), "nxgraph")
    policy_path = os.path.join(os.getcwd(), "policies")
    save = False
    save_path = os.path.join(os.getcwd(), "output")
    include_standard_elements = False
    categorization_path = os.path.join(os.getcwd(), "categorizations/categorization.json")

    # Handles command line arguments
    # '-h' or '--help' prints the proper format
    # '-r' or '--ros_view' displays the ROS graph
    # '-p' or '--privacy_view' displays the privacy graph
    # '-s' or '--save' saves the graphs to the output directory
    # '--save_path' specifies the output directory
    # '-c' or '--categorization_path' specifies the path to the categorization file
    # '-d' or '--default_connections' includes the standard connections in the graph (e.g. /list_parameters)
    proper_format = "main.py -h -r -p -s -c -d\nalternative long options:\n--help\n--ros_view\n--privacy_view\n" \
                    "--save\n--save_path\n--categorization_path\n--default_connections\n"
    try:
        opts, _ = getopt.getopt(argv, "hrpsdc:", ["help", "ros_view", "privacy_view", "save",
                                                  "save_path=", "default_connections", "categorization_path="])
        print(f'Options chosen: {opts}')
    except getopt.GetoptError:
        print('Error')
        print(proper_format)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(proper_format)
            sys.exit()
        elif opt in ("-r", "--ros_view"):
            show_ros_view = True
        elif opt in ("-p", "--privacy_view"):
            show_privacy_view = True
        elif opt in ("-s", "--save"):
            save = True
        elif opt == "--save_path":
            save_path = arg
        elif opt in ("-c", "--categorization_path"):
            categorization_path = arg
        elif opt in ("-d", "--default_connections"):
            include_standard_elements = True

    if use_existing_graph:
        graph = ROSGraph.ROSGraph(graph_path=existing_graph_path, include_standard_elements=include_standard_elements)
    else:
        graph = XMLParser.build_graph_from_directory(path=policy_path,
                                                     include_standard_elements=include_standard_elements)
    with open(categorization_path, 'r') as infile:
        print(f'Loading categorization from {categorization_path}')
        categorization_dict = json.load(infile)
    graph.apply_categorization(source_nodes=categorization_dict['source'],
                               leak_nodes=categorization_dict['leak'],
                               conduit_nodes=categorization_dict['conduit'],
                               sanitizer_nodes=categorization_dict['sanitizer'],
                               sensitive_transmitters=categorization_dict['sensitive'],
                               mundane_transmitters=categorization_dict['mundane'])
    if show_ros_view:
        graph.show_ros_view(layout='kamada_kawai')  # layout='planar'
    if graph.is_privacy_vulnerable():
        print("Privacy Vulnerable")
    else:
        print("Privacy Safe")
    if show_privacy_view:
        graph.show_privacy_view(layout='kamada_kawai')
    if save:
        save_graph(graph, save_path)


# Saves the ROS and privacy graphs to the given path as adjacency lists
def save_graph(graph: ROSGraph.ROSGraph, path: str) -> None:
    ros_graph = graph.get_ros_graph()
    nx.write_multiline_adjlist(ros_graph, os.path.join(path, "ros_graph"))
    privacy_graph = graph.get_privacy_graph()
    nx.write_multiline_adjlist(privacy_graph, os.path.join(path, "privacy_graph"))


if __name__ == '__main__':
    main(sys.argv[1:])
